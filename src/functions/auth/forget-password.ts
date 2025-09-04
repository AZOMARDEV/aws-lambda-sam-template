import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Account, IAccount } from '../../models/account.schema';
import { VerificationCode } from '../../models/verification_codes.schema';
import { SQSService } from '../../utils/lambdaSqs';

// ==================== INTERFACES ====================

interface ForgetPasswordRequest {
    // Primary identifier - one required
    email?: string;
    phone?: string;
    username?: string;

    // Device info for security
    deviceInfo: {
        deviceType?: 'desktop' | 'mobile' | 'tablet';
        os: string;
        browser: string;
        userAgent: string;
        fingerprint?: {
            hash: string;
            components: Record<string, any>;
        };
    };

    // Captcha for bot protection
    captchaToken?: string;
    captchaProvider?: 'recaptcha' | 'hcaptcha' | 'cloudflare';
}

interface ForgetPasswordResponseData {
    success: boolean;
    message: string;
    resetSessionId: string;
    expiresIn: number; // seconds until OTP expires
    maskedContact: string;
    method: 'email' | 'sms';
}

// ==================== BUSINESS HANDLER CLASS ====================

class ForgetPasswordBusinessHandler {
    private requestData: ForgetPasswordRequest;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;
    private sqsservice: SQSService;

    // Environment variables
    private readonly SQS_QUEUE_URL: string;

    // Data holders
    private account?: IAccount;
    private clientIP: string = '';
    private deviceLocation?: any;
    private resetSessionId?: string;

    constructor(event: APIGatewayProxyEvent, body: ForgetPasswordRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

        // Initialize services
        this.sqsservice = new SQSService();

        // Get environment variables
        this.SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            identifier: this.getIdentifier(),
            functionName: 'forget_password'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<ForgetPasswordResponseData> {
        this.logger.info('Starting forget password process');

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Find account
        await this.findAccount();

        // Step 3: Check if password reset is allowed
        this.checkResetEligibility();

        // Step 4: Generate and send OTP
        return await this.initiatePasswordReset();
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating forget password request data');

        // At least one identifier required
        if (!this.requestData.email && !this.requestData.phone && !this.requestData.username) {
            throw new HttpError('Email, phone, or username is required', 400);
        }

        // Device info validation
        if (!this.requestData.deviceInfo?.os || !this.requestData.deviceInfo?.browser) {
            throw new HttpError('Device information is required for security purposes', 400);
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Find account
     */
    private async findAccount(): Promise<void> {
        this.logger.debug('Finding account');

        const conditions: any[] = [];

        if (this.requestData.email) {
            conditions.push({ email: this.requestData.email.toLowerCase() });
        }
        if (this.requestData.phone) {
            conditions.push({ phone: this.requestData.phone });
        }
        if (this.requestData.username) {
            conditions.push({ username: this.requestData.username.toLowerCase() });
        }

        const foundAccount = await Account.findOne({
            $or: conditions,
            accountStatus: { $ne: 'deactivated' }
        });

        this.account = foundAccount || undefined;

        // For security, don't reveal if account exists or not
        // But log the attempt for monitoring
        if (!this.account) {
            this.logger.warn('Password reset attempted for non-existent account', {
                identifier: this.getIdentifier(),
                ip: this.clientIP
            });
            throw new HttpError('Account not found', 404);
        } else {
            this.logger.debug('Account found for password reset', {
                accountId: this.account._id,
                accountStatus: this.account.accountStatus,
                hasPassword: !!this.account.password
            });
        }
    }

    /**
     * Step 3: Check if password reset is allowed
     */
    private checkResetEligibility(): void {
        if (!this.account) {
            // Even if account doesn't exist, we'll return success for security
            // but we won't actually send anything
            return;
        }

        // Check if account is suspended or locked
        if (this.account.accountStatus.status === 'suspended') {
            throw new HttpError('Account is suspended. Please contact support.', 403);
        }

        // Check if account is locked
        if (this.account.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
            const minutesRemaining = Math.ceil((this.account.security.lockedUntil.getTime() - Date.now()) / (1000 * 60));
            throw new HttpError(`Account is locked. Try again in ${minutesRemaining} minutes.`, 423);
        }

        // Check for recent password change attempts (rate limiting)
        const recentChangeAttempt = this.account.security.lastPasswordChange;
        if (recentChangeAttempt) {
            const timeSinceLastChange = Date.now() - recentChangeAttempt.getTime();
            const cooldownPeriod = 10 * 60 * 1000; // 10 minutes

            if (timeSinceLastChange < cooldownPeriod) {
                const minutesRemaining = Math.ceil((cooldownPeriod - timeSinceLastChange) / (1000 * 60));
                throw new HttpError(
                    `Please wait ${minutesRemaining} minutes before requesting another password change.`,
                    429
                );
            }
        }

        this.logger.debug('Account is eligible for password reset');
    }

    /**
     * Step 4: Initiate password reset process
     */
    private async initiatePasswordReset(): Promise<ForgetPasswordResponseData> {
        this.logger.debug('Initiating password reset process');

        // Generate reset session ID
        this.resetSessionId = `reset_${Date.now()}_${Math.random().toString(36).substring(2)}`;

        // Check for existing active reset codes and invalidate them
        if (this.account) {
            await VerificationCode.updateMany(
                {
                    accountId: this.account._id,
                    type: 'password_reset',
                    status: 'active'
                },
                {
                    status: 'expired',
                    updatedAt: new Date()
                }
            );
        }

        // Determine preferred contact method
        const preferredMethod = this.determineContactMethod();
        const recipient = this.getRecipientAddress(preferredMethod);
        const maskedContact = this.maskContact(preferredMethod, recipient);

        // Always return success for security (even if account doesn't exist)
        // But only actually send OTP if account exists
        if (this.account) {
            await this.generateAndSendOTP(preferredMethod, recipient);

            // Update account with reset attempt info
            this.account.security.lastPasswordChange = new Date();
            await this.account.save();

            this.logger.info('Password reset OTP sent successfully', {
                accountId: this.account._id,
                method: preferredMethod,
                resetSessionId: this.resetSessionId
            });
        } else {
            // Log security event but still return success
            this.logger.warn('Password reset attempted for non-existent account - returning fake success', {
                identifier: this.getIdentifier(),
                ip: this.clientIP
            });
        }

        return {
            success: true,
            message: `A verification code has been sent to your ${preferredMethod === 'email' ? 'email address' : 'phone number'}. Please check your ${preferredMethod === 'email' ? 'inbox' : 'messages'} and enter the code to reset your password.`,
            resetSessionId: this.resetSessionId!,
            expiresIn: 600, // 10 minutes
            maskedContact,
            method: preferredMethod
        };
    }

    /**
     * Generate and send OTP code
     */
    private async generateAndSendOTP(method: 'email' | 'sms', recipient: string): Promise<void> {
        if (!this.account) return;

        // Generate OTP
        const otpCode = VerificationCode.generateCode(6);

        // Create verification code record
        const verificationCode = new VerificationCode({
            accountId: this.account._id,
            code: otpCode,
            hashedCode: VerificationCode.hashCode(otpCode),
            type: 'password_reset',
            purpose: 'Password reset verification',
            method: method,
            deliveryInfo: {
                channel: method,
                provider: method === 'sms' ? 'twilio' : 'ses',
                recipient: recipient,
                deliveryStatus: 'pending'
            },
            maxAttempts: 3,
            remainingAttempts: 3,
            expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
            context: {
                initiatedBy: 'user',
                triggerEvent: 'password_reset_request',
                metadata: {
                    accountId: (this.account._id as string | number | { toString(): string }).toString(),
                    resetSessionId: this.resetSessionId!,
                    method: method
                },
                sessionId: this.event.requestContext?.requestId,
                ip: this.clientIP,
                userAgent: this.requestData.deviceInfo.userAgent
            },
            security: {
                requiresSecureChannel: true,
                preventBruteForce: true,
                logAllAttempts: true,
                notifyOnFailure: true,
                riskScore: this.calculateRiskScore()
            }
        });

        await verificationCode.save();

        // Send OTP
        await this.sendOTP(method, otpCode, recipient);
    }

    /**
     * Send OTP via email or SMS
     */
    private async sendOTP(method: 'email' | 'sms', otpCode: string, recipient: string): Promise<void> {
        if (!this.account) return;

        const sqsBody = {
            notificationType: method === 'sms' ? 'sms_password_reset' : 'email_password_reset',
            channels: [method],
            content: method === 'sms' ? {
                sms: {
                    message: `Your password reset code is: ${otpCode}. This code expires in 10 minutes. If you didn't request this, please ignore this message.`,
                    recipient: recipient
                }
            } : {
                email: {
                    subject: 'Password Reset Verification Code',
                    template: 'password-reset',
                    data: {
                        name: this.account.profile.firstName || 'User',
                        otp: otpCode,
                        expiryMinutes: 10,
                        device: `${this.requestData.deviceInfo.browser} on ${this.requestData.deviceInfo.os}`,
                        location: this.deviceLocation?.country || 'Unknown',
                        ip_address: this.clientIP,
                        reset_time: new Date().toISOString(),
                        user_email: this.account.email,
                        reset_url: `${process.env.APP_URL}/reset-password`,
                        support_url: `${process.env.APP_URL}/support`,
                        security_url: `${process.env.APP_URL}/account/security`,
                        privacy_url: `${process.env.APP_URL}/privacy`
                    },
                    recipient: recipient
                }
            },
            priority: 'high'
        };

        await this.sqsservice.sendMessage(this.SQS_QUEUE_URL, sqsBody);
    }

    // ==================== HELPER METHODS ====================

    private getIdentifier(): string {
        return this.requestData.email || this.requestData.phone || this.requestData.username || 'unknown';
    }

    private determineContactMethod(): 'email' | 'sms' {
        // Prioritize email for password reset as it's more secure and common
        if (this.account?.email) {
            return 'email';
        } else if (this.account?.phone) {
            return 'sms';
        }

        // Default to email even if account doesn't exist (for security)
        return 'email';
    }

    private getRecipientAddress(method: 'email' | 'sms'): string {
        if (!this.account) {
            // Return dummy address for non-existent accounts
            return method === 'email' ? 'dummy@example.com' : '+1234567890';
        }

        if (method === 'email') {
            return this.account.email || '';
        } else {
            return this.account.phone || '';
        }
    }

    private maskContact(method: 'email' | 'sms', contact: string): string {
        if (method === 'email') {
            const [username, domain] = contact.split('@');
            if (username && domain) {
                const maskedUsername = username.length > 2
                    ? username.substring(0, 2) + '*'.repeat(Math.min(username.length - 2, 4))
                    : '*'.repeat(username.length);
                return `${maskedUsername}@${domain}`;
            }
            return '***@example.com';
        } else {
            // SMS
            return contact.length > 4 ? `***${contact.slice(-4)}` : '***0000';
        }
    }

    private calculateRiskScore(): number {
        let score = 0;

        // Base score for password reset
        score += 10;

        // Check for recent attempts
        // Note: In a real implementation, you'd check recent attempts from this IP

        return score;
    }
}

// ==================== LAMBDA HANDLER ====================

const ForgetPasswordHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Forget password handler started');

    try {
        // Parse request body
        const parsedBody = parseRequestBody<ForgetPasswordRequest>(event, logger);

        // Connect to database
        await connectDB();

        // Process forget password request
        const businessHandler = new ForgetPasswordBusinessHandler(event, parsedBody);
        const result = await businessHandler.processRequest();

        logger.info('Forget password handler completed successfully');
        logger.logBusinessEvent('LAMBDA_SUCCESS', {
            operationType: 'forget_password',
            method: result.method,
            resetSessionId: result.resetSessionId
        });

        return SuccessResponse({
            message: result.message,
            data: result
        });

    } catch (error: any) {
        logger.error('Forget password handler failed', {
            error: error.message,
            stack: error.stack
        });

        if (error instanceof HttpError) {
            throw error;
        }

        throw new HttpError('Internal server error', 500);
    }
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(ForgetPasswordHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});