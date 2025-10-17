import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { extractAuthData, ExtractedAuthData, SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Account, IAccount } from '../../models/account.schema';
import { TempAccount, ITempAccount } from '../../models/temp_account.schema'; // Add this import
import { VerificationCode, IVerificationCode } from '../../models/verification_codes.schema';
import { SQSService } from '../../utils/lambdaSqs';
import { Types } from 'mongoose';

// ==================== INTERFACES ====================

interface ResendCodeRequest {
    // Identification (one required)
    email?: string;
    phone?: string;
    accountId?: string;

    // Code type and method
    verificationType: 'email_verification' | 'sms_verification' | 'mfa' | 'password_reset' | 'account_recovery';
    method?: 'sms' | 'email' | 'whatsapp';

    // For 2FA resend - requires login session
    loginSessionId?: string;

    // For MFA method preference
    preferredMfaMethod?: 'sms' | 'email' | 'totp';
}

interface ResendCodeResponseData {
    success: boolean;
    message: string;
    codeId: string;
    method: any;
    maskedRecipient: string;
    expiresAt: Date;
    cooldownSeconds?: number;
    remainingAttempts: number;
    nextResendAllowedAt?: Date;
}

// ==================== BUSINESS HANDLER CLASS ====================

class ResendCodeBusinessHandler {
    private requestData: ResendCodeRequest;
    private authdata: ExtractedAuthData;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;
    private sqsService: SQSService;

    // Environment variables
    private readonly SQS_QUEUE_URL: string;

    // Data holders
    private account?: IAccount;
    private tempAccount?: ITempAccount;
    private existingCode?: IVerificationCode;
    private clientIP: string = '';
    private deviceLocation?: any;
    private isTemporaryAccount: boolean = false;

    // Rate limiting constants
    private readonly RESEND_COOLDOWN_SECONDS = 60; // 1 minute between resends
    private readonly MAX_RESENDS_PER_HOUR = 3;
    private readonly MAX_RESENDS_PER_DAY = 10;

    constructor(event: APIGatewayProxyEvent, body: ResendCodeRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
        this.authdata = extractAuthData(event.headers as Record<string, string>);

        // Initialize services
        this.sqsService = new SQSService();

        // Get environment variables
        this.SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            verificationType: this.requestData.verificationType,
            functionName: 'resendCode'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<ResendCodeResponseData> {
        this.logger.info('Starting resend verification code process');

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Find account in both collections
        await this.findAccount();

        // Step 3: Check rate limits
        await this.checkRateLimits();

        // Step 4: Find or validate existing verification code
        await this.findExistingCode();

        // Step 5: Create new verification code
        const newCode = await this.createNewVerificationCode();

        // Step 6: Send the code
        await this.sendVerificationCode(newCode);

        // Step 7: Build response
        return this.buildResendResponse(newCode);
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating resend request data');

        // At least one identifier required
        if (!this.requestData.email && !this.requestData.phone && !this.requestData.accountId) {
            throw new HttpError('Email, phone, or accountId is required', 400);
        }

        // Validation for specific types
        switch (this.requestData.verificationType) {
            case 'mfa':
                if (!this.requestData.loginSessionId) {
                    throw new HttpError('Login session ID is required for MFA resend', 400);
                }
                break;
            case 'email_verification':
                if (!this.requestData.email && !this.requestData.accountId) {
                    throw new HttpError('Email or accountId is required for email verification', 400);
                }
                break;
            case 'sms_verification':
                if (!this.requestData.phone && !this.requestData.accountId) {
                    throw new HttpError('Phone or accountId is required for phone verification', 400);
                }
                break;
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Find account in both Account and TempAccount collections
     */
    private async findAccount(): Promise<void> {
        this.logger.debug('Finding account for resend request');

        let query: any = {};

        if (this.requestData.accountId) {
            query._id = this.requestData.accountId;
        } else {
            const conditions: any[] = [];

            if (this.requestData.email) {
                conditions.push({ email: this.requestData.email.toLowerCase() });
            }
            if (this.requestData.phone) {
                conditions.push({ phone: this.requestData.phone });
            }

            query = { $or: conditions };
        }

        // First, try to find in Account collection
        let accountQuery = { ...query };

        // Don't exclude deactivated accounts for email verification
        if (this.requestData.verificationType !== 'email_verification') {
            accountQuery.accountStatus = { $ne: 'deactivated' };
        }

        const accountData = await Account.findOne(accountQuery);

        if (accountData) {
            this.account = accountData;
            this.isTemporaryAccount = false;

            this.logger.debug('Account found in Account collection', {
                accountId: this.account._id,
                accountStatus: this.account.accountStatus,
                isTemporary: false
            });
            return;
        }

        // If not found in Account collection, search in TempAccount collection
        this.logger.debug('Account not found in Account collection, searching TempAccount');

        // For temp accounts, we don't need to check account status
        const tempAccountData = await TempAccount.findOne(query);

        if (tempAccountData) {
            this.tempAccount = tempAccountData;
            this.isTemporaryAccount = true;

            this.logger.debug('Account found in TempAccount collection', {
                tempAccountId: this.tempAccount._id,
                isTemporary: true,
                email: this.tempAccount.email,
                phone: this.tempAccount.phone
            });
            return;
        }

        // If account is not found in either collection
        this.logger.warn('Account not found in either Account or TempAccount collections', {
            verificationType: this.requestData.verificationType,
            hasEmail: !!this.requestData.email,
            hasPhone: !!this.requestData.phone,
            hasAccountId: !!this.requestData.accountId
        });

        // For security, don't reveal if account exists
        throw new HttpError('Unable to resend verification code', 404);
    }

    /**
     * Step 3: Check rate limits
     */
    private async checkRateLimits(): Promise<void> {
        this.logger.debug('Checking resend rate limits');

        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Build query based on available identifiers
        const rateLimitQuery: any = {
            type: this.requestData.verificationType,
            createdAt: { $gte: oneHourAgo },
            $or: []
        };

        // Add account identifiers to rate limit check
        if (this.account) {
            rateLimitQuery.$or.push({ accountId: this.account._id });
        } else if (this.tempAccount) {
            rateLimitQuery.$or.push({ tempAccountId: this.tempAccount._id });
        }

        if (this.requestData.email) {
            rateLimitQuery.$or.push({ 'deliveryInfo.recipient': this.requestData.email });
        }
        if (this.requestData.phone) {
            rateLimitQuery.$or.push({ 'deliveryInfo.recipient': this.requestData.phone });
        }
        rateLimitQuery.$or.push({ 'context.ip': this.clientIP });

        // Check hourly limit
        const recentResends = await VerificationCode.countDocuments(rateLimitQuery);

        if (recentResends >= this.MAX_RESENDS_PER_HOUR) {
            throw new HttpError('Too many resend attempts. Please try again later.', 429);
        }

        // Check daily limit
        rateLimitQuery.createdAt = { $gte: oneDayAgo };
        const dailyResends = await VerificationCode.countDocuments(rateLimitQuery);

        if (dailyResends >= this.MAX_RESENDS_PER_DAY) {
            throw new HttpError('Daily resend limit exceeded. Please try again tomorrow.', 429);
        }

        // Check cooldown period (last resend)
        rateLimitQuery.createdAt = { $gte: new Date(now.getTime() - this.RESEND_COOLDOWN_SECONDS * 1000) };
        const recentResend = await VerificationCode.findOne(rateLimitQuery).sort({ createdAt: -1 });

        if (recentResend) {
            const cooldownRemaining = Math.ceil((recentResend.createdAt.getTime() + this.RESEND_COOLDOWN_SECONDS * 1000 - now.getTime()) / 1000);
            if (cooldownRemaining > 0) {
                throw new HttpError(`Please wait ${cooldownRemaining} seconds before requesting another code.`, 429);
            }
        }

        this.logger.debug('Rate limit checks passed');
    }

    /**
     * Step 4: Find existing verification code
     */
    private async findExistingCode(): Promise<void> {
        this.logger.debug('Finding existing verification code for metadata');

        let query: any = {
            status: 'active',
            // expiresAt: { $gt: new Date() }
        };

        // Special handling for MFA resend
        if (this.requestData.loginSessionId) {
            query['context.metadata.loginSessionId'] = this.requestData.loginSessionId;
        }
        // else if (this.account) {
        //     query.accountId = this.account._id;
        // } else if (this.tempAccount) {
        //     query.tempAccountId = this.tempAccount._id;
        // } else {
        //     // For codes without account
        //     query.$or = [];
        //     if (this.requestData.email) {
        //         query.$or.push({ 'deliveryInfo.recipient': this.requestData.email });
        //     }
        //     if (this.requestData.phone) {
        //         query.$or.push({ 'deliveryInfo.recipient': this.requestData.phone });
        //     }
        // }

        const existingCodeData = await VerificationCode.findOne(query).sort({ createdAt: -1 });

        if (!existingCodeData) {
            throw new HttpError('No active verification code found', 404);
        }
        this.existingCode = existingCodeData;

        this.logger.debug('Existing code search completed', {
            foundExisting: !!this.existingCode,
            existingCodeId: this.existingCode?.codeId,
            isTemporaryAccount: this.isTemporaryAccount,
            note: 'This code will be deactivated during new code creation'
        });
    }

    /**
         * Step 5: Create new verification code
         */
    private async createNewVerificationCode(): Promise<IVerificationCode> {
        this.logger.debug('Creating new verification code');

        // Determine method and recipient
        const { method, recipient } = this.determineMethodAndRecipient();

        // Generate new code
        const codeLength = this.requestData.verificationType === 'mfa' ? 6 : 6;
        const newCodeValue = VerificationCode.generateCode(codeLength);
        const hashedCode = VerificationCode.hashCode(newCodeValue);

        // ENHANCED: Deactivate ALL existing active codes for this verification type and account
        await this.deactivateExistingCodes();

        // Get user name for template
        const userName = this.account?.profile?.firstName ||
            this.tempAccount?.profile?.firstName ||
            'User';

        console.log("purpose", this.existingCode?.purpose);

        // Create new verification code
        const newCodeData: any = {
            code: newCodeValue,
            hashedCode,
            type: this.requestData.verificationType,
            purpose: this.existingCode?.purpose,
            method,
            deliveryInfo: {
                channel: method,
                provider: method === 'sms' ? 'twilio' : 'brevo',
                recipient,
                deliveryStatus: 'pending'
            },
            maxAttempts: this.requestData.verificationType === 'mfa' ? 3 : 5,
            remainingAttempts: this.requestData.verificationType === 'mfa' ? 3 : 5,
            expiresAt: new Date(Date.now() + this.getExpirationTime()),
            context: {
                initiatedBy: 'user',
                triggerEvent: 'resend_verification',
                metadata: {
                    originalCodeId: this.existingCode?.codeId,
                    resendReason: 'user_requested',
                    isTemporaryAccount: this.isTemporaryAccount,
                    loginSessionId: this.requestData.loginSessionId
                },
                sessionId: this.event.requestContext?.requestId,
                deviceId: this.authdata.metadata.device.deviceId,
                ip: this.clientIP,
                userAgent: this.authdata.metadata.device.userAgent || this.event.headers?.['User-Agent']
            },
            security: {
                requiresSecureChannel: true,
                preventBruteForce: true,
                logAllAttempts: true,
                notifyOnFailure: this.requestData.verificationType === 'mfa',
                riskScore: this.calculateRiskScore()
            },
            template: {
                language: 'en',
                variables: {
                    name: userName,
                    code: newCodeValue,
                    expiryMinutes: Math.floor(this.getExpirationTime() / (60 * 1000)),
                    verificationType: this.requestData.verificationType
                }
            }
        };

        // Set appropriate account reference
        if (this.account) {
            newCodeData.accountId = this.account._id;
            newCodeData.context.metadata.accountId = this.account._id;
        } else if (this.tempAccount) {
            newCodeData.tempAccountId = this.tempAccount._id;
            newCodeData.context.metadata.tempAccountId = this.tempAccount.tempId;
        }

        const newCode = new VerificationCode(newCodeData);
        await newCode.save();

        this.logger.info('New verification code created and previous codes deactivated', {
            codeId: newCode.codeId,
            method,
            recipient: this.maskRecipient(recipient),
            expiresAt: newCode.expiresAt,
            isTemporaryAccount: this.isTemporaryAccount,
            accountType: this.isTemporaryAccount ? 'temp' : 'permanent'
        });

        return newCode;
    }

    /**
     * NEW METHOD: Deactivate all existing active codes for this verification type and account
     */
    private async deactivateExistingCodes(): Promise<void> {
        this.logger.debug('Deactivating existing verification codes');

        try {
            // Build query to find all active codes for this account and verification type
            let deactivationQuery: any = {
                status: { $in: ['active', 'pending'] }, // Include both active and pending codes
            };

            // Special handling for MFA with login session
            deactivationQuery['context.metadata.loginSessionId'] = this.requestData.loginSessionId;
            // Find all matching active codes
            const existingCodes = await VerificationCode.find(deactivationQuery);

            if (existingCodes.length > 0) {
                this.logger.debug(`Found ${existingCodes.length} existing codes to deactivate`);

                const bulkUpdateResult = await VerificationCode.updateMany(
                    deactivationQuery,
                    {
                        $set: {
                            status: 'revoked',
                            revokedAt: new Date(),
                            revokedBy: this.account?.id || this.tempAccount?.id,
                            revocationReason: 'superseded_by_resend',
                            updatedAt: new Date()
                        }
                    }
                );

                this.logger.debug('Bulk deactivated existing codes', {
                    modifiedCount: bulkUpdateResult.modifiedCount,
                    matchedCount: bulkUpdateResult.matchedCount
                });

                this.logger.info('Successfully deactivated all existing codes', {
                    deactivatedCount: existingCodes.length,
                    verificationType: this.requestData.verificationType,
                    isTemporaryAccount: this.isTemporaryAccount
                });
            } else {
                this.logger.debug('No existing active codes found to deactivate');
            }

        } catch (error) {
            this.logger.error('Error deactivating existing codes', {
                error: error instanceof Error ? error.message : 'Unknown error',
                verificationType: this.requestData.verificationType,
                isTemporaryAccount: this.isTemporaryAccount
            });

            // Don't throw error here as this shouldn't prevent new code creation
            // but log it as a warning for monitoring
            this.logger.warn('Continuing with new code creation despite deactivation error');
        }
    }


    /**
     * Step 6: Send verification code
     */
    private async sendVerificationCode(verificationCode: IVerificationCode): Promise<void> {
        this.logger.debug('Sending verification code');

        const method = verificationCode.method;
        const recipient = verificationCode.deliveryInfo.recipient;
        const code = verificationCode.code;

        // Get user name for message
        const userName = this.account?.profile?.firstName ||
            this.tempAccount?.profile?.firstName ||
            'User';

        // Prepare SQS message
        const sqsBody = {
            notificationType: this.getNotificationType(method),
            channels: [method],
            content: method === 'sms' ? {
                sms: {
                    message: this.getSMSMessage(code),
                    recipient
                }
            } : {
                email: {
                    subject: this.getEmailSubject(),
                    template: this.getEmailTemplate(),
                    data: {
                        name: userName,
                        otp: code,
                        expiryMinutes: Math.floor(this.getExpirationTime() / (60 * 1000)),
                        verificationType: this.requestData.verificationType,
                        isResend: true,
                        isTemporaryAccount: this.isTemporaryAccount
                    },
                    recipient
                }
            },
            priority: this.requestData.verificationType === 'mfa' ? 'high' : 'normal',
            metadata: {
                codeId: verificationCode.codeId,
                verificationType: this.requestData.verificationType,
                accountId: this.account?._id?.toString(),
                tempAccountId: this.tempAccount?._id?.toString(),
                isTemporaryAccount: this.isTemporaryAccount
            }
        };

        try {
            await this.sqsService.sendMessage(this.SQS_QUEUE_URL, sqsBody);

            // Update delivery status
            verificationCode.deliveryInfo.deliveryStatus = 'sent';
            await verificationCode.save();

            this.logger.info('Verification code sent successfully', {
                codeId: verificationCode.codeId,
                method,
                recipient: this.maskRecipient(recipient),
                isTemporaryAccount: this.isTemporaryAccount
            });

        } catch (error) {
            this.logger.error('Failed to send verification code', {
                error: error instanceof Error ? error.message : 'Unknown error',
                codeId: verificationCode.codeId,
                isTemporaryAccount: this.isTemporaryAccount
            });

            // Update delivery status to failed
            verificationCode.deliveryInfo.deliveryStatus = 'failed';
            verificationCode.deliveryInfo.failureReason = error instanceof Error ? error.message : 'Unknown error';
            verificationCode.status = 'failed';
            await verificationCode.save();

            throw new HttpError('Failed to send verification code', 500);
        }
    }

    /**
     * Step 7: Build response
     */
    private buildResendResponse(verificationCode: IVerificationCode): ResendCodeResponseData {
        const nextResendTime = new Date(Date.now() + this.RESEND_COOLDOWN_SECONDS * 1000);

        return {
            success: true,
            message: this.getSuccessMessage(verificationCode.method),
            codeId: verificationCode.codeId,
            method: verificationCode.method,
            maskedRecipient: this.maskRecipient(verificationCode.deliveryInfo.recipient),
            expiresAt: verificationCode.expiresAt,
            cooldownSeconds: this.RESEND_COOLDOWN_SECONDS,
            remainingAttempts: verificationCode.remainingAttempts,
            nextResendAllowedAt: nextResendTime
        };
    }

    // ==================== HELPER METHODS ====================

    private determineMethodAndRecipient(): { method: 'sms' | 'email' | 'whatsapp', recipient: string } {
        switch (this.requestData.verificationType) {
            case 'email_verification':
                const email = this.requestData.email ||
                    this.account?.email ||
                    this.tempAccount?.email;
                if (!email) throw new HttpError('Email not found for verification', 400);
                return { method: 'email', recipient: email };

            case 'sms_verification':
                const phone = this.requestData.phone ||
                    this.account?.phone ||
                    this.tempAccount?.phone;
                if (!phone) throw new HttpError('Phone not found for verification', 400);
                return { method: 'sms', recipient: phone };

            case 'mfa':
                // Use preferred method or determine from account settings
                const method = this.requestData.preferredMfaMethod || 'email';
                const mfaRecipient = method === 'sms'
                    ? (this.account?.phone || this.tempAccount?.phone)
                    : (this.account?.email || this.tempAccount?.email);

                if (!mfaRecipient) {
                    throw new HttpError(`${method === 'sms' ? 'Phone' : 'Email'} not found for MFA`, 400);
                }
                return { method: method as 'sms' | 'email', recipient: mfaRecipient };

            case 'password_reset':
            case 'account_recovery':
                const recoveryEmail = this.requestData.email ||
                    this.account?.email ||
                    this.tempAccount?.email;
                if (!recoveryEmail) throw new HttpError('Email not found for recovery', 400);
                return { method: 'email', recipient: recoveryEmail };

            default:
                const defaultEmail = this.requestData.email ||
                    this.account?.email ||
                    this.tempAccount?.email;
                if (!defaultEmail) throw new HttpError('Email not found for verification', 400);
                return { method: 'email', recipient: defaultEmail };
        }
    }

    private getExpirationTime(): number {
        const expirationTimes = {
            'email_verification': 30 * 60 * 1000, // 30 minutes
            'sms_verification': 10 * 60 * 1000, // 10 minutes
            'mfa': 5 * 60 * 1000, // 5 minutes
            'password_reset': 15 * 60 * 1000, // 15 minutes
            'account_recovery': 15 * 60 * 1000 // 15 minutes
        };

        return expirationTimes[this.requestData.verificationType] || 10 * 60 * 1000;
    }

    private getNotificationType(method: string): string {
        const notificationTypes = {
            'email_verification': 'email_verification',
            'sms_verification': 'sms_verification',
            'mfa': method === 'sms' ? 'sms_2fa' : 'email_2fa',
            'password_reset': 'email_password_reset',
            'account_recovery': 'email_account_recovery'
        };

        return notificationTypes[this.requestData.verificationType] || 'email_verification';
    }

    private getSMSMessage(code: string): string {
        const messages = {
            'email_verification': `Your email verification code is: ${code}. This code expires in 30 minutes.`,
            'sms_verification': `Your phone verification code is: ${code}. This code expires in 10 minutes.`,
            'mfa': `Your login verification code is: ${code}. This code expires in 5 minutes.`,
            'password_reset': `Your password reset code is: ${code}. This code expires in 15 minutes.`,
            'account_recovery': `Your account recovery code is: ${code}. This code expires in 15 minutes.`
        };

        return messages[this.requestData.verificationType] || `Your verification code is: ${code}`;
    }

    private getEmailSubject(): string {
        const subjects = {
            'email_verification': 'Verify Your Email Address',
            'sms_verification': 'Phone Verification Code',
            'mfa': 'Login Verification Code',
            'password_reset': 'Password Reset Code',
            'account_recovery': 'Account Recovery Code'
        };

        return subjects[this.requestData.verificationType] || 'Verification Code';
    }

    private getEmailTemplate(): string {
        const templates = {
            'email_verification': 'account-verification',
            'sms_verification': 'phone-verification',
            'mfa': 'login-2fa',
            'password_reset': 'password-reset',
            'account_recovery': 'account-recovery'
        };

        return templates[this.requestData.verificationType] || 'verification-code';
    }

    private getSuccessMessage(method: string): string {
        const methodText = method === 'sms' ? 'text message' : 'email';
        const typeText = this.requestData.verificationType === 'mfa' ? 'verification code' : 'verification code';

        return `A new ${typeText} has been sent via ${methodText}. Please check your ${method === 'sms' ? 'messages' : 'email'}.`;
    }

    private maskRecipient(recipient: string): string {
        if (recipient.includes('@')) {
            // Email
            const [username, domain] = recipient.split('@');
            const maskedUsername = username.length > 2
                ? username.substring(0, 2) + '*'.repeat(Math.max(1, username.length - 2))
                : '*'.repeat(username.length);
            return `${maskedUsername}@${domain}`;
        } else {
            // Phone number
            return recipient.length > 4 ? `***${recipient.slice(-4)}` : recipient;
        }
    }

    private calculateRiskScore(): number {
        let score = 0;

        // Add risk factors
        if (this.isTemporaryAccount) score += 15; // Temporary account has higher risk
        if (!this.account && !this.tempAccount) score += 20; // No account at all

        // Add more risk factors as needed
        return Math.min(score, 100);
    }
}

// ==================== LAMBDA HANDLER ====================

const ResendCodeHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Resend verification code handler started');

    // Parse request body
    const parsedBody = parseRequestBody<ResendCodeRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process resend request
    const businessHandler = new ResendCodeBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Resend verification code handler completed successfully', {
        verificationType: parsedBody.verificationType,
        method: result.method,
        codeId: result.codeId
    });

    logger.logBusinessEvent('RESEND_CODE_SUCCESS', {
        operationType: 'resend_verification_code',
        verificationType: parsedBody.verificationType,
        method: result.method,
        codeId: result.codeId
    });

    return SuccessResponse({
        message: result.message,
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(ResendCodeHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});