import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import bcrypt from 'bcryptjs';
import { Account, IAccount } from '../../models/account.schema';
import { VerificationCode } from '../../models/verification_codes.schema';
import { Session } from '../../models/sessions.schema';
import { SQSService } from '../../utils/lambdaSqs';

// ==================== INTERFACES ====================

interface ResetPasswordRequest {
    // Reset session from forget password
    resetSessionId: string;

    // OTP code from email/SMS
    otpCode: string;

    // New password
    newPassword: string;
    confirmPassword: string;

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

    // Optional: Invalidate all existing sessions
    invalidateAllSessions?: boolean;
}

interface ResetPasswordResponseData {
    success: boolean;
    message: string;
    passwordResetStatus: 'success' | 'invalid_code' | 'expired_session';

    // Account info
    accountId?: string;
    profile?: {
        firstName?: string;
        lastName?: string;
        displayName?: string;
        avatar?: string;
    };

    // Security info
    sessionsInvalidated?: number;
    securityAlerts?: string[];
}

// ==================== BUSINESS HANDLER CLASS ====================

class ResetPasswordBusinessHandler {
    private requestData: ResetPasswordRequest;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;
    private sqsservice: SQSService;

    // Environment variables
    private readonly SQS_QUEUE_URL: string;

    // Data holders
    private account?: IAccount;
    private verificationCode?: any;
    private clientIP: string = '';
    private deviceLocation?: any;
    private sessionsInvalidated: number = 0;
    private securityAlerts: string[] = [];

    constructor(event: APIGatewayProxyEvent, body: ResetPasswordRequest) {
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
            resetSessionId: this.requestData.resetSessionId,
            functionName: 'reset_password'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<ResetPasswordResponseData> {
        this.logger.info('Starting reset password process');

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Verify OTP and find account
        await this.verifyOTPAndFindAccount();

        // Step 3: Validate new password
        this.validateNewPassword();

        // Step 4: Reset password and cleanup
        return await this.resetPasswordAndCleanup();
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating reset password request data');

        // Required fields
        const requiredFields = ['resetSessionId', 'otpCode', 'newPassword', 'confirmPassword'];
        validateRequiredFields(this.requestData, requiredFields);

        // OTP code format validation
        if (!/^\d{6}$/.test(this.requestData.otpCode)) {
            throw new HttpError('Invalid verification code format', 400);
        }

        // Password confirmation
        if (this.requestData.newPassword !== this.requestData.confirmPassword) {
            throw new HttpError('Password confirmation does not match', 400);
        }

        // Device info validation
        if (!this.requestData.deviceInfo?.os || !this.requestData.deviceInfo?.browser) {
            throw new HttpError('Device information is required for security purposes', 400);
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Verify OTP and find account
     */
    private async verifyOTPAndFindAccount(): Promise<void> {
        this.logger.debug('Verifying OTP and finding account');

        // Find active verification code
        this.verificationCode = await VerificationCode.findOne({
            'context.metadata.resetSessionId': this.requestData.resetSessionId,
            type: 'password_reset',
            status: 'active',
            expiresAt: { $gt: new Date() }
        });

        if (!this.verificationCode) {
            this.logger.warn('Invalid or expired reset session', {
                resetSessionId: this.requestData.resetSessionId
            });
            throw new HttpError(
                'Invalid or expired reset session. Please request a new password reset.',
                404,
                'EXPIRED_SESSION'
            );
        }

        // Verify OTP code
        const isValidOTP = this.verificationCode.verify(this.requestData.otpCode, {});

        if (!isValidOTP) {
            await this.verificationCode.save();
            this.logger.warn('Invalid OTP code provided for password reset', {
                resetSessionId: this.requestData.resetSessionId,
                remainingAttempts: this.verificationCode.remainingAttempts
            });
            throw new HttpError(
                `Invalid verification code. ${this.verificationCode.remainingAttempts} attempts remaining.`,
                400,
                'INVALID_CODE'
            );
        }

        // Find account using verification code's account ID
        const accountData = await Account.findById(this.verificationCode.accountId);

        if (!accountData) {
            this.logger.error('Account not found for valid verification code', {
                accountId: this.verificationCode.accountId,
                resetSessionId: this.requestData.resetSessionId
            });
            throw new HttpError('Account not found', 404);
        }

        this.account = accountData;

        this.logger.debug('OTP verified and account found', {
            accountId: this.account._id,
            accountStatus: this.account.accountStatus
        });
    }

    /**
     * Step 3: Validate new password
     */
    private validateNewPassword(): void {
        this.logger.debug('Validating new password');

        const password = this.requestData.newPassword;

        // Password strength validation
        if (password.length < 8) {
            throw new HttpError('Password must be at least 8 characters long', 400);
        }

        if (password.length > 128) {
            throw new HttpError('Password is too long (max 128 characters)', 400);
        }

        // Check for at least one uppercase, lowercase, number, and special character
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password);

        if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar) {
            throw new HttpError(
                'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
                400
            );
        }

        // Check against common passwords (basic check)
        const commonPasswords = ['password', '12345678', 'qwerty123', 'admin123', 'password123'];
        if (commonPasswords.includes(password.toLowerCase())) {
            throw new HttpError('Password is too common. Please choose a stronger password.', 400);
        }

        // Check if password is same as old password (if account has one)
        if (this.account?.password) {
            const isSamePassword = bcrypt.compareSync(password, this.account.password);
            if (isSamePassword) {
                throw new HttpError('New password must be different from your current password', 400);
            }
        }

        this.logger.debug('Password validation completed');
    }

    /**
     * Step 4: Reset password and cleanup
     */
    private async resetPasswordAndCleanup(): Promise<ResetPasswordResponseData> {
        if (!this.account || !this.verificationCode) {
            throw new HttpError('Missing required data', 500);
        }

        this.logger.debug('Resetting password and performing cleanup');

        // Hash new password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(this.requestData.newPassword, saltRounds);

        // Update account password
        this.account.password = hashedPassword;

        // Update security info
        this.account.security.lastPasswordChange = new Date();
        this.account.security.failedLoginAttempts = 0;
        this.account.security.lockedUntil = undefined;

        // // Add password reset to security history
        // this.account.security.loginHistory.push({
        //     timestamp: new Date(),
        //     ip: this.clientIP,
        //     userAgent: this.requestData.deviceInfo.userAgent,
        //     deviceId: this.requestData.deviceInfo.fingerprint?.hash,
        //     success: true,
        //     location: this.deviceLocation,
        //     // action: 'password_reset'
        // });

        // Keep only last 50 security events
        if (this.account.security.loginHistory.length > 50) {
            this.account.security.loginHistory = this.account.security.loginHistory.slice(-50);
        }

        await this.account.save();

        // Mark verification code as used
        this.verificationCode.isUsed = true;
        this.verificationCode.usedAt = new Date();
        await this.verificationCode.save();

        // Invalidate all existing verification codes for this account
        await VerificationCode.updateMany(
            {
                accountId: this.account._id,
                type: 'password_reset',
                status: 'active',
                _id: { $ne: this.verificationCode._id }
            },
            {
                status: 'expired',
                updatedAt: new Date()
            }
        );

        // Handle session invalidation
        if (this.requestData.invalidateAllSessions !== false) { // Default to true
            await this.invalidateAllSessions();
        }

        this.logger.info('Password reset completed successfully', {
            accountId: this.account._id,
            sessionsInvalidated: this.sessionsInvalidated,
            resetSessionId: this.requestData.resetSessionId
        });

        return {
            success: true,
            message: 'Password has been reset successfully. Please log in with your new password.',
            passwordResetStatus: 'success',
            accountId: String(this.account._id),
            profile: this.account.profile || {},
            sessionsInvalidated: this.sessionsInvalidated,
            securityAlerts: this.securityAlerts
        };
    }

    /**
     * Invalidate all existing sessions
     */
    private async invalidateAllSessions(): Promise<void> {
        if (!this.account) return;

        this.logger.debug('Invalidating all existing sessions');

        const result = await Session.updateMany(
            {
                accountId: this.account._id,
                isActive: true,
                status: 'active'
            },
            {
                isActive: false,
                status: 'terminated',
                terminatedAt: new Date(),
                terminationReason: 'password_reset',
                terminatedBy: 'system'
            }
        );

        this.sessionsInvalidated = result.modifiedCount || 0;

        if (this.sessionsInvalidated > 0) {
            this.securityAlerts.push(`${this.sessionsInvalidated} existing sessions were terminated for security.`);
        }

        this.logger.debug('Sessions invalidated', {
            count: this.sessionsInvalidated
        });
    }
}


// ==================== LAMBDA HANDLER ====================

const ResetPasswordHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
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
        const parsedBody = parseRequestBody<ResetPasswordRequest>(event, logger);

        // Connect to database
        await connectDB();

        // Process reset password request
        const businessHandler = new ResetPasswordBusinessHandler(event, parsedBody);
        const result = await businessHandler.processRequest();

        logger.info('Reset password handler completed successfully');
        logger.logBusinessEvent('LAMBDA_SUCCESS', {
            operationType: 'reset_password',
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

export const handler = lambdaMiddleware(ResetPasswordHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});
