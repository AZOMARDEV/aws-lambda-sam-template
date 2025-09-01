import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { TempAccount, ITempAccount } from '../../models/temp_account.schema';
import { Account } from '../../models/account.schema';
import { IVerificationCode, VerificationCode } from '../../models/verification_codes.schema';

// ==================== INTERFACES ====================

interface ValidateOTPRequest {
    tempId: string;
    code: string;
    verificationType: 'email' | 'phone';
}

interface ValidateOTPResponseData {
    success: boolean;
    tempId: string;
    message: string;
    accountStatus: 'verified' | 'partially_verified' | 'completed';
    nextStep?: {
        action: 'complete_profile' | 'verify_phone' | 'verify_email' | 'login';
        message: string;
    };
    verificationStatus: {
        email: boolean;
        phone: boolean;
    };
    accountCreated: boolean;
    accountId?: string;
    metadata: {
        verificationType: string;
        hasCompleteProfile: boolean;
        allVerificationsComplete: boolean;
    };
}

// ==================== BUSINESS HANDLER CLASS ====================

class ValidateOTPBusinessHandler {
    private requestData: ValidateOTPRequest;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;

    // Data holders
    private tempAccount?: ITempAccount;
    private verificationCode?: IVerificationCode;
    private clientIP: string = '';
    private finalAccount?: any;

    constructor(event: APIGatewayProxyEvent, body: ValidateOTPRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            tempId: this.requestData.tempId,
            verificationType: this.requestData.verificationType,
            functionName: 'validate-otp'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<ValidateOTPResponseData> {
        this.logger.info('Starting OTP validation process');

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Find and validate temp account
        await this.findTempAccount();

        // Step 3: Find and validate verification code
        await this.findAndValidateVerificationCode();

        // Step 4: Verify the OTP code
        await this.verifyOTPCode();

        // Step 5: Update verification status
        await this.updateVerificationStatus();

        // Step 6: Check if all verifications are complete
        const allVerificationsComplete = await this.checkAllVerificationsComplete();

        // Step 7: Create final account if all verifications complete
        if (allVerificationsComplete) {
            await this.createFinalAccount();
        }

        // Step 8: Prepare response
        const responseData = this.prepareResponseData(allVerificationsComplete);

        this.logger.info('OTP validation completed successfully', {
            tempId: this.tempAccount!.tempId,
            verificationType: this.requestData.verificationType,
            accountCreated: allVerificationsComplete
        });

        this.logger.logBusinessEvent('OTP_VALIDATION_SUCCESS', {
            tempId: this.tempAccount!.tempId,
            verificationType: this.requestData.verificationType,
            accountCreated: allVerificationsComplete,
            finalAccountId: this.finalAccount?.accountId
        });

        return responseData;
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating OTP request data');

        const requiredFields: string[] = ['tempId', 'code', 'verificationType'];
        const customMessages: Record<string, string> = {
            tempId: 'Temporary account ID is required',
            code: 'Verification code is required',
            verificationType: 'Verification type is required'
        };

        validateRequiredFields(this.requestData, requiredFields, customMessages);

        // Validate code format
        if (!/^\d{6}$/.test(this.requestData.code)) {
            throw new HttpError('Invalid verification code format. Code must be 6 digits.', 400);
        }

        // Validate verification type
        if (!['email', 'phone'].includes(this.requestData.verificationType)) {
            throw new HttpError('Invalid verification type. Must be either email or phone.', 400);
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Find and validate temp account
     */
    private async findTempAccount(): Promise<void> {
        this.logger.debug('Finding temporary account', {
            tempId: this.requestData.tempId
        });

        // Clean up expired temp accounts first
        await TempAccount.cleanupExpired();

        const foundTempAccount = await TempAccount.findOne({
            tempId: this.requestData.tempId,
            status: { $in: ['active', 'partial', 'verified'] },
            expiresAt: { $gt: new Date() }
        });
        this.tempAccount = foundTempAccount ?? undefined;

        if (!this.tempAccount) {
            throw new HttpError('Invalid or expired registration session. Please start registration again.', 404);
        }

        // Check if this verification type is required and not already completed
        const verificationType = this.requestData.verificationType;
        const verificationReq = verificationType === 'email'
            ? this.tempAccount.verificationRequirements.emailVerification
            : this.tempAccount.verificationRequirements.phoneVerification;

        if (!verificationReq.required) {
            throw new HttpError(`${verificationType} verification is not required for this account.`, 400);
        }

        if (verificationReq.completed) {
            throw new HttpError(`${verificationType} verification is already completed.`, 400);
        }

        this.logger.debug('Temporary account found', {
            tempId: this.tempAccount.tempId,
            status: this.tempAccount.status
        });
    }

    /**
     * Step 3: Find and validate verification code
     */
    private async findAndValidateVerificationCode(): Promise<void> {
        this.logger.debug('Finding verification code');

        const verificationType = this.requestData.verificationType;
        const verificationReq = verificationType === 'email'
            ? this.tempAccount!.verificationRequirements.emailVerification
            : this.tempAccount!.verificationRequirements.phoneVerification;

        if (!verificationReq.codeId) {
            throw new HttpError('No verification code found for this account. Please request a new one.', 404);
        }

        const foundVerificationCode = await VerificationCode.findOne({
            codeId: verificationReq.codeId,
            status: "active",
            expiresAt: { $gt: new Date() }
        });
        this.verificationCode = foundVerificationCode ?? undefined;

        if (!this.verificationCode) {
            throw new HttpError('Verification code has expired or is invalid. Please request a new one.', 404);
        }

        // Check remaining attempts
        if (this.verificationCode.remainingAttempts <= 0) {
            this.logger.warn('Verification code has no remaining attempts', {
                codeId: this.verificationCode.codeId,
                attempts: this.verificationCode.attempts
            });
            throw new HttpError('Maximum verification attempts exceeded. Please request a new code.', 429);
        }

        this.logger.debug('Verification code found', {
            codeId: this.verificationCode.codeId,
            remainingAttempts: this.verificationCode.remainingAttempts
        });
    }

    /**
     * Step 4: Verify the OTP code
     */
    private async verifyOTPCode(): Promise<void> {
        this.logger.debug('Verifying OTP code');

        if (!this.verificationCode) {
            throw new HttpError('Verification code not found.', 500);
        }
        const isValidCode = this.verificationCode.verify(this.requestData.code, {});

        if (!isValidCode) {
            await this.verificationCode.save();

            // Add audit log to temp account
            this.tempAccount!.addAuditLog(
                'verification_failed',
                `Invalid ${this.requestData.verificationType} verification code attempted`,
                this.clientIP,
                this.event.headers?.['User-Agent']
            );
            await this.tempAccount!.save();

            this.logger.warn('Invalid verification code provided', {
                codeId: this.verificationCode.codeId,
                remainingAttempts: this.verificationCode.remainingAttempts
            });

            throw new HttpError(
                `Invalid verification code. ${this.verificationCode.remainingAttempts} attempts remaining.`,
                400
            );
        }

        // Code is valid - mark as used
        this.verificationCode.isUsed = true;
        this.verificationCode.usedAt = new Date();
        await this.verificationCode.save();

        this.logger.debug('OTP code verified successfully');
    }

    /**
     * Step 5: Update verification status
     */
    private async updateVerificationStatus(): Promise<void> {
        this.logger.debug('Updating verification status');

        const verificationType = this.requestData.verificationType;

        if (verificationType === 'email') {
            this.tempAccount!.verificationRequirements.emailVerification.completed = true;
            this.tempAccount!.verificationRequirements.emailVerification.verifiedAt = new Date();
        } else {
            this.tempAccount!.verificationRequirements.phoneVerification.completed = true;
            this.tempAccount!.verificationRequirements.phoneVerification.verifiedAt = new Date();
        }

        // Add audit log
        this.tempAccount!.addAuditLog(
            'verification_completed',
            `${verificationType} verification completed successfully`,
            this.clientIP,
            this.event.headers?.['User-Agent']
        );

        // Update status
        this.tempAccount!.status = 'verified';
        this.tempAccount!.lastActivity = new Date();

        await this.tempAccount!.save();

        this.logger.debug('Verification status updated successfully');
    }

    /**
     * Step 6: Check if all required verifications are complete
     */
    private async checkAllVerificationsComplete(): Promise<boolean> {
        const emailReq = this.tempAccount!.verificationRequirements.emailVerification;
        const phoneReq = this.tempAccount!.verificationRequirements.phoneVerification;

        const emailComplete = !emailReq.required || emailReq.completed;
        const phoneComplete = !phoneReq.required || phoneReq.completed;

        const allComplete = emailComplete && phoneComplete;

        this.logger.debug('Checking verification completeness', {
            emailRequired: emailReq.required,
            emailComplete: emailReq.completed,
            phoneRequired: phoneReq.required,
            phoneComplete: phoneReq.completed,
            allComplete
        });

        return allComplete;
    }

    /**
     * Step 7: Create final account if all verifications complete
     */
    private async createFinalAccount(): Promise<void> {
        this.logger.debug('Creating final account');

        // Create the final account
        const accountData = {
            email: this.tempAccount!.email,
            phone: this.tempAccount!.phone,
            username: this.tempAccount!.username,
            password: this.tempAccount!.password, // This can now be undefined
            hasPassword: !!this.tempAccount!.password, // Set the flag

            profile: {
                firstName: this.tempAccount!.profile.firstName,
                lastName: this.tempAccount!.profile.lastName,
                displayName: this.tempAccount!.profile.displayName,
                dateOfBirth: this.tempAccount!.profile.dateOfBirth,
                gender: this.tempAccount!.profile.gender,
                language: this.tempAccount!.profile.language,
                timezone: this.tempAccount!.profile.timezone,
                country: this.tempAccount!.profile.country
            },

            preferences: {
                language: this.tempAccount!.profile.language || 'en',
                timezone: this.tempAccount!.profile.timezone || 'UTC',
                notifications: {
                    email: this.tempAccount!.complianceData.marketingConsent?.email || false,
                    sms: this.tempAccount!.complianceData.marketingConsent?.sms || false,
                    push: this.tempAccount!.complianceData.marketingConsent?.push || false
                }
            },

            security: {
                emailVerified: this.tempAccount!.verificationRequirements.emailVerification.completed,
                phoneVerified: this.tempAccount!.verificationRequirements.phoneVerification.completed,
                emailVerifiedAt: this.tempAccount!.verificationRequirements.emailVerification.verifiedAt,
                phoneVerifiedAt: this.tempAccount!.verificationRequirements.phoneVerification.verifiedAt,
                lastPasswordChange: this.tempAccount!.password ? new Date() : undefined, // Only set if password exists
                twoFactorEnabled: !this.tempAccount!.password // Enable 2FA if no password
            },

            // Force 2FA for passwordless accounts
            mfaConfig: {
                enabled: !this.tempAccount!.password, // Enable if no password
                methods: {
                    email: {
                        enabled: !this.tempAccount!.password, // Use email 2FA if no password
                        verified: this.tempAccount!.verificationRequirements.emailVerification.completed
                    }
                }
            },

            deviceInfo: this.tempAccount!.deviceInfo,

            registrationData: {
                registrationMethod: this.tempAccount!.registrationContext.registrationMethod,
                registrationDate: this.tempAccount!.createdAt,
                registrationIP: this.tempAccount!.deviceInfo.ip,
                referralSource: this.tempAccount!.registrationContext.referralSource,
                utmSource: this.tempAccount!.registrationContext.utmSource,
                utmMedium: this.tempAccount!.registrationContext.utmMedium,
                utmCampaign: this.tempAccount!.registrationContext.utmCampaign
            },

            complianceData: this.tempAccount!.complianceData,

            accountStatus: 'active',
            accountType: 'standard'
        };

        this.finalAccount = new Account(accountData);
        await this.finalAccount.save();

        // Update temp account status
        this.tempAccount!.status = 'verified';
        this.tempAccount!.metadata.accountCreated = true;
        this.tempAccount!.metadata.finalAccountId = this.finalAccount.accountId;

        this.tempAccount!.addAuditLog(
            'account_created',
            'Final account created successfully',
            this.clientIP,
            this.event.headers?.['User-Agent']
        );

        await this.tempAccount!.save();

        this.logger.info('Final account created successfully', {
            accountId: this.finalAccount.accountId,
            tempId: this.tempAccount!.tempId
        });
    }

    /**
     * Step 8: Prepare response data
     */
    private prepareResponseData(allVerificationsComplete: boolean): ValidateOTPResponseData {
        const hasCompleteProfile = this.hasCompleteProfile();

        let accountStatus: 'verified' | 'partially_verified' | 'completed';
        let nextStep: { action: 'login' | 'complete_profile' | 'verify_email' | 'verify_phone'; message: string } | undefined;

        if (allVerificationsComplete) {
            accountStatus = 'completed';
            if (hasCompleteProfile) {
                nextStep = {
                    action: 'login',
                    message: 'Account created successfully. You can now log in.'
                };
            } else {
                nextStep = {
                    action: 'complete_profile',
                    message: 'Please complete your profile information.'
                };
            }
        } else {
            accountStatus = 'partially_verified';
            // Determine what verification is still needed
            const emailReq = this.tempAccount!.verificationRequirements.emailVerification;
            const phoneReq = this.tempAccount!.verificationRequirements.phoneVerification;

            if (emailReq.required && !emailReq.completed) {
                nextStep = {
                    action: 'verify_email',
                    message: 'Please verify your email address to complete registration.'
                };
            } else if (phoneReq.required && !phoneReq.completed) {
                nextStep = {
                    action: 'verify_phone',
                    message: 'Please verify your phone number to complete registration.'
                };
            }
        }

        return {
            success: true,
            tempId: this.tempAccount!.tempId,
            message: `${this.requestData.verificationType} verification completed successfully.`,
            accountStatus,
            nextStep,
            verificationStatus: {
                email: this.tempAccount!.verificationRequirements.emailVerification.completed,
                phone: this.tempAccount!.verificationRequirements.phoneVerification.completed
            },
            accountCreated: allVerificationsComplete,
            accountId: this.finalAccount?.accountId,
            metadata: {
                verificationType: this.requestData.verificationType,
                hasCompleteProfile,
                allVerificationsComplete
            }
        };
    }

    // ==================== HELPER METHODS ====================

    private hasCompleteProfile(): boolean {
        if (!this.tempAccount) return false;

        return !!(
            this.tempAccount.profile.firstName &&
            this.tempAccount.profile.lastName
        );
    }
}

// ==================== LAMBDA HANDLER ====================

const ValidateOTPHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Validate OTP handler started');

    // Parse request body
    const parsedBody = parseRequestBody<ValidateOTPRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process OTP validation
    const businessHandler = new ValidateOTPBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Validate OTP handler completed successfully');
    logger.logBusinessEvent('LAMBDA_SUCCESS', {
        operationType: 'otp_validation',
        tempId: result.tempId,
        verificationType: result.metadata.verificationType,
        accountCreated: result.accountCreated
    });

    return SuccessResponse({
        message: 'OTP validation completed successfully',
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(ValidateOTPHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});