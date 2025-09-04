import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import bcrypt from 'bcryptjs';
import { TempAccount, ITempAccount } from '../../models/temp_account.schema';
import { Account } from '../../models/account.schema';
import { SQSService } from '../../utils/lambdaSqs';
import { VerificationCode } from '../../models/verification_codes.schema';
import ProjectSettingsModel, { IProjectSettings } from '../../models/project.schema';

// ==================== INTERFACES ====================

interface RegisterAccountRequest {
    // Primary identifier - at least one required
    email?: string;
    phone?: string;
    username?: string;

    // REQUIRED password and name fields
    password: string;
    firstName: string;
    lastName: string;

    // Optional profile information
    displayName?: string;
    dateOfBirth?: string; // ISO date string
    gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
    language?: string;
    timezone?: string;
    country: string;

    // Registration context
    registrationMethod?: 'email' | 'phone';
    referralSource?: string;
    utmSource?: string;
    utmMedium?: string;
    utmCampaign?: string;

    // Compliance
    termsAccepted: boolean;
    privacyPolicyAccepted: boolean;
    termsVersion: string;
    privacyVersion: string;
    marketingConsent?: {
        email?: boolean;
        sms?: boolean;
        push?: boolean;
    };
    gdprConsent?: boolean;

    // Device/Security info
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

    // Captcha verification
    captchaToken?: string;
    captchaProvider?: 'recaptcha' | 'hcaptcha' | 'cloudflare';
}

interface RegisterAccountResponseData {
    tempId: string;
    status: string;
    message: string;
    nextStep: {
        action: 'verify_email' | 'verify_phone';
        identifier: string;
        expiresIn: number; // seconds
    };
    verificationRequired: {
        email: boolean;
        phone: boolean;
    };
    accountCreated: boolean;
    metadata: {
        registrationMethod: string;
        hasProfile: boolean;
        requiresCompletion: boolean;
    };
}

// ==================== BUSINESS HANDLER CLASS ====================

class RegisterAccountBusinessHandler {
    private requestData: RegisterAccountRequest;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;

    private sqsservice: SQSService;

    // Environment variables
    private readonly SQS_QUEUE_URL: string;

    // Services (TODO: Initialize these in constructor)
    // private verificationCodeService: VerificationCodeService;
    // private emailService: EmailService;
    // private smsService: SMSService;

    // Data holders
    private project?: IProjectSettings; // Project configuration
    private tempAccount?: ITempAccount;
    private hashedPassword?: string;
    private clientIP: string = '';
    private deviceLocation?: any;
    private securityCheckResult?: any;

    constructor(event: APIGatewayProxyEvent, body: RegisterAccountRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

        // Initialize services
        this.sqsservice = new SQSService();

        // Get environment variables
        this.SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';

        // TODO: Initialize external services
        // this.verificationCodeService = new VerificationCodeService();
        // this.emailService = new EmailService();
        // this.smsService = new SMSService();

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            registrationMethod: this.requestData.registrationMethod || this.determineRegistrationMethod(),
            functionName: 'register-account'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<RegisterAccountResponseData> {
        this.logger.info('Starting account registration process');

        await this.loadProjectConfiguration();

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Check for existing accounts
        await this.checkExistingAccounts();

        // Step 4: Hash password (now always required)
        await this.hashPassword();

        if (this.project?.settings?.traditionalFlow.registration.verificationRequired) {
            // Step 5: Create temp account
            await this.createTempAccount();

            // Step 6: Send verification code
            await this.sendVerificationCode();
        } else {
            throw new HttpError('Self-service registration without verification is not allowed yet', 400);
        }

        // Step 7: Prepare response
        const responseData = this.prepareResponseData();

        this.logger.info('Account registration completed successfully', {
            tempId: this.tempAccount!.tempId,
            registrationMethod: this.requestData.registrationMethod,
            hasProfile: this.hasProfileInfo()
        });

        this.logger.logBusinessEvent('ACCOUNT_REGISTRATION_INITIATED', {
            tempId: this.tempAccount!.tempId,
            registrationMethod: this.requestData.registrationMethod,
            hasCompleteProfile: this.hasProfileInfo()
        });

        return responseData;
    }

    private async validatePasswordAgainstProjectPolicy(): Promise<void> {
        // Password is now always required, so no need to check if it exists
        if (!this.project?.settings?.passwordPolicy) {
            // Fallback to basic validation if no project policy
            if (this.requestData.password.length < 8) {
                throw new HttpError('Password must be at least 8 characters long', 400);
            }
            return;
        }

        const policy = this.project.settings.passwordPolicy;
        const password = this.requestData.password;

        // Validate against project password policy
        if (password.length < policy.minLength) {
            throw new HttpError(`Password must be at least ${policy.minLength} characters long`, 400);
        }

        if (policy.requireUppercase && !/[A-Z]/.test(password)) {
            throw new HttpError('Password must contain at least one uppercase letter', 400);
        }

        if (policy.requireNumbers && !/\d/.test(password)) {
            throw new HttpError('Password must contain at least one number', 400);
        }

        if (policy.requireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            throw new HttpError('Password must contain at least one special character', 400);
        }
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating registration request data');

        if (!this.project?.settings?.traditionalFlow?.registration) {
            this.logger.error('Traditional registration flow configuration is missing');
            throw new HttpError('Registration configuration not found', 500);
        }

        // Get required fields from the settings
        const requiredFields: string[] = this.project.settings.traditionalFlow.registration.requiredFields;

        // Optional: map custom messages dynamically
        const customMessages: Record<string, string> = requiredFields.reduce((acc, field) => {
            acc[field] = `${this.formatFieldName(field)} is required`;
            return acc;
        }, {} as Record<string, string>);

        validateRequiredFields(this.requestData, requiredFields, customMessages);

        // Specific validations
        this.validateSpecificFields();

        this.logger.debug('Request validation completed');
    }

    // Helper to prettify field names for messages
    private formatFieldName(field: string): string {
        return field
            .replace(/([A-Z])/g, ' $1') // split camelCase
            .replace(/^./, str => str.toUpperCase()); // capitalize first letter
    }


    private validateSpecificFields(): void {
        // At least one identifier required
        if (!this.requestData.email && !this.requestData.phone && !this.requestData.username) {
            throw new HttpError('At least one of email, phone, or username is required', 400);
        }

        // Validate firstName and lastName
        if (this.requestData.firstName.trim().length === 0) {
            throw new HttpError('First name cannot be empty', 400);
        }

        if (this.requestData.lastName.trim().length === 0) {
            throw new HttpError('Last name cannot be empty', 400);
        }

        // First name validation (length and characters)
        if (this.requestData.firstName.length < 2 || this.requestData.firstName.length > 50) {
            throw new HttpError('First name must be between 2 and 50 characters', 400);
        }

        if (!/^[a-zA-ZÀ-ÿ\s'-]+$/.test(this.requestData.firstName)) {
            throw new HttpError('First name can only contain letters, spaces, hyphens, and apostrophes', 400);
        }

        // Last name validation (length and characters)
        if (this.requestData.lastName.length < 2 || this.requestData.lastName.length > 50) {
            throw new HttpError('Last name must be between 2 and 50 characters', 400);
        }

        if (!/^[a-zA-ZÀ-ÿ\s'-]+$/.test(this.requestData.lastName)) {
            throw new HttpError('Last name can only contain letters, spaces, hyphens, and apostrophes', 400);
        }

        // Password validation (now always required)
        this.validatePasswordAgainstProjectPolicy();

        // Email validation
        if (this.requestData.email && !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(this.requestData.email)) {
            throw new HttpError('Invalid email format', 400);
        }

        // Phone validation (E.164 format)
        if (this.requestData.phone && !/^\+[1-9]\d{1,14}$/.test(this.requestData.phone)) {
            throw new HttpError('Invalid phone format. Use E.164 format (e.g., +1234567890)', 400);
        }

        // Username validation
        if (this.requestData.username) {
            if (this.requestData.username.length < 3 || this.requestData.username.length > 30) {
                throw new HttpError('Username must be between 3 and 30 characters', 400);
            }
            if (!/^[a-zA-Z0-9_.-]+$/.test(this.requestData.username)) {
                throw new HttpError('Username can only contain letters, numbers, dots, hyphens and underscores', 400);
            }
        }

        // Date of birth validation
        if (this.requestData.dateOfBirth) {
            const dob = new Date(this.requestData.dateOfBirth);
            if (isNaN(dob.getTime())) {
                throw new HttpError('Invalid date of birth format', 400);
            }

            // Check if user is at least 13 years old
            const minAge = new Date();
            minAge.setFullYear(minAge.getFullYear() - 13);
            if (dob > minAge) {
                throw new HttpError('You must be at least 13 years old to register', 400);
            }
        }

        // Gender validation
        if (this.requestData.gender && !['male', 'female', 'other', 'prefer_not_to_say'].includes(this.requestData.gender)) {
            throw new HttpError('Invalid gender value', 400);
        }

        // Compliance validation
        if (!this.requestData.termsAccepted || !this.requestData.privacyPolicyAccepted) {
            throw new HttpError('You must accept the terms of service and privacy policy', 400);
        }

        // Device info validation
        if (!this.requestData.deviceInfo || !this.requestData.deviceInfo.os || !this.requestData.deviceInfo.browser || !this.requestData.deviceInfo.userAgent) {
            throw new HttpError('Device information is required for security purposes', 400);
        }
    }

    private async loadProjectConfiguration(): Promise<void> {
        this.logger.debug('Loading project configuration');

        // Get the single project document from the DB
        const project = await ProjectSettingsModel.findOne({ category: "AUTH" });

        if (!project) {
            this.logger.error('No project configuration found in database');
            throw new HttpError('Project configuration not found. Please contact support.', 500);
        }

        if (project.settings && !project.settings.traditionalFlow.enabled) {
            this.logger.error('Traditional authentication flow is not enabled');
            throw new HttpError('Traditional authentication flow is not enabled', 400);
        }

        this.project = project;
    }

    private async checkExistingAccounts(): Promise<void> {
        this.logger.debug('Checking for existing accounts');

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

        // Check main accounts (cannot overwrite)
        const existingAccount = await Account.findOne({
            $or: conditions,
            accountStatus: { $ne: 'deactivated' }
        });

        if (existingAccount) {
            let conflictField = '';
            if (existingAccount.email === this.requestData.email?.toLowerCase()) conflictField = 'email';
            else if (existingAccount.phone === this.requestData.phone) conflictField = 'phone';
            else if (existingAccount.username === this.requestData.username?.toLowerCase()) conflictField = 'username';

            throw new HttpError(`An account with this ${conflictField} already exists`, 409);
        }

        // Check temp accounts
        const existingTempAccounts = await TempAccount.find({
            $or: conditions,
            status: { $in: ['active', 'verified', 'partial'] },
            expiresAt: { $gt: new Date() }
        });

        if (existingTempAccounts.length > 0) {
            // Delete all conflicting temp accounts so we can start fresh
            const deleteIds = existingTempAccounts.map(acc => acc._id);
            await TempAccount.deleteMany({ _id: { $in: deleteIds } });

            this.logger.info(`Deleted ${deleteIds.length} conflicting temporary account(s) to allow new registration`);
        }

        this.logger.debug('No main account conflicts, temp accounts cleaned up');
    }


    /**
     * Step 3: Perform security checks
     */
    // private async performSecurityChecks(): Promise<void> {
    //     this.logger.debug('Performing security checks');

    //     // TODO: Implement actual security checks
    //     // - IP reputation check
    //     // - Email reputation check (if provided)
    //     // - Disposable email detection
    //     // - VPN/Tor detection
    //     // - Device fingerprinting analysis
    //     // - Captcha verification

    //     this.securityCheckResult = {
    //         riskScore: 0,
    //         riskFactors: [],
    //         isHighRisk: false,
    //         checks: {
    //             emailReputation: true,
    //             phoneReputation: true,
    //             ipReputation: true,
    //             deviceReputation: true,
    //             disposableEmail: false,
    //             vpnDetected: false,
    //             torDetected: false,
    //             botDetected: false
    //         },
    //         lastCheck: new Date()
    //     };

    //     // Basic disposable email check
    //     if (this.requestData.email) {
    //         const disposableDomains = ['10minutemail.com', 'tempmail.org', 'guerrillamail.com'];
    //         const emailDomain = this.requestData.email.split('@')[1]?.toLowerCase();
    //         if (disposableDomains.includes(emailDomain)) {
    //             this.securityCheckResult.checks.disposableEmail = true;
    //             this.securityCheckResult.riskScore += 30;
    //             this.securityCheckResult.riskFactors.push('Disposable email detected');
    //         }
    //     }

    //     // TODO: Verify captcha token
    //     if (this.requestData.captchaToken) {
    //         // Implement captcha verification
    //         this.logger.debug('Captcha token provided for verification');
    //     }

    //     if (this.securityCheckResult.riskScore > 70) {
    //         this.securityCheckResult.isHighRisk = true;
    //         this.logger.warn('High risk registration detected', {
    //             riskScore: this.securityCheckResult.riskScore,
    //             riskFactors: this.securityCheckResult.riskFactors
    //         });
    //     }

    //     this.logger.debug('Security checks completed', {
    //         riskScore: this.securityCheckResult.riskScore,
    //         isHighRisk: this.securityCheckResult.isHighRisk
    //     });
    // }

    /**
     * Step 4: Hash password (now always required) using bcryptjs
     */
    public async hashPassword(): Promise<void> {
        this.logger.debug('Hashing password with bcryptjs');

        const saltRounds = 12; // good balance of security & performance
        this.hashedPassword = await bcrypt.hash(this.requestData.password, saltRounds);

        this.logger.debug('Password hashed successfully');
    }

    /**
     * Step 5: Create temp account
     */
    private async createTempAccount(): Promise<void> {
        this.logger.debug('Creating temporary account');

        const registrationMethod = this.determineRegistrationMethod();

        // Prepare device location (TODO: implement geolocation service)
        this.deviceLocation = {
            country: this.requestData.country
            // TODO: Add city, region, latitude, longitude from IP geolocation
        };

        const tempAccountData = {
            // Basic identifiers
            email: this.requestData.email?.toLowerCase(),
            phone: this.requestData.phone,
            username: this.requestData.username?.toLowerCase(),
            password: this.hashedPassword, // Now always present since password is required

            // Profile info (firstName and lastName now always present)
            profile: {
                firstName: this.requestData.firstName,
                lastName: this.requestData.lastName,
                displayName: this.requestData.displayName,
                dateOfBirth: this.requestData.dateOfBirth ? new Date(this.requestData.dateOfBirth) : undefined,
                gender: this.requestData.gender,
                language: this.requestData.language || 'en',
                timezone: this.requestData.timezone || 'UTC',
                country: this.requestData.country
            },

            // Registration context
            registrationContext: {
                registrationMethod: registrationMethod as 'email' | 'phone',
                referralSource: this.requestData.referralSource,
                utmSource: this.requestData.utmSource,
                utmMedium: this.requestData.utmMedium,
                utmCampaign: this.requestData.utmCampaign
            },

            // Verification requirements
            verificationRequirements: {
                emailVerification: {
                    required: !!this.requestData.email,
                    completed: false,
                    attempts: 0
                },
                phoneVerification: {
                    required: !!this.requestData.phone && registrationMethod === 'phone',
                    completed: false,
                    attempts: 0
                },
                socialVerification: {
                    required: false,
                    completed: false
                },
                documentVerification: {
                    required: false,
                    completed: false
                },
                captchaVerification: {
                    required: !!this.requestData.captchaToken,
                    completed: !!this.requestData.captchaToken, // TODO: verify actual token
                    provider: this.requestData.captchaProvider || 'recaptcha'
                }
            },

            // Device info
            deviceInfo: {
                deviceType: this.requestData.deviceInfo.deviceType || 'unknown',
                os: this.requestData.deviceInfo.os,
                browser: this.requestData.deviceInfo.browser,
                userAgent: this.requestData.deviceInfo.userAgent,
                ip: this.clientIP,
                location: this.deviceLocation,
                fingerprint: this.requestData.deviceInfo.fingerprint
            },

            // Security check results
            securityCheck: this.securityCheckResult,

            // Compliance data
            complianceData: {
                termsAccepted: {
                    accepted: this.requestData.termsAccepted,
                    version: this.requestData.termsVersion,
                    acceptedAt: new Date(),
                    ip: this.clientIP
                },
                privacyPolicyAccepted: {
                    accepted: this.requestData.privacyPolicyAccepted,
                    version: this.requestData.privacyVersion,
                    acceptedAt: new Date(),
                    ip: this.clientIP
                },
                marketingConsent: {
                    email: this.requestData.marketingConsent?.email || false,
                    sms: this.requestData.marketingConsent?.sms || false,
                    push: this.requestData.marketingConsent?.push || false,
                    consentedAt: this.requestData.marketingConsent ? new Date() : undefined
                },
                ageVerification: {
                    verified: !!this.requestData.dateOfBirth,
                    method: this.requestData.dateOfBirth ? 'self_declared' : undefined,
                    verifiedAt: this.requestData.dateOfBirth ? new Date() : undefined
                },
                gdprConsent: {
                    given: this.requestData.gdprConsent || false,
                    version: '1.0',
                    consentedAt: this.requestData.gdprConsent ? new Date() : undefined,
                    ip: this.clientIP
                }
            },

            // Status
            status: 'active',
            lastActivity: new Date(),

            // Metadata
            metadata: {
                hasCompleteProfile: this.hasProfileInfo(),
                registrationSource: 'api',
                deviceFingerprint: this.requestData.deviceInfo.fingerprint?.hash
            }
        };

        this.tempAccount = new TempAccount(tempAccountData);

        // Add initial audit log
        this.tempAccount.addAuditLog(
            'account_created',
            `Registration initiated via ${registrationMethod}`,
            this.clientIP,
            this.requestData.deviceInfo.userAgent
        );

        await this.tempAccount.save();

        this.logger.debug('Temporary account created successfully', {
            tempId: this.tempAccount.tempId,
            hasProfile: this.hasProfileInfo()
        });
    }

    /**
     * Step 6: Send verification code
     */
    private async sendVerificationCode(): Promise<void> {
        if (!this.tempAccount) return;

        const registrationMethod = this.determineRegistrationMethod();

        this.logger.debug('Sending verification code', {
            method: registrationMethod,
            tempId: this.tempAccount.tempId
        });

        try {
            if (registrationMethod === 'email' && this.requestData.email) {
                // Generate OTP using the schema's static method
                const otpCode = VerificationCode.generateCode(6); // 6-digit code
                const hashedOtp = VerificationCode.hashCode(otpCode);

                // Create verification code record
                const verificationCode = new VerificationCode({
                    accountId: undefined, // No account yet, using temp account
                    code: otpCode,
                    hashedCode: hashedOtp,
                    type: 'email_verification',
                    purpose: 'Email verification for account registration',
                    method: 'email',
                    deliveryInfo: {
                        channel: 'email',
                        provider: 'ses', // or your email provider
                        recipient: this.requestData.email,
                        deliveryStatus: 'pending'
                    },
                    maxAttempts: 3,
                    remainingAttempts: 3,
                    context: {
                        initiatedBy: 'user',
                        triggerEvent: 'account_registration',
                        metadata: {
                            tempAccountId: this.tempAccount.tempId,
                            registrationMethod: registrationMethod
                        },
                        sessionId: this.event.requestContext?.requestId,
                        ip: this.clientIP,
                        userAgent: this.requestData.deviceInfo.userAgent,
                        location: {
                            country: this.requestData.country
                        }
                    },
                    security: {
                        requiresSecureChannel: true,
                        preventBruteForce: true,
                        logAllAttempts: true,
                        notifyOnFailure: false,
                        riskScore: this.securityCheckResult?.riskScore || 0
                    },
                    linkedOperations: [{
                        operationType: 'account_registration',
                        operationId: this.tempAccount.tempId,
                        requiresCompletion: true
                    }],
                    template: {
                        language: this.requestData.language || 'en',
                        variables: {
                            firstName: this.requestData.firstName, // Now always available
                            email: this.requestData.email
                        }
                    }
                });

                await verificationCode.save();

                // Prepare SQS message with OTP (now includes firstName)
                const sqsBody = {
                    "notificationType": "email_verification",
                    "channels": ["email"],
                    "content": {
                        "email": {
                            "subject": "Verify Your Email Address",
                            "template": "account-verification",
                            "data": {
                                "email": this.requestData.email,
                                "name": this.requestData.firstName, // Now always available
                                "otp": otpCode, // Include the generated OTP
                                "verificationCodeId": verificationCode.codeId,
                                "expiryMinutes": 10
                            },
                            "metadata": {
                                "campaign_id": "email_verification_2024",
                                "trigger_source": "signup",
                                "tempAccountId": this.tempAccount.tempId
                            }
                        }
                    },
                    "priority": "high"
                };

                await this.sqsservice.sendMessage(this.SQS_QUEUE_URL, sqsBody);

                // Update temp account with verification code reference
                this.tempAccount.verificationRequirements.emailVerification.codeId = verificationCode.codeId;

                this.tempAccount.addAuditLog(
                    'verification_email_sent',
                    `Verification email with OTP sent to ${this.requestData.email}`,
                    this.clientIP
                );

                this.logger.debug('Verification code generated and queued for email delivery', {
                    verificationCodeId: verificationCode.codeId,
                    recipient: this.requestData.email
                });

            } else if (registrationMethod === 'phone' && this.requestData.phone) {
                // Generate OTP for SMS
                const otpCode = VerificationCode.generateCode(6);
                const hashedOtp = VerificationCode.hashCode(otpCode);

                // Create verification code record for SMS
                const verificationCode = new VerificationCode({
                    accountId: undefined,
                    code: otpCode,
                    hashedCode: hashedOtp,
                    type: 'phone_verification',
                    purpose: 'Phone verification for account registration',
                    method: 'sms',
                    deliveryInfo: {
                        channel: 'sms',
                        provider: 'twilio', // or your SMS provider
                        recipient: this.requestData.phone,
                        deliveryStatus: 'pending'
                    },
                    maxAttempts: 3,
                    remainingAttempts: 3,
                    context: {
                        initiatedBy: 'user',
                        triggerEvent: 'account_registration',
                        metadata: {
                            tempAccountId: this.tempAccount.tempId,
                            registrationMethod: registrationMethod
                        },
                        sessionId: this.event.requestContext?.requestId,
                        ip: this.clientIP,
                        userAgent: this.requestData.deviceInfo.userAgent,
                        location: {
                            country: this.requestData.country
                        }
                    },
                    security: {
                        requiresSecureChannel: true,
                        preventBruteForce: true,
                        logAllAttempts: true,
                        notifyOnFailure: false,
                        riskScore: this.securityCheckResult?.riskScore || 0
                    },
                    linkedOperations: [{
                        operationType: 'account_registration',
                        operationId: this.tempAccount.tempId,
                        requiresCompletion: true
                    }],
                    template: {
                        language: this.requestData.language || 'en',
                        variables: {
                            firstName: this.requestData.firstName, // Now always available
                            phone: this.requestData.phone
                        }
                    }
                });

                await verificationCode.save();

                // Update temp account with verification code reference
                this.tempAccount.verificationRequirements.phoneVerification.codeId = verificationCode.codeId;

                this.tempAccount.addAuditLog(
                    'verification_sms_sent',
                    `Verification SMS with OTP sent to ${this.requestData.phone}`,
                    this.clientIP
                );

                this.logger.debug('Verification code generated for SMS delivery', {
                    verificationCodeId: verificationCode.codeId,
                    recipient: this.requestData.phone
                });
            }

            await this.tempAccount.save();
            this.logger.debug('Verification code sent successfully');

        } catch (error) {
            this.logger.error('Failed to send verification code', {
                error: error instanceof Error ? error.message : 'Unknown error',
                method: registrationMethod,
                tempId: this.tempAccount.tempId
            });

            // Don't throw error - account is created, user can retry verification
            this.tempAccount.addAuditLog(
                'verification_send_failed',
                `Failed to send verification via ${registrationMethod}`,
                this.clientIP
            );
            await this.tempAccount.save();
        }
    }

    /**
     * Step 7: Prepare response data
     */
    private prepareResponseData(): RegisterAccountResponseData {
        if (!this.tempAccount) {
            throw new HttpError('Temporary account not created', 500);
        }

        const registrationMethod = this.determineRegistrationMethod();
        const identifier = registrationMethod === 'email'
            ? this.requestData.email!
            : this.requestData.phone!;

        return {
            tempId: this.tempAccount.tempId,
            status: 'pending_verification',
            message: 'Registration initiated successfully. Please verify your account to continue.',
            nextStep: {
                action: registrationMethod === 'email' ? 'verify_email' : 'verify_phone',
                identifier: this.maskIdentifier(identifier),
                expiresIn: Math.floor((this.tempAccount.expiresAt.getTime() - Date.now()) / 1000)
            },
            verificationRequired: {
                email: this.tempAccount.verificationRequirements.emailVerification.required,
                phone: this.tempAccount.verificationRequirements.phoneVerification.required
            },
            accountCreated: false,
            metadata: {
                registrationMethod,
                hasProfile: this.hasProfileInfo(),
                requiresCompletion: false // Now always false since profile info is required
            }
        };
    }

    // ==================== HELPER METHODS ====================

    private determineRegistrationMethod(): 'email' | 'phone' {
        if (this.requestData.registrationMethod) {
            return this.requestData.registrationMethod;
        }

        // Auto-determine based on provided fields
        if (this.requestData.email) return 'email';
        if (this.requestData.phone) return 'phone';

        return 'email'; // default
    }

    private hasProfileInfo(): boolean {
        // Now always returns true since firstName and lastName are required
        // But keeping the method for consistency and future extensibility
        return !!(
            this.requestData.firstName ||
            this.requestData.lastName ||
            this.requestData.displayName ||
            this.requestData.dateOfBirth
        );
    }

    private maskIdentifier(identifier: string): string {
        if (identifier.includes('@')) {
            // Email masking
            const [username, domain] = identifier.split('@');
            const maskedUsername = username.length > 2
                ? username.substring(0, 2) + '*'.repeat(username.length - 2)
                : '*'.repeat(username.length);
            return `${maskedUsername}@${domain}`;
        } else {
            // Phone masking
            const visibleDigits = 4;
            const maskedLength = identifier.length - visibleDigits;
            return maskedLength > 0
                ? identifier.substring(0, 2) + '*'.repeat(maskedLength) + identifier.slice(-2)
                : identifier;
        }
    }
}

// ==================== LAMBDA HANDLER ====================

const RegisterAccountHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Register account handler started');

    // Parse request body
    const parsedBody = parseRequestBody<RegisterAccountRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process registration
    const businessHandler = new RegisterAccountBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Register account handler completed successfully');
    logger.logBusinessEvent('LAMBDA_SUCCESS', {
        operationType: 'account_registration',
        tempId: result.tempId,
        registrationMethod: result.metadata.registrationMethod
    });

    return SuccessResponse({
        message: 'Registration initiated successfully',
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(RegisterAccountHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});