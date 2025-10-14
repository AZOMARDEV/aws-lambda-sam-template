import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { extractAuthData, ExtractedAuthData, SuccessResponse } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Account, IAccount } from '../../models/account.schema';
import { TempAccount, ITempAccount } from '../../models/temp_account.schema';
import { VerificationCode } from '../../models/verification_codes.schema';
import { Session, ISession } from '../../models/sessions.schema';
import { SQSService } from '../../utils/lambdaSqs';
import jwt, { SignOptions } from 'jsonwebtoken';
import ProjectSettingsModel, { IProjectSettings } from '../../models/project.schema';

// ==================== INTERFACES ====================

interface CombinedAuthRequest {
    // Primary identifier - one required
    email?: string;
    phone?: string;

    // Registration context
    combinedMethod?: 'email' | 'phone';

    // Compliance (for new registrations)
    termsAccepted?: boolean;
    privacyPolicyAccepted?: boolean;
    termsVersion?: string;
    privacyVersion?: string;

    // Optional flags
    rememberMe?: boolean;

    // OTP code (for verification step)
    otpCode?: string;

    // Session continuation
    loginSessionId?: string;
}

interface CombinedAuthResponseData {
    success: boolean;
    authFlow: 'login_success' | 'profile_completion_required' | 'otp_sent';
    message: string;

    // Successful login data
    accessToken?: string;
    refreshToken?: string;
    expiresIn?: number;
    sessionId?: string;

    // OTP/Registration data
    tempId?: string;
    loginSessionId?: string;
    nextStep?: {
        action: 'verify_otp' | 'complete_profile';
        identifier?: string;
        expiresIn?: number;
        requiredFields?: string[];
        method?: 'email' | 'sms';
        purpose?: string;
    };

    // Account info
    accountId?: string;
    profile?: {
        firstName?: string;
        lastName?: string;
        displayName?: string;
        picture?: any;
        isComplete?: boolean;
        completionPercentage?: number;
    };

    // Status info
    lastLogin?: Date;
    newDevice?: boolean;
    accountCreated?: boolean;
    isNewUser?: boolean;
}

// ==================== BUSINESS HANDLER CLASS ====================

class CombinedAuthBusinessHandler {
    private requestData: CombinedAuthRequest;
    private authdata: ExtractedAuthData;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;
    private sqsservice: SQSService;

    // Environment variables
    private readonly SQS_QUEUE_URL: string;
    private readonly JWT_SECRET: string;
    private readonly JWT_EXPIRES_IN: string;
    private readonly REFRESH_TOKEN_SECRET: string;

    // Data holders
    private account?: IAccount;
    private tempAccount?: ITempAccount;
    private project?: IProjectSettings;
    private session?: ISession;
    private clientIP: string = '';
    private deviceLocation?: any;
    private loginSessionId?: string;
    private isNewDevice: boolean = false;
    private authFlow: 'login_otp_send' | 'login_otp_verify' | 'register_otp_send' | 'register_otp_verify' = 'login_otp_send';

    constructor(event: APIGatewayProxyEvent, body: CombinedAuthRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
        this.authdata = extractAuthData(event.headers as Record<string, string>);

        // Initialize services
        this.sqsservice = new SQSService();

        // Get environment variables
        this.SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';
        this.JWT_SECRET = process.env.JWT_SECRET || '';
        this.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
        this.REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            identifier: this.getIdentifier(),
            functionName: 'combined-auth'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<CombinedAuthResponseData> {
        this.logger.info('Starting combined auth process');

        // Step 1: Load project configuration
        await this.loadProjectConfiguration();

        // Step 2: Basic validation
        this.validateBasicRequest();

        // Step 3: Determine auth flow
        await this.determineAuthFlow();

        // Step 4: Process based on determined flow
        switch (this.authFlow) {
            case 'login_otp_send':
                return await this.handleLoginOTPSend();
            case 'login_otp_verify':
                return await this.handleLoginOTPVerify();
            case 'register_otp_send':
                return await this.handleRegistrationOTPSend();
            case 'register_otp_verify':
                return await this.handleRegistrationOTPVerify();
            default:
                throw new HttpError('Invalid auth flow determined', 500);
        }
    }

    /**
     * Step 1: Basic validation
     */
    private validateBasicRequest(): void {
        this.logger.debug('Validating basic request data');

        // At least one identifier required
        if (!this.requestData.email && !this.requestData.phone) {
            throw new HttpError('Email or phone is required', 400);
        }

        this.logger.debug('Basic request validation completed');
    }

    /**
     * Step 2: Load project configuration
     */
    private async loadProjectConfiguration(): Promise<void> {
        this.logger.debug('Loading project configuration');

        const project = await ProjectSettingsModel.findOne({ category: "AUTH" });

        if (!project) {
            this.logger.error('No project configuration found in database');
            throw new HttpError('Project configuration not found. Please contact support.', 500);
        }

        if (project.settings && !project.settings.mfa.enabled) {
            this.logger.error('MFA authentication flow is not enabled');
            throw new HttpError('MFA authentication flow is not enabled', 400);
        }

        this.project = project;
    }

    /**
     * Step 3: Determine auth flow based on user existence and request data
     */
    private async determineAuthFlow(): Promise<void> {
        this.logger.debug('Determining auth flow');

        // Check for OTP verification step
        if (this.requestData.loginSessionId && this.requestData.otpCode) {
            // Determine if this is login or registration OTP verification
            const verificationCode = await VerificationCode.findOne({
                'context.metadata.loginSessionId': this.requestData.loginSessionId,
                status: "active",
                expiresAt: { $gt: new Date() }
            });

            if (!verificationCode) {
                throw new HttpError('Invalid or expired login session. Please start again.', 404);
            }

            if (verificationCode.purpose === 'register') {
                this.authFlow = 'register_otp_verify';
            } else {
                this.authFlow = 'login_otp_verify';
            }

            this.logger.info('Auth flow determined: OTP verification', { flow: this.authFlow });
            return;
        }

        // Build search conditions
        const conditions: any[] = [];
        if (this.requestData.email) {
            conditions.push({ email: this.requestData.email.toLowerCase() });
        }
        if (this.requestData.phone) {
            conditions.push({ phone: this.requestData.phone });
        }

        // Look for existing account
        const existingAccount = await Account.findOne({
            $or: conditions,
            "accountStatus.status": { $ne: "deactivated" }
        });

        if (existingAccount) {
            this.account = existingAccount;
            this.authFlow = 'login_otp_send';
            this.logger.debug('Auth flow determined: Existing user login OTP send', {
                accountId: this.account._id
            });
            return;
        }

        // Clean up any existing temp accounts with same identifiers
        const existingTempAccounts = await TempAccount.find({
            $or: conditions,
            status: { $in: ['active', 'verified', 'partial'] },
            expiresAt: { $gt: new Date() }
        });

        if (existingTempAccounts.length > 0) {
            const deleteIds = existingTempAccounts.map(acc => acc._id);
            await TempAccount.deleteMany({ _id: { $in: deleteIds } });
            this.logger.info(`Deleted ${deleteIds.length} conflicting temporary account(s) to allow new registration`);
        }

        // No existing user found - new registration
        this.authFlow = 'register_otp_send';
        this.logger.debug('Auth flow determined: New user registration OTP send');
    }

    /**
     * Handle login OTP send
     */
    private async handleLoginOTPSend(): Promise<CombinedAuthResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Handling login OTP send');

        // Check account status
        this.checkAccountStatus();

        // // Determine which identifier to use (phone or email)
        const verificationMethod = this.determineVerificationMethod();
        // let otpPurpose: 'login' | 'phone_verification' | 'email_verification' = 'login';

        // // If phone/email is not verified, send OTP for verification first
        // if (verificationMethod === 'sms' && !this.account.isPhoneVerified) {
        //     otpPurpose = 'phone_verification';
        //     this.logger.info('Phone not verified, sending OTP to verify phone');
        // } else if (verificationMethod === 'email' && !this.account.isEmailVerified) {
        //     otpPurpose = 'email_verification';
        //     this.logger.info('Email not verified, sending OTP to verify email');
        // } else {
        //     this.logger.info('Sending OTP for normal login');
        // }

        // Send OTP
        await this.sendLoginOTP(verificationMethod);

        return {
            success: true,
            authFlow: 'otp_sent',
            message: `OTP sent successfully. Please check your ${verificationMethod === 'email' ? 'email' : 'phone'} for the verification code.`,
            loginSessionId: this.loginSessionId,
            nextStep: {
                action: 'verify_otp',
                identifier: this.maskIdentifier(this.getPrimaryIdentifier()),
                method: verificationMethod,
                expiresIn: 300, // 5 minutes
            },
            accountId: String(this.account._id)
        };
    }


    /**
     * Handle login OTP verification
     */
    private async handleLoginOTPVerify(): Promise<CombinedAuthResponseData> {
        this.logger.debug('Handling login OTP verification');

        // Verify OTP
        const verificationCode = await this.verifyOTP();

        // Find the account
        const accountId = verificationCode.accountId;
        const accountData = await Account.findById(accountId);

        if (!accountData) {
            throw new HttpError('Account not found', 404);
        }

        this.account = accountData;

        // Complete login
        return await this.completeLogin(false);
    }

    /**
     * Handle registration OTP send
     */
    private async handleRegistrationOTPSend(): Promise<CombinedAuthResponseData> {
        this.logger.debug('Handling registration OTP send');

        // Create temp account
        await this.createTempAccount();

        // Determine verification method and send verification OTP
        const verificationMethod = this.determineVerificationMethod();
        await this.sendRegistrationOTP(verificationMethod);

        return {
            success: true,
            authFlow: 'otp_sent',
            message: `Registration initiated. Please verify your account with the OTP sent to your ${verificationMethod === 'email' ? 'email' : 'phone'}.`,
            loginSessionId: this.loginSessionId,
            tempId: this.tempAccount!.tempId,
            nextStep: {
                action: 'verify_otp',
                identifier: this.maskIdentifier(this.getPrimaryIdentifier()),
                method: verificationMethod,
                expiresIn: 600 // 10 minutes
            },
            accountCreated: false,
            isNewUser: true
        };
    }

    /**
     * Handle registration OTP verification
     */
    private async handleRegistrationOTPVerify(): Promise<CombinedAuthResponseData> {
        this.logger.debug('Handling registration OTP verification');

        // Verify OTP
        const verificationCode = await this.verifyOTP();

        // Find temp account
        const tempAccountId = verificationCode.context?.metadata?.tempAccountId;
        const tempAccountData = await TempAccount.findOne({ tempId: tempAccountId });

        if (!tempAccountData) {
            throw new HttpError('Temporary account not found', 404);
        }

        this.tempAccount = tempAccountData;
        this.tempAccount.status = 'verified';

        // Mark email or phone as verified
        if (verificationCode.method === 'email') {
            this.tempAccount.verificationRequirements.emailVerification.completed = true;
        } else if (verificationCode.method === 'phone') {
            this.tempAccount.verificationRequirements.phoneVerification.completed = true;
        }

        await this.tempAccount.save();

        // Check if profile completion is required
        if (this.project?.settings?.mfa?.requireProfileCompletion) {
            return {
                success: true,
                authFlow: 'profile_completion_required',
                message: 'OTP verified successfully. Please complete your profile to continue.',
                tempId: this.tempAccount.tempId,
                nextStep: {
                    action: 'complete_profile',
                    requiredFields: this.project.settings.mfa.profileCompletionFields || ['firstName', 'lastName']
                },
                accountCreated: false,
                isNewUser: true
            };
        }

        // No profile completion required - create account directly
        this.account = await this.convertTempToRealAccount();
        return await this.completeLogin(true);
    }

    /**
     * Verify OTP code
     */
    private async verifyOTP(): Promise<any> {
        const verificationCode = await VerificationCode.findOne({
            'context.metadata.loginSessionId': this.requestData.loginSessionId,
            status: "active",
            expiresAt: { $gt: new Date() }
        });

        if (!verificationCode) {
            throw new HttpError('Invalid or expired login session. Please start again.', 404);
        }

        // Verify OTP code
        const isValidOTP = verificationCode.verify(this.requestData.otpCode!, {});

        if (!isValidOTP) {
            await verificationCode.save();
            this.logger.warn('Invalid OTP code provided', {
                remainingAttempts: verificationCode.remainingAttempts
            });
            throw new HttpError(
                `Invalid OTP code. ${verificationCode.remainingAttempts} attempts remaining.`,
                400
            );
        }

        // Mark OTP as used
        verificationCode.isUsed = true;
        verificationCode.usedAt = new Date();
        await verificationCode.save();

        return verificationCode;
    }

    /**
     * Complete successful login/registration
     */
    private async completeLogin(isNewAccount: boolean = false): Promise<CombinedAuthResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Completing successful login', { isNewAccount });

        // Generate tokens
        const accessToken = this.generateAccessToken();
        const refreshToken = this.generateRefreshToken();

        // Create session
        await this.createSession(accessToken, refreshToken);

        // Update account login info
        this.account.lastLogin = new Date();
        this.account.loginCount += 1;

        // Add login history
        this.account.security.loginHistory.push({
            timestamp: new Date(),
            ip: this.clientIP,
            userAgent: this.authdata.metadata.device.userAgent,
            deviceId: this.authdata.metadata.device.deviceId,
            success: true,
            location: this.deviceLocation
        });

        // Manage trusted devices
        if (this.isNewDevice && this.authdata.metadata.device.deviceId) {
            this.account.security.trustedDevices.push(this.authdata.metadata.device.deviceId);
            if (this.account.security.trustedDevices.length > 10) {
                this.account.security.trustedDevices = this.account.security.trustedDevices.slice(-10);
            }
        }

        await this.account.save();

        // Calculate profile completion
        const profileCompletion = this.calculateProfileCompletion();

        this.logger.info('Login completed successfully', {
            accountId: this.account._id,
            sessionId: this.session?.sessionId,
            isNewAccount,
            profileCompletion: profileCompletion.percentage
        });

        return {
            success: true,
            authFlow: 'login_success',
            message: isNewAccount ? 'Account created and logged in successfully' : 'Login successful',
            accessToken,
            refreshToken,
            expiresIn: this.parseJWTExpiration(this.JWT_EXPIRES_IN),
            sessionId: this.session?.sessionId,
            accountId: String(this.account._id),
            profile: {
                firstName: this.account.profile?.firstName,
                lastName: this.account.profile?.lastName,
                displayName: this.account.profile?.displayName,
                picture: this.account.profile?.profilePicture,
                isComplete: profileCompletion.isComplete,
                completionPercentage: profileCompletion.percentage
            },
            lastLogin: this.account.lastLogin,
            newDevice: this.isNewDevice,
            accountCreated: isNewAccount,
            isNewUser: isNewAccount
        };
    }

    // ==================== HELPER METHODS ====================

    private async createTempAccount(): Promise<void> {
        const registrationMethod = this.determineRegistrationMethod();

        const tempAccountData = {
            email: this.requestData.email?.toLowerCase(),
            phone: this.requestData.phone,
            registrationContext: {
                registrationMethod: registrationMethod as 'email' | 'phone'
            },
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
                }
            },
            deviceInfo: {
                deviceType: this.authdata.metadata.device.type || 'unknown',
                os: this.authdata.metadata.device.os,
                browser: this.authdata.metadata.device.browser,
                userAgent: this.authdata.metadata.device.userAgent,
                ip: this.clientIP,
                location: this.deviceLocation,
                deviceId: this.authdata.metadata.device.deviceId
            },
            complianceData: {
                termsAccepted: {
                    accepted: this.requestData.termsAccepted || false,
                    version: this.requestData.termsVersion || '1.0',
                    acceptedAt: this.requestData.termsAccepted ? new Date() : undefined,
                    ip: this.clientIP
                },
                privacyPolicyAccepted: {
                    accepted: this.requestData.privacyPolicyAccepted || false,
                    version: this.requestData.privacyVersion || '1.0',
                    acceptedAt: this.requestData.privacyPolicyAccepted ? new Date() : undefined,
                    ip: this.clientIP
                }
            },
            status: 'active',
            lastActivity: new Date()
        };

        this.tempAccount = new TempAccount(tempAccountData);
        await this.tempAccount.save();

        this.logger.debug('Temp account created', { tempId: this.tempAccount.tempId });
    }

    private async sendRegistrationOTP(method: 'email' | 'sms'): Promise<void> {
        if (!this.tempAccount) return;

        const registrationMethod = this.determineRegistrationMethod();
        const otpCode = VerificationCode.generateCode(6);
        this.loginSessionId = `register_${Date.now()}_${Math.random().toString(36).substring(2)}`;

        const verificationCode = new VerificationCode({
            accountId: undefined,
            code: otpCode,
            hashedCode: VerificationCode.hashCode(otpCode),
            type: method === 'email' ? 'email_verification' : 'sms_verification',
            purpose: 'register',
            method: method,
            deliveryInfo: {
                channel: method,
                provider: method === 'email' ? 'ses' : 'twilio',
                recipient: method === 'email' ? this.requestData.email : this.requestData.phone,
                deliveryStatus: 'pending'
            },
            maxAttempts: 3,
            remainingAttempts: 3,
            expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
            context: {
                initiatedBy: 'user',
                triggerEvent: 'combined_auth_registration',
                metadata: {
                    tempAccountId: this.tempAccount.tempId,
                    registrationMethod: registrationMethod,
                    loginSessionId: this.loginSessionId,
                },
                sessionId: this.event.requestContext?.requestId,
                ip: this.clientIP,
                userAgent: this.authdata.metadata.device.userAgent
            },
            security: {
                requiresSecureChannel: true,
                preventBruteForce: true,
                logAllAttempts: true,
                riskScore: 0
            }
        });

        await verificationCode.save();

        // Send via SQS
        await this.sendVerificationOTP(method, otpCode);

        // Update temp account
        if (method === 'email') {
            this.tempAccount.verificationRequirements.emailVerification.codeId = verificationCode.codeId;
        } else {
            this.tempAccount.verificationRequirements.phoneVerification.codeId = verificationCode.codeId;
        }
        await this.tempAccount.save();
    }

    private async sendLoginOTP(
        method: 'email' | 'sms',
        purpose: 'login' | 'phone_verification' | 'email_verification' = 'login'
    ): Promise<void> {
        if (!this.account) return;

        const otpCode = VerificationCode.generateCode(6);
        this.loginSessionId = `login_${Date.now()}_${Math.random().toString(36).substring(2)}`;

        const verificationCode = new VerificationCode({
            accountId: this.account._id,
            code: otpCode,
            hashedCode: VerificationCode.hashCode(otpCode),
            type: 'mfa',
            purpose: purpose, // dynamic purpose
            method: method,
            deliveryInfo: {
                channel: method,
                provider: method === 'email' ? 'ses' : 'twilio',
                recipient: method === 'email' ? this.account.email : this.account.phone,
                deliveryStatus: 'pending'
            },
            maxAttempts: 3,
            remainingAttempts: 3,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
            context: {
                initiatedBy: 'user',
                triggerEvent: 'combined_auth_login',
                metadata: {
                    accountId: String(this.account._id),
                    loginSessionId: this.loginSessionId
                },
                sessionId: this.event.requestContext?.requestId,
                ip: this.clientIP,
                userAgent: this.authdata.metadata.device.userAgent
            },
            security: {
                requiresSecureChannel: true,
                preventBruteForce: true,
                logAllAttempts: true,
                riskScore: this.calculateRiskScore()
            }
        });

        await verificationCode.save();

        // Send via SQS (email/SMS)
        await this.sendVerificationOTP(method, otpCode);
    }


    /**
     * Send 2FA OTP via preferred method
     */
    private async sendVerificationOTP(method: 'sms' | 'email', otpCode: string): Promise<void> {
        const isLogin = !!this.account;
        const recipient = method === 'sms'
            ? (this.account?.phone || this.requestData.phone)
            : (this.account?.email || this.requestData.email);

        if (!recipient) {
            throw new HttpError(`${method === 'sms' ? 'Phone' : 'Email'} is required for verification`, 400);
        }

        const sqsBody = {
            notificationType: method === 'sms' ? 'sms_2fa' : (isLogin ? 'email_2fa' : 'email_verification'),
            channels: [method === 'sms' ? 'sms' : 'email'],
            content: method === 'sms' ? {
                sms: {
                    message: this.project?.settings?.smsSettings?.templates?.verification ||
                        `Your verification code is: ${otpCode}. This code expires in ${isLogin ? '5' : '10'} minutes.`,
                    recipient: recipient
                }
            } : {
                email: {
                    subject: isLogin ? 'Login Verification Code' : 'Verify Your Email Address',
                    template: isLogin
                        ? (this.project?.settings?.emailSettings?.templates?.['login-2fa'] || 'login-2fa')
                        : (this.project?.settings?.emailSettings?.templates?.['account-verification'] || 'account-verification'),
                    data: {
                        name: this.account?.profile?.firstName || 'User',
                        otp: otpCode,
                        expiryMinutes: isLogin ? 5 : 10,
                        location: this.deviceLocation?.country || 'Unknown',
                        device: this.authdata.metadata.device.os,
                        email: recipient,

                        // Additional placeholders for login
                        ...(isLogin && {
                            login_time: new Date().toISOString(),
                            ip_address: this.clientIP,
                            location_info: this.deviceLocation?.country || 'Unknown',
                            device_info: `${this.authdata.metadata.device.browser} on ${this.authdata.metadata.device.os}`,
                            user_email: this.account?.email || 'Unknown',
                            login_url: `${process.env.APP_URL}/login`,
                            help_url: `${process.env.APP_URL}/help`,
                            privacy_url: `${process.env.APP_URL}/privacy`,
                            security_url: `${process.env.APP_URL}/account/security`,
                            unsubscribe_url: `${process.env.APP_URL}/unsubscribe`,
                        })
                    },
                    recipient: recipient
                }
            },
            priority: 'high'
        };

        await this.sqsservice.sendMessage(this.SQS_QUEUE_URL, sqsBody);
    }

    private async convertTempToRealAccount(): Promise<IAccount> {
        if (!this.tempAccount) throw new HttpError('Temp account not found', 500);

        this.logger.debug('Converting temp account to real account', {
            tempId: this.tempAccount.tempId
        });

        const accountData = {
            email: this.tempAccount.email,
            phone: this.tempAccount.phone,
            profile: this.tempAccount.profile || {},
            accountStatus: {
                status: 'active',
                verificationLevel: 'basic',
                registrationDate: new Date(),
                accountType: 'standard',
                membershipTier: 'basic',
                isComplete: true,
                lastActive: new Date(),
                statusHistory: [{
                    status: 'active',
                    reason: 'Account created',
                    timestamp: new Date(),
                    changedBy: 'system'
                }]
            },
            security: {
                failedLoginAttempts: 0,
                lockedUntil: undefined,
                loginHistory: [],
                trustedDevices: [],
                passwordResetTokens: [],
                mfaBackupCodes: []
            },
            preferences: {
                language: this.tempAccount.profile?.language || 'en',
                timezone: this.tempAccount.profile?.timezone || 'UTC',
                notifications: {
                    email: this.tempAccount.complianceData?.marketingConsent?.email || true,
                    sms: this.tempAccount.complianceData?.marketingConsent?.sms || false,
                    push: this.tempAccount.complianceData?.marketingConsent?.push || false
                }
            },
            registrationContext: this.tempAccount.registrationContext,
            complianceData: this.tempAccount.complianceData,
            lastLogin: undefined,
            loginCount: 0,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const newAccount = new Account(accountData);
        await newAccount.save();

        // Clean up temp account
        this.tempAccount.status = 'converted';
        this.tempAccount.addAuditLog(
            'converted_to_account',
            `Temp account converted to real account: ${newAccount._id}`,
            this.clientIP,
            this.authdata.metadata.device.userAgent
        );
        await this.tempAccount.save();

        this.logger.info('Temp account converted to real account', {
            tempId: this.tempAccount.tempId,
            accountId: newAccount._id
        });

        return newAccount;
    }

    private checkAccountStatus(): void {
        if (!this.account) return;

        // Check if account is locked
        if (this.account.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
            const minutesRemaining = Math.ceil((this.account.security.lockedUntil.getTime() - Date.now()) / (1000 * 60));
            throw new HttpError(`Account is locked. Try again in ${minutesRemaining} minutes.`, 423);
        }

        // Check account status
        if (this.account.accountStatus.status === 'suspended') {
            throw new HttpError('Account is suspended. Please contact support.', 403);
        }

        // Check device and location
        this.checkDeviceAndLocation();
    }

    private checkDeviceAndLocation(): void {
        if (!this.account || !this.project) return;

        const deviceId = this.authdata.metadata.device.deviceId;
        const trustedDevicesEnabled = this.project.settings?.mfa.trustedDevices.enabled;

        if (deviceId && trustedDevicesEnabled) {
            if (!this.account.security.trustedDevices.includes(deviceId)) {
                this.isNewDevice = true;
            }
        }

        this.deviceLocation = { country: 'Unknown' };
    }

    private async createSession(accessToken: string, refreshToken: string): Promise<void> {
        if (!this.account) throw new HttpError('Account not found', 404);

        // Check concurrent session limits
        const activeSessions = await Session.countDocuments({
            accountId: this.account._id,
            isActive: true,
            status: 'active'
        });

        const maxConcurrentSessions = 3;

        if (activeSessions >= maxConcurrentSessions) {
            const oldestSession = await Session.findOne({
                accountId: this.account._id,
                isActive: true,
                status: 'active'
            }).sort({ lastActivityAt: 1 });

            if (oldestSession) {
                oldestSession.terminate('max_sessions', 'system');
                await oldestSession.save();
            }
        }

        const sessionDuration = this.project?.settings?.sessionManagement?.maxSessionDurationHours || 8;
        const idleTimeout = this.project?.settings?.sessionManagement?.idleTimeoutMinutes || 15;

        this.session = new Session({
            accountId: this.account._id,
            deviceInfo: {
                deviceId: this.authdata.metadata.device.deviceId,
                deviceType: this.authdata.metadata.device.type || 'unknown',
                os: this.authdata.metadata.device.os,
                browser: this.authdata.metadata.device.browser,
                userAgent: this.authdata.metadata.device.userAgent,
            },
            location: {
                ip: this.clientIP,
                country: this.deviceLocation?.country,
            },
            securityContext: {
                riskScore: this.calculateRiskScore(),
                riskFactors: [],
                isTrusted: !this.isNewDevice,
                requiresMfa: this.project?.settings?.mfa.enabled || false,
                mfaCompleted: true,
                authenticationMethod: 'combined_auth',
                strongAuthentication: true
            },
            accessToken,
            refreshTokens: [{
                token: refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                isRevoked: false,
                family: `fam_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
            }],
            isPersistent: this.requestData.rememberMe || false,
            expiresAt: this.requestData.rememberMe
                ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
                : new Date(Date.now() + sessionDuration * 60 * 60 * 1000),
            idleTimeoutAt: new Date(Date.now() + idleTimeout * 60 * 1000),
            metadata: {
                loginMethod: 'combined_auth',
                browserInfo: {
                    userAgent: this.authdata.metadata.device.userAgent,
                    browser: this.authdata.metadata.device.browser,
                    os: this.authdata.metadata.device.os
                },
                newDevice: this.isNewDevice
            }
        });

        this.session.addActivity({
            action: 'combined_auth_login',
            endpoint: this.event.path,
            method: this.event.httpMethod,
            statusCode: 200,
            userAgent: this.authdata.metadata.device.userAgent,
            ip: this.clientIP
        });

        await this.session.save();
    }

    private calculateProfileCompletion(): { isComplete: boolean; percentage: number; missingFields: string[] } {
        if (!this.account) return { isComplete: false, percentage: 0, missingFields: [] };

        const requiredFields = ['firstName', 'lastName', 'email'];
        const optionalFields = ['displayName', 'dateOfBirth', 'phone', 'country'];

        const missingRequired: string[] = [];
        let presentOptional = 0;

        // Check required fields
        requiredFields.forEach(field => {
            if (field === 'email' && !this.account!.email) missingRequired.push(field);
            else if (field === 'firstName' && !this.account!.profile?.firstName) missingRequired.push(field);
            else if (field === 'lastName' && !this.account!.profile?.lastName) missingRequired.push(field);
        });

        // Count optional fields
        if (this.account.profile?.displayName) presentOptional++;
        if (this.account.profile?.dateOfBirth) presentOptional++;
        if (this.account.phone) presentOptional++;

        const isComplete = missingRequired.length === 0;
        const percentage = Math.round(((requiredFields.length - missingRequired.length) / requiredFields.length +
            (presentOptional / optionalFields.length)) * 50);

        return {
            isComplete,
            percentage: Math.min(percentage, 100),
            missingFields: missingRequired
        };
    }

    // ==================== UTILITY METHODS ====================

    private getIdentifier(): string {
        return this.requestData.email || this.requestData.phone || 'unknown';
    }

    private getPrimaryIdentifier(): string {
        return this.requestData.email || this.requestData.phone || '';
    }

    private determineRegistrationMethod(): 'email' | 'phone' {
        if (this.requestData.combinedMethod) {
            return this.requestData.combinedMethod;
        }
        return this.requestData.email ? 'email' : 'phone';
    }

    private determineVerificationMethod(): 'email' | 'sms' {
        // Check if both email and phone are available
        const hasEmail = !!(this.account?.email || this.requestData.email);
        const hasPhone = !!(this.account?.phone || this.requestData.phone);

        // Check project settings for supported methods
        const supportedMethods = this.project?.settings?.mfa?.methods || ['EMAIL'];

        // If combinedMethod is specified, use it if supported
        // if (this.requestData.combinedMethod) {
        //     const methodMapping = { 'email': 'EMAIL', 'phone': 'SMS' };
        //     const projectMethod = methodMapping[this.requestData.combinedMethod];
        //     if (supportedMethods.includes(projectMethod)) {
        //         return this.requestData.combinedMethod === 'phone' ? 'sms' : 'email';
        //     }
        // }

        // Default preference: SMS if phone available and SMS enabled, otherwise email
        if (hasPhone && supportedMethods.includes('SMS')) {
            return 'sms';
        }

        if (hasEmail && supportedMethods.includes('EMAIL')) {
            return 'email';
        }

        // Fallback based on what's available
        if (hasEmail) return 'email';
        if (hasPhone) return 'sms';

        throw new HttpError('No valid verification method available', 400);
    }

    private maskIdentifier(identifier: string): string {
        if (identifier.includes('@')) {
            const [username, domain] = identifier.split('@');
            const maskedUsername = username.length > 2
                ? username.substring(0, 2) + '*'.repeat(username.length - 2)
                : '*'.repeat(username.length);
            return `${maskedUsername}@${domain}`;
        } else {
            const visibleDigits = 4;
            const maskedLength = identifier.length - visibleDigits;
            return maskedLength > 0
                ? identifier.substring(0, 2) + '*'.repeat(maskedLength) + identifier.slice(-2)
                : identifier;
        }
    }

    private calculateRiskScore(): number {
        let score = 0;
        if (this.isNewDevice) score += 20;
        if (!this.account?.security.trustedDevices.length) score += 10;
        return score;
    }

    private generateAccessToken(): string {
        if (!this.account) throw new Error("Account is missing");

        const payload = {
            accountId: this.account._id,
            type: 'access'
        };

        const options: SignOptions = {
            expiresIn: this.JWT_EXPIRES_IN as any
        };

        return jwt.sign(payload, this.JWT_SECRET, options);
    }

    private generateRefreshToken(): string {
        return jwt.sign(
            {
                accountId: this.account!._id,
                type: 'refresh'
            },
            this.REFRESH_TOKEN_SECRET,
            { expiresIn: '7d' }
        );
    }

    private parseJWTExpiration(expiresIn: string): number {
        const unit = expiresIn.slice(-1);
        const value = parseInt(expiresIn.slice(0, -1));

        switch (unit) {
            case 's': return value;
            case 'm': return value * 60;
            case 'h': return value * 60 * 60;
            case 'd': return value * 24 * 60 * 60;
            default: return 24 * 60 * 60;
        }
    }
}

// ==================== LAMBDA HANDLER ====================

const CombinedAuthHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Combined auth handler started');

    // Parse request body
    const parsedBody = parseRequestBody<CombinedAuthRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process combined auth
    const businessHandler = new CombinedAuthBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Combined auth handler completed successfully', {
        authFlow: result.authFlow,
        accountId: result.accountId,
        isNewUser: result.isNewUser
    });

    logger.logBusinessEvent('LAMBDA_SUCCESS', {
        operationType: 'combined_auth',
        authFlow: result.authFlow,
        accountId: result.accountId,
        isNewUser: result.isNewUser
    });

    return SuccessResponse({
        message: result.message,
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(CombinedAuthHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'debug'
});