// import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
// import { connectDB } from '../../utils/dbconnect';
// import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
// import { createLogger } from '../../utils/logger';
// import { parseRequestBody } from '../../utils/requestParser';
// import HttpError from '../../exception/httpError';
// import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
// import bcrypt from 'bcryptjs';
// import { Account, IAccount } from '../../models/account.schema';
// import { TempAccount, ITempAccount } from '../../models/temp_account.schema';
// import { VerificationCode } from '../../models/verification_codes.schema';
// import { Session, ISession } from '../../models/sessions.schema';
// import { SQSService } from '../../utils/lambdaSqs';
// import jwt, { SignOptions } from 'jsonwebtoken';
// import ProjectModel, { IProjectSettings } from '../../models/project.schema';

// // ==================== INTERFACES ====================

// interface CombinedAuthRequest {
//     // Primary identifier - one required
//     email?: string;
//     phone?: string;
//     username?: string;

//     // Password (optional for first-time users)
//     password?: string;

//     // Profile information (required for new registrations)
//     firstName?: string;
//     lastName?: string;
//     displayName?: string;
//     dateOfBirth?: string;
//     gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
//     language?: string;
//     timezone?: string;
//     country?: string;

//     // Device info for security
//     deviceInfo: {
//         deviceType?: 'desktop' | 'mobile' | 'tablet';
//         os: string;
//         browser: string;
//         userAgent: string;
//         fingerprint?: {
//             hash: string;
//             components: Record<string, any>;
//         };
//     };

//     // Registration context (for new users)
//     registrationMethod?: 'email' | 'phone';
//     referralSource?: string;
//     utmSource?: string;
//     utmMedium?: string;
//     utmCampaign?: string;

//     // Compliance (for new registrations)
//     termsAccepted?: boolean;
//     privacyPolicyAccepted?: boolean;
//     termsVersion?: string;
//     privacyVersion?: string;
//     marketingConsent?: {
//         email?: boolean;
//         sms?: boolean;
//         push?: boolean;
//     };
//     gdprConsent?: boolean;

//     // Optional flags
//     rememberMe?: boolean;
//     captchaToken?: string;
//     captchaProvider?: 'recaptcha' | 'hcaptcha' | 'cloudflare';

//     // 2FA/OTP verification
//     otpCode?: string;
//     mfaMethod?: 'sms' | 'email' | 'totp';
//     loginSessionId?: string;
// }

// interface CombinedAuthResponseData {
//     success: boolean;
//     authFlow: 'login_success' | 'registration_pending' | 'profile_completion_required' | 'requires_2fa' | 'account_locked';
//     message: string;

//     // Successful login data
//     accessToken?: string;
//     refreshToken?: string;
//     expiresIn?: number;
//     sessionId?: string;

//     // Registration/profile completion data
//     tempId?: string;
//     profileCompletionToken?: string;
//     nextStep?: {
//         action: 'verify_email' | 'verify_phone' | 'complete_profile';
//         identifier?: string;
//         expiresIn?: number;
//         requiredFields?: string[];
//     };

//     // 2FA data
//     loginSessionId?: string;
//     mfaRequired?: {
//         methods: Array<'sms' | 'email' | 'totp'>;
//         preferredMethod: 'sms' | 'email' | 'totp';
//         maskedContact?: string;
//         expiresIn: number;
//     };

//     // Account info
//     accountId?: string;
//     profile?: {
//         firstName?: string;
//         lastName?: string;
//         displayName?: string;
//         avatar?: string;
//         isComplete?: boolean;
//         completionPercentage?: number;
//     };

//     // Security/status info
//     lastLogin?: Date;
//     newDevice?: boolean;
//     securityAlerts?: string[];
//     verificationRequired?: {
//         email: boolean;
//         phone: boolean;
//     };
//     accountCreated?: boolean;
//     isNewUser?: boolean;
// }

// // ==================== BUSINESS HANDLER CLASS ====================

// class CombinedAuthBusinessHandler {
//     private requestData: CombinedAuthRequest;
//     private event: APIGatewayProxyEvent;
//     private logger: ReturnType<typeof createLogger>;
//     private sqsservice: SQSService;

//     // Environment variables
//     private readonly SQS_QUEUE_URL: string;
//     private readonly JWT_SECRET: string;
//     private readonly JWT_EXPIRES_IN: string;
//     private readonly REFRESH_TOKEN_SECRET: string;

//     // Data holders
//     private account?: IAccount;
//     private tempAccount?: ITempAccount;
//     private project?: IProjectSettings;
//     private session?: ISession;
//     private clientIP: string = '';
//     private deviceLocation?: any;
//     private loginSessionId?: string;
//     private isNewDevice: boolean = false;
//     private securityAlerts: string[] = [];
//     private authFlow: 'login' | 'register' | 'profile_completion' | '2fa_verification' = 'login';

//     constructor(event: APIGatewayProxyEvent, body: CombinedAuthRequest) {
//         const requestId = event.requestContext?.requestId || 'unknown';
//         this.event = event;
//         this.requestData = body;
//         this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

//         // Initialize services
//         this.sqsservice = new SQSService();

//         // Get environment variables
//         this.SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';
//         this.JWT_SECRET = process.env.JWT_SECRET || '';
//         this.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
//         this.REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || '';

//         this.logger = createLogger('auth-service', requestId);

//         this.logger.appendPersistentKeys({
//             userAgent: event.headers?.['User-Agent'],
//             sourceIP: this.clientIP,
//             identifier: this.getIdentifier(),
//             functionName: 'combined-auth'
//         });
//     }

//     /**
//      * Main processing method
//      */
//     async processRequest(): Promise<CombinedAuthResponseData> {
//         this.logger.info('Starting combined auth process');

//         // Step 1: Basic validation
//         this.validateBasicRequest();

//         // Step 2: Load project configuration
//         await this.loadProjectConfiguration();

//         // Step 3: Determine auth flow
//         await this.determineAuthFlow();

//         // Step 4: Process based on determined flow
//         switch (this.authFlow) {
//             case 'login':
//                 return await this.handleExistingUserLogin();
//             case 'register':
//                 return await this.handleNewUserRegistration();
//             case 'profile_completion':
//                 return await this.handleProfileCompletion();
//             case '2fa_verification':
//                 return await this.handle2FAVerification();
//             default:
//                 throw new HttpError('Invalid auth flow determined', 500);
//         }
//     }

//     /**
//      * Step 1: Basic validation
//      */
//     private validateBasicRequest(): void {
//         this.logger.debug('Validating basic request data');

//         // At least one identifier required
//         if (!this.requestData.email && !this.requestData.phone && !this.requestData.username) {
//             throw new HttpError('Email, phone, or username is required', 400);
//         }

//         // Device info validation
//         if (!this.requestData.deviceInfo?.os || !this.requestData.deviceInfo?.browser) {
//             throw new HttpError('Device information is required for security purposes', 400);
//         }

//         this.logger.debug('Basic request validation completed');
//     }

//     /**
//      * Step 2: Load project configuration
//      */
//     private async loadProjectConfiguration(): Promise<void> {
//         this.logger.debug('Loading project configuration');

//         const project = await ProjectModel.findOne({ category: "AUTH" });

//         if (!project) {
//             this.logger.error('No project configuration found in database');
//             throw new HttpError('Project configuration not found. Please contact support.', 500);
//         }

//         this.project = project;
//     }

//     /**
//      * Step 3: Determine auth flow based on user existence and request data
//      */
//     private async determineAuthFlow(): Promise<void> {
//         this.logger.debug('Determining auth flow');

//         // Check for 2FA verification step first
//         if (this.requestData.loginSessionId && this.requestData.otpCode) {
//             this.authFlow = '2fa_verification';
//             this.logger.debug('Auth flow determined: 2FA verification');
//             return;
//         }

//         // Build search conditions
//         const conditions: any[] = [];
//         if (this.requestData.email) {
//             conditions.push({ email: this.requestData.email.toLowerCase() });
//         }
//         if (this.requestData.phone) {
//             conditions.push({ phone: this.requestData.phone });
//         }
//         if (this.requestData.username) {
//             conditions.push({ username: this.requestData.username.toLowerCase() });
//         }

//         // Look for existing account
//         const existingAccount = await Account.findOne({
//             $or: conditions,
//             accountStatus: { $ne: 'deactivated' }
//         });

//         if (existingAccount) {
//             this.account = existingAccount;
//             this.authFlow = 'login';
//             this.logger.debug('Auth flow determined: Existing user login', {
//                 accountId: this.account._id,
//                 accountStatus: this.account.accountStatus
//             });
//             return;
//         }

//         // Look for temp account (profile completion scenario)
//         await TempAccount.cleanupExpired();
//         const existingTempAccount = await TempAccount.findOne({
//             $or: conditions,
//             status: { $in: ['verified', 'partial'] }, // Only verified temp accounts can complete profile
//             expiresAt: { $gt: new Date() }
//         });

//         if (existingTempAccount && existingTempAccount.status === 'verified') {
//             this.tempAccount = existingTempAccount;
//             this.authFlow = 'profile_completion';
//             this.logger.debug('Auth flow determined: Profile completion', {
//                 tempId: this.tempAccount.tempId
//             });
//             return;
//         }

//         // No existing user found - new registration
//         this.authFlow = 'register';
//         this.logger.debug('Auth flow determined: New user registration');
//     }

//     /**
//      * Handle existing user login
//      */
//     private async handleExistingUserLogin(): Promise<CombinedAuthResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         this.logger.debug('Handling existing user login');

//         // Check account status
//         this.checkAccountStatus();

//         // Check if password is required
//         const accountHasPassword = !!this.account.password;
//         const userProvidedPassword = !!this.requestData.password;
//         const project2FAEnabled = this.project?.settings?.mfa.enabled;

//         // Password validation for accounts that have passwords
//         if (accountHasPassword) {
//             if (!userProvidedPassword) {
//                 throw new HttpError('Password is required for this account', 400, 'PASSWORD_REQUIRED');
//             }

//             const isValidPassword = await bcrypt.compare(this.requestData.password!, this.account.password!);
//             if (!isValidPassword) {
//                 await this.handleFailedLogin();
//                 throw new HttpError('Invalid credentials', 401);
//             }

//             // Reset failed attempts on successful password verification
//             this.account.security.failedLoginAttempts = 0;
//             this.account.security.lockedUntil = undefined;
//         }

//         // Check if 2FA is required
//         if (project2FAEnabled && this.hasAvailable2FAMethods()) {
//             return await this.initiate2FA();
//         }

//         // Complete login directly
//         return await this.completeLogin();
//     }

//     /**
//      * Handle new user registration
//      */
//     private async handleNewUserRegistration(): Promise<CombinedAuthResponseData> {
//         this.logger.debug('Handling new user registration');

//         // Validate registration data
//         this.validateRegistrationData();

//         // Check for conflicts with existing accounts/temp accounts
//         await this.checkRegistrationConflicts();

//         // Perform security checks
//         await this.performSecurityChecks();

//         // Hash password if provided
//         let hashedPassword: string | undefined;
//         if (this.requestData.password) {
//             hashedPassword = await bcrypt.hash(this.requestData.password, 12);
//         }

//         // Create temp account
//         await this.createTempAccount(hashedPassword);

//         // Send verification
//         await this.sendVerificationCode();

//         return {
//             success: true,
//             authFlow: 'registration_pending',
//             message: 'Registration initiated successfully. Please verify your account to continue.',
//             tempId: this.tempAccount!.tempId,
//             nextStep: {
//                 action: this.determineRegistrationMethod() === 'email' ? 'verify_email' : 'verify_phone',
//                 identifier: this.maskIdentifier(this.getPrimaryIdentifier()),
//                 expiresIn: Math.floor((this.tempAccount!.expiresAt.getTime() - Date.now()) / 1000)
//             },
//             verificationRequired: {
//                 email: this.tempAccount!.verificationRequirements.emailVerification.required,
//                 phone: this.tempAccount!.verificationRequirements.phoneVerification.required
//             },
//             accountCreated: false,
//             isNewUser: true
//         };
//     }

//     /**
//      * Handle profile completion for verified temp accounts
//      */
//     private async handleProfileCompletion(): Promise<CombinedAuthResponseData> {
//         if (!this.tempAccount) throw new HttpError('Temp account not found', 404);

//         this.logger.debug('Handling profile completion', {
//             tempId: this.tempAccount.tempId
//         });

//         // Validate profile completion data
//         this.validateProfileCompletionData();

//         // Update temp account with additional profile data
//         if (this.requestData.firstName) this.tempAccount.profile.firstName = this.requestData.firstName;
//         if (this.requestData.lastName) this.tempAccount.profile.lastName = this.requestData.lastName;
//         if (this.requestData.displayName) this.tempAccount.profile.displayName = this.requestData.displayName;
//         if (this.requestData.dateOfBirth) this.tempAccount.profile.dateOfBirth = new Date(this.requestData.dateOfBirth);
//         if (this.requestData.gender) this.tempAccount.profile.gender = this.requestData.gender;
//         if (this.requestData.country) this.tempAccount.profile.country = this.requestData.country;

//         // Hash password if provided
//         if (this.requestData.password && !this.tempAccount.password) {
//             this.tempAccount.password = await bcrypt.hash(this.requestData.password, 12);
//         }

//         // Update compliance data if provided
//         if (this.requestData.termsAccepted !== undefined) {
//             this.tempAccount.complianceData.termsAccepted.accepted = this.requestData.termsAccepted;
//             this.tempAccount.complianceData.termsAccepted.version = this.requestData.termsVersion || '1.0';
//             this.tempAccount.complianceData.termsAccepted.acceptedAt = new Date();
//         }

//         if (this.requestData.privacyPolicyAccepted !== undefined) {
//             this.tempAccount.complianceData.privacyPolicyAccepted.accepted = this.requestData.privacyPolicyAccepted;
//             this.tempAccount.complianceData.privacyPolicyAccepted.version = this.requestData.privacyVersion || '1.0';
//             this.tempAccount.complianceData.privacyPolicyAccepted.acceptedAt = new Date();
//         }

//         // Mark as complete and convert to real account
//         this.tempAccount.status = 'completed';
//         this.tempAccount.metadata.hasCompleteProfile = true;

//         this.tempAccount.addAuditLog(
//             'profile_completed',
//             'User completed profile information',
//             this.clientIP,
//             this.requestData.deviceInfo.userAgent
//         );

//         await this.tempAccount.save();

//         // Convert temp account to real account
//         const newAccount = await this.convertTempToRealAccount();
//         this.account = newAccount;

//         // Check if 2FA is required
//         if (this.project?.settings?.mfa.enabled && this.hasAvailable2FAMethods()) {
//             return await this.initiate2FA();
//         }

//         // Complete login directly
//         return await this.completeLogin(true); // true indicates new account
//     }

//     /**
//      * Handle 2FA verification
//      */
//     private async handle2FAVerification(): Promise<CombinedAuthResponseData> {
//         this.logger.debug('Handling 2FA verification step');

//         const conditions: any[] = [];

//         if (this.requestData.email) {
//             conditions.push({ email: this.requestData.email.toLowerCase() });
//         }
//         if (this.requestData.phone) {
//             conditions.push({ phone: this.requestData.phone });
//         }
//         if (this.requestData.username) {
//             conditions.push({ username: this.requestData.username.toLowerCase() });
//         }

//         const accountData = await Account.findOne({
//             $or: conditions,
//             accountStatus: { $ne: 'deactivated' }
//         });

//         if (!accountData) throw new HttpError('Account not found for 2FA verification', 404);
//         this.account = accountData;

//         // Verify login session and OTP
//         const verificationCode = await VerificationCode.findOne({
//             'context.metadata.loginSessionId': this.requestData.loginSessionId,
//             type: 'mfa',
//             status: "active",
//             expiresAt: { $gt: new Date() }
//         });

//         if (!verificationCode) {
//             throw new HttpError('Invalid or expired login session. Please start login again.', 404);
//         }

//         // Verify OTP code
//         const isValidOTP = verificationCode.verify(this.requestData.otpCode!, {});

//         if (!isValidOTP) {
//             await verificationCode.save();
//             this.logger.warn('Invalid 2FA code provided', {
//                 accountId: this.account._id,
//                 remainingAttempts: verificationCode.remainingAttempts
//             });
//             throw new HttpError(
//                 `Invalid 2FA code. ${verificationCode.remainingAttempts} attempts remaining.`,
//                 400
//             );
//         }

//         // 2FA successful
//         verificationCode.isUsed = true;
//         verificationCode.usedAt = new Date();
//         await verificationCode.save();

//         return await this.completeLogin();
//     }

//     /**
//      * Complete successful login/registration
//      */
//     private async completeLogin(isNewAccount: boolean = false): Promise<CombinedAuthResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         this.logger.debug('Completing successful login', { isNewAccount });

//         // Generate tokens
//         const accessToken = this.generateAccessToken();
//         const refreshToken = this.generateRefreshToken();

//         // Create session
//         await this.createSession(accessToken, refreshToken);

//         // Update account login info
//         this.account.lastLogin = new Date();
//         this.account.loginCount += 1;

//         // Add login history
//         this.account.security.loginHistory.push({
//             timestamp: new Date(),
//             ip: this.clientIP,
//             userAgent: this.requestData.deviceInfo.userAgent,
//             deviceId: this.requestData.deviceInfo.fingerprint?.hash,
//             success: true,
//             location: this.deviceLocation
//         });

//         // Manage trusted devices
//         if (this.isNewDevice && this.requestData.deviceInfo.fingerprint?.hash) {
//             this.account.security.trustedDevices.push(this.requestData.deviceInfo.fingerprint.hash);
//             if (this.account.security.trustedDevices.length > 10) {
//                 this.account.security.trustedDevices = this.account.security.trustedDevices.slice(-10);
//             }
//         }

//         await this.account.save();

//         // Calculate profile completion
//         const profileCompletion = this.calculateProfileCompletion();

//         this.logger.info('Login completed successfully', {
//             accountId: this.account._id,
//             sessionId: this.session?.sessionId,
//             isNewAccount,
//             profileCompletion: profileCompletion.percentage
//         });

//         return {
//             success: true,
//             authFlow: 'login_success',
//             message: isNewAccount ? 'Account created and logged in successfully' : 'Login successful',
//             accessToken,
//             refreshToken,
//             expiresIn: this.parseJWTExpiration(this.JWT_EXPIRES_IN),
//             sessionId: this.session?.sessionId,
//             accountId: String(this.account._id),
//             profile: {
//                 ...this.account.profile,
//                 isComplete: profileCompletion.isComplete,
//                 completionPercentage: profileCompletion.percentage
//             },
//             lastLogin: this.account.lastLogin,
//             newDevice: this.isNewDevice,
//             securityAlerts: this.securityAlerts,
//             accountCreated: isNewAccount,
//             isNewUser: isNewAccount
//         };
//     }

//     // ==================== HELPER METHODS ====================

//     private validateRegistrationData(): void {
//         // Basic registration requirements
//         if (!this.requestData.email && !this.requestData.phone) {
//             throw new HttpError('Email or phone is required for registration', 400);
//         }

//         // Email validation
//         if (this.requestData.email && !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(this.requestData.email)) {
//             throw new HttpError('Invalid email format', 400);
//         }

//         // Phone validation
//         if (this.requestData.phone && !/^\+[1-9]\d{1,14}$/.test(this.requestData.phone)) {
//             throw new HttpError('Invalid phone format. Use E.164 format', 400);
//         }

//         // Password validation if provided
//         if (this.requestData.password && this.requestData.password.length < 8) {
//             throw new HttpError('Password must be at least 8 characters long', 400);
//         }
//     }

//     private validateProfileCompletionData(): void {
//         if (!this.requestData.firstName || !this.requestData.lastName) {
//             throw new HttpError('First name and last name are required to complete profile', 400);
//         }

//         if (!this.requestData.termsAccepted || !this.requestData.privacyPolicyAccepted) {
//             throw new HttpError('You must accept the terms and privacy policy to complete registration', 400);
//         }
//     }

//     private async checkRegistrationConflicts(): Promise<void> {
//         const conditions: any[] = [];

//         if (this.requestData.email) {
//             conditions.push({ email: this.requestData.email.toLowerCase() });
//         }
//         if (this.requestData.phone) {
//             conditions.push({ phone: this.requestData.phone });
//         }

//         // Check existing accounts
//         const existingAccount = await Account.findOne({
//             $or: conditions,
//             accountStatus: { $ne: 'deactivated' }
//         });

//         if (existingAccount) {
//             throw new HttpError('An account with this email or phone already exists', 409);
//         }

//         // Check temp accounts
//         const existingTempAccount = await TempAccount.findOne({
//             $or: conditions,
//             status: { $in: ['active', 'verified'] },
//             expiresAt: { $gt: new Date() }
//         });

//         if (existingTempAccount) {
//             throw new HttpError('A registration with this email or phone is already in progress', 409);
//         }
//     }

//     private async performSecurityChecks(): Promise<void> {
//         // Basic security check implementation
//         // In production, integrate with fraud detection services
//         this.deviceLocation = { country: this.requestData.country || 'Unknown' };
//     }

//     private async createTempAccount(hashedPassword?: string): Promise<void> {
//         const registrationMethod = this.determineRegistrationMethod();

//         const tempAccountData = {
//             email: this.requestData.email?.toLowerCase(),
//             phone: this.requestData.phone,
//             username: this.requestData.username?.toLowerCase(),
//             password: hashedPassword,
//             profile: {
//                 firstName: this.requestData.firstName,
//                 lastName: this.requestData.lastName,
//                 displayName: this.requestData.displayName,
//                 dateOfBirth: this.requestData.dateOfBirth ? new Date(this.requestData.dateOfBirth) : undefined,
//                 gender: this.requestData.gender,
//                 language: this.requestData.language || 'en',
//                 timezone: this.requestData.timezone || 'UTC',
//                 country: this.requestData.country
//             },
//             registrationContext: {
//                 registrationMethod: registrationMethod as 'email' | 'phone',
//                 referralSource: this.requestData.referralSource,
//                 utmSource: this.requestData.utmSource,
//                 utmMedium: this.requestData.utmMedium,
//                 utmCampaign: this.requestData.utmCampaign
//             },
//             verificationRequirements: {
//                 emailVerification: {
//                     required: !!this.requestData.email,
//                     completed: false,
//                     attempts: 0
//                 },
//                 phoneVerification: {
//                     required: !!this.requestData.phone && registrationMethod === 'phone',
//                     completed: false,
//                     attempts: 0
//                 },
//                 captchaVerification: {
//                     required: !!this.requestData.captchaToken,
//                     completed: !!this.requestData.captchaToken,
//                     provider: this.requestData.captchaProvider || 'recaptcha'
//                 }
//             },
//             deviceInfo: {
//                 deviceType: this.requestData.deviceInfo.deviceType || 'unknown',
//                 os: this.requestData.deviceInfo.os,
//                 browser: this.requestData.deviceInfo.browser,
//                 userAgent: this.requestData.deviceInfo.userAgent,
//                 ip: this.clientIP,
//                 location: this.deviceLocation,
//                 fingerprint: this.requestData.deviceInfo.fingerprint
//             },
//             securityCheck: {
//                 riskScore: 0,
//                 riskFactors: [],
//                 isHighRisk: false,
//                 checks: {
//                     emailReputation: true,
//                     phoneReputation: true,
//                     ipReputation: true,
//                     deviceReputation: true
//                 }
//             },
//             complianceData: {
//                 termsAccepted: {
//                     accepted: this.requestData.termsAccepted || false,
//                     version: this.requestData.termsVersion || '1.0',
//                     acceptedAt: this.requestData.termsAccepted ? new Date() : undefined,
//                     ip: this.clientIP
//                 },
//                 privacyPolicyAccepted: {
//                     accepted: this.requestData.privacyPolicyAccepted || false,
//                     version: this.requestData.privacyVersion || '1.0',
//                     acceptedAt: this.requestData.privacyPolicyAccepted ? new Date() : undefined,
//                     ip: this.clientIP
//                 },
//                 marketingConsent: {
//                     email: this.requestData.marketingConsent?.email || false,
//                     sms: this.requestData.marketingConsent?.sms || false,
//                     push: this.requestData.marketingConsent?.push || false
//                 }
//             },
//             status: 'active',
//             lastActivity: new Date()
//         };

//         this.tempAccount = new TempAccount(tempAccountData);
//         await this.tempAccount.save();

//         this.logger.debug('Temp account created', { tempId: this.tempAccount.tempId });
//     }

//     private async sendVerificationCode(): Promise<void> {
//         if (!this.tempAccount) return;

//         const registrationMethod = this.determineRegistrationMethod();
//         const otpCode = VerificationCode.generateCode(6);

//         const verificationCode = new VerificationCode({
//             accountId: undefined,
//             code: otpCode,
//             hashedCode: VerificationCode.hashCode(otpCode),
//             type: registrationMethod === 'email' ? 'email_verification' : 'phone_verification',
//             purpose: `${registrationMethod.charAt(0).toUpperCase() + registrationMethod.slice(1)} verification for registration`,
//             method: registrationMethod,
//             deliveryInfo: {
//                 channel: registrationMethod,
//                 provider: registrationMethod === 'email' ? 'ses' : 'twilio',
//                 recipient: registrationMethod === 'email' ? this.requestData.email : this.requestData.phone,
//                 deliveryStatus: 'pending'
//             },
//             maxAttempts: 3,
//             remainingAttempts: 3,
//             context: {
//                 initiatedBy: 'user',
//                 triggerEvent: 'combined_auth_registration',
//                 metadata: {
//                     tempAccountId: this.tempAccount.tempId,
//                     registrationMethod: registrationMethod
//                 },
//                 sessionId: this.event.requestContext?.requestId,
//                 ip: this.clientIP,
//                 userAgent: this.requestData.deviceInfo.userAgent
//             },
//             security: {
//                 requiresSecureChannel: true,
//                 preventBruteForce: true,
//                 logAllAttempts: true,
//                 riskScore: 0
//             }
//         });

//         await verificationCode.save();

//         // Send via SQS
//         const sqsBody = {
//             notificationType: registrationMethod === 'email' ? 'email_verification' : 'sms_verification',
//             channels: [registrationMethod],
//             content: registrationMethod === 'email' ? {
//                 email: {
//                     subject: 'Verify Your Email Address',
//                     template: 'account-verification',
//                     data: {
//                         email: this.requestData.email,
//                         name: this.requestData.firstName || 'User',
//                         otp: otpCode,
//                         expiryMinutes: 10
//                     },
//                     recipient: this.requestData.email
//                 }
//             } : {
//                 sms: {
//                     message: `Your verification code is: ${otpCode}. This code expires in 10 minutes.`,
//                     recipient: this.requestData.phone
//                 }
//             },
//             priority: 'high'
//         };

//         await this.sqsservice.sendMessage(this.SQS_QUEUE_URL, sqsBody);

//         // Update temp account
//         if (registrationMethod === 'email') {
//             this.tempAccount.verificationRequirements.emailVerification.codeId = verificationCode.codeId;
//         } else {
//             this.tempAccount.verificationRequirements.phoneVerification.codeId = verificationCode.codeId;
//         }

//         await this.tempAccount.save();
//     }

//     private async convertTempToRealAccount(): Promise<IAccount> {
//         if (!this.tempAccount) throw new HttpError('Temp account not found', 500);

//         this.logger.debug('Converting temp account to real account', {
//             tempId: this.tempAccount.tempId
//         });

//         const accountData = {
//             email: this.tempAccount.email,
//             phone: this.tempAccount.phone,
//             username: this.tempAccount.username,
//             password: this.tempAccount.password,
//             profile: this.tempAccount.profile,
//             accountStatus: {
//                 status: 'active',
//                 statusReason: 'Account created via combined auth',
//                 lastStatusChange: new Date(),
//                 statusHistory: [{
//                     status: 'active',
//                     reason: 'Account created',
//                     timestamp: new Date(),
//                     changedBy: 'system'
//                 }]
//             },
//             security: {
//                 failedLoginAttempts: 0,
//                 lockedUntil: undefined,
//                 loginHistory: [],
//                 trustedDevices: [],
//                 passwordResetTokens: [],
//                 mfaBackupCodes: []
//             },
//             preferences: {
//                 language: this.tempAccount.profile.language || 'en',
//                 timezone: this.tempAccount.profile.timezone || 'UTC',
//                 notifications: {
//                     email: this.tempAccount.complianceData.marketingConsent.email,
//                     sms: this.tempAccount.complianceData.marketingConsent.sms,
//                     push: this.tempAccount.complianceData.marketingConsent.push
//                 }
//             },
//             registrationContext: this.tempAccount.registrationContext,
//             complianceData: this.tempAccount.complianceData,
//             lastLogin: undefined,
//             loginCount: 0,
//             createdAt: new Date(),
//             updatedAt: new Date()
//         };

//         const newAccount = new Account(accountData);
//         await newAccount.save();

//         // Clean up temp account
//         this.tempAccount.status = 'converted';
//         this.tempAccount.addAuditLog(
//             'converted_to_account',
//             `Temp account converted to real account: ${newAccount._id}`,
//             this.clientIP,
//             this.requestData.deviceInfo.userAgent
//         );
//         await this.tempAccount.save();

//         this.logger.info('Temp account converted to real account', {
//             tempId: this.tempAccount.tempId,
//             accountId: newAccount._id
//         });

//         return newAccount;
//     }

//     private checkAccountStatus(): void {
//         if (!this.account) return;

//         // Check if account is locked
//         if (this.account.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
//             const minutesRemaining = Math.ceil((this.account.security.lockedUntil.getTime() - Date.now()) / (1000 * 60));
//             throw new HttpError(`Account is locked. Try again in ${minutesRemaining} minutes.`, 423);
//         }

//         // Check account status
//         if (this.account.accountStatus.status === 'suspended') {
//             throw new HttpError('Account is suspended. Please contact support.', 403);
//         }

//         if (this.account.accountStatus.status === 'pending_verification') {
//             throw new HttpError('Account email verification is required. Please check your email.', 403);
//         }

//         // Check device and location
//         this.checkDeviceAndLocation();
//     }

//     private checkDeviceAndLocation(): void {
//         if (!this.account || !this.project) return;

//         const deviceId = this.requestData.deviceInfo.fingerprint?.hash;
//         const trustedDevicesEnabled = this.project.settings?.mfa.trustedDevices.enabled;

//         if (deviceId && trustedDevicesEnabled) {
//             if (!this.account.security.trustedDevices.includes(deviceId)) {
//                 this.isNewDevice = true;
//                 this.securityAlerts.push('New device detected');
//             }
//         }

//         this.deviceLocation = { country: 'Unknown' };
//     }

//     private hasAvailable2FAMethods(): boolean {
//         if (!this.account || !this.project) return false;

//         const projectMethods = this.project.settings?.mfa.methods || [];
//         const hasSMS = projectMethods.includes('SMS') && !!this.account.phone;
//         const hasEmail = projectMethods.includes('EMAIL') && !!this.account.email;
//         const hasTOTP = projectMethods.includes('TOTP');

//         return hasSMS || hasEmail || hasTOTP;
//     }

//     private async initiate2FA(): Promise<CombinedAuthResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         this.logger.debug('Initiating 2FA process');

//         this.loginSessionId = `login_${Date.now()}_${Math.random().toString(36).substring(2)}`;

//         const availableMethods = this.getAvailable2FAMethods();
//         const preferredMethod = this.getPreferred2FAMethod(availableMethods);

//         const otpCode = VerificationCode.generateCode(6);

//         const verificationCode = new VerificationCode({
//             accountId: this.account._id,
//             code: otpCode,
//             hashedCode: VerificationCode.hashCode(otpCode),
//             type: 'mfa',
//             purpose: 'MFA verification for combined auth login',
//             method: preferredMethod,
//             deliveryInfo: {
//                 channel: preferredMethod === 'sms' ? 'sms' : 'email',
//                 provider: preferredMethod === 'sms' ? 'twilio' : 'ses',
//                 recipient: preferredMethod === 'sms' ? this.account.phone : this.account.email,
//                 deliveryStatus: 'pending'
//             },
//             maxAttempts: 3,
//             remainingAttempts: 3,
//             expiresAt: new Date(Date.now() + 5 * 60 * 1000),
//             context: {
//                 initiatedBy: 'user',
//                 triggerEvent: 'combined_auth_2fa',
//                 metadata: {
//                     accountId: String(this.account._id),
//                     loginSessionId: this.loginSessionId,
//                     mfaMethod: preferredMethod
//                 },
//                 sessionId: this.event.requestContext?.requestId,
//                 ip: this.clientIP,
//                 userAgent: this.requestData.deviceInfo.userAgent
//             },
//             security: {
//                 requiresSecureChannel: true,
//                 preventBruteForce: true,
//                 logAllAttempts: true,
//                 riskScore: this.calculateRiskScore()
//             }
//         });

//         await verificationCode.save();

//         // Send 2FA code
//         await this.send2FAOTP(preferredMethod, otpCode);

//         return {
//             success: true,
//             authFlow: 'requires_2fa',
//             message: '2FA verification required. Please check your device for the verification code.',
//             loginSessionId: this.loginSessionId,
//             mfaRequired: {
//                 methods: availableMethods,
//                 preferredMethod,
//                 maskedContact: this.maskContact(preferredMethod),
//                 expiresIn: 180
//             },
//             accountId: String(this.account._id)
//         };
//     }

//     private getAvailable2FAMethods(): Array<'sms' | 'email' | 'totp'> {
//         if (!this.account || !this.project) return [];

//         const methods: Array<'sms' | 'email' | 'totp'> = [];
//         const projectMethods = this.project.settings?.mfa.methods || [];

//         if (projectMethods.includes('SMS') && this.account.phone) {
//             methods.push('sms');
//         }

//         if (projectMethods.includes('EMAIL') && this.account.email) {
//             methods.push('email');
//         }

//         if (projectMethods.includes('TOTP')) {
//             methods.push('totp');
//         }

//         return methods;
//     }

//     private getPreferred2FAMethod(availableMethods: Array<'sms' | 'email' | 'totp'>): 'sms' | 'email' | 'totp' {
//         if (availableMethods.includes('sms')) return 'sms';
//         if (availableMethods.includes('email')) return 'email';
//         return 'totp';
//     }

//     private async send2FAOTP(method: 'sms' | 'email' | 'totp', otpCode: string): Promise<void> {
//         if (method === 'totp') return;

//         const sqsBody = {
//             notificationType: method === 'sms' ? 'sms_2fa' : 'email_2fa',
//             channels: [method === 'sms' ? 'sms' : 'email'],
//             content: method === 'sms' ? {
//                 sms: {
//                     message: `Your verification code is: ${otpCode}. This code expires in 3 minutes.`,
//                     recipient: this.account!.phone
//                 }
//             } : {
//                 email: {
//                     subject: 'Login Verification Code',
//                     template: 'login-2fa',
//                     data: {
//                         name: this.account!.profile.firstName || 'User',
//                         otp: otpCode,
//                         expiryMinutes: 3,
//                         location: this.deviceLocation?.country || 'Unknown',
//                         device: this.requestData.deviceInfo.os,
//                         email: this.account!.email
//                     },
//                     recipient: this.account!.email
//                 }
//             },
//             priority: 'high'
//         };

//         await this.sqsservice.sendMessage(this.SQS_QUEUE_URL, sqsBody);
//     }

//     private async handleFailedLogin(): Promise<void> {
//         if (!this.account) return;

//         this.account.security.failedLoginAttempts += 1;

//         if (this.account.security.failedLoginAttempts >= 5) {
//             this.account.security.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
//         }

//         this.account.security.loginHistory.push({
//             timestamp: new Date(),
//             ip: this.clientIP,
//             userAgent: this.requestData.deviceInfo.userAgent,
//             deviceId: this.requestData.deviceInfo.fingerprint?.hash,
//             success: false,
//             location: this.deviceLocation
//         });

//         await this.account.save();
//     }

//     private async createSession(accessToken: string, refreshToken: string): Promise<void> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         // Check concurrent session limits
//         const activeSessions = await Session.countDocuments({
//             accountId: this.account._id,
//             isActive: true,
//             status: 'active'
//         });

//         const maxConcurrentSessions = 3;

//         if (activeSessions >= maxConcurrentSessions) {
//             const oldestSession = await Session.findOne({
//                 accountId: this.account._id,
//                 isActive: true,
//                 status: 'active'
//             }).sort({ lastActivityAt: 1 });

//             if (oldestSession) {
//                 oldestSession.terminate('max_sessions', 'system');
//                 await oldestSession.save();
//             }
//         }

//         const sessionDuration = this.project?.settings?.sessionManagement?.maxSessionDurationHours || 8;
//         const idleTimeout = this.project?.settings?.sessionManagement?.idleTimeoutMinutes || 15;

//         this.session = new Session({
//             accountId: this.account._id,
//             deviceInfo: {
//                 deviceId: this.requestData.deviceInfo.fingerprint?.hash,
//                 deviceType: this.requestData.deviceInfo.deviceType || 'unknown',
//                 os: this.requestData.deviceInfo.os,
//                 browser: this.requestData.deviceInfo.browser,
//                 userAgent: this.requestData.deviceInfo.userAgent,
//             },
//             location: {
//                 ip: this.clientIP,
//                 country: this.deviceLocation?.country,
//             },
//             securityContext: {
//                 riskScore: this.calculateRiskScore(),
//                 riskFactors: this.securityAlerts,
//                 isTrusted: !this.isNewDevice,
//                 requiresMfa: this.project?.settings?.mfa.enabled || false,
//                 mfaCompleted: this.project?.settings?.mfa.enabled || false,
//                 authenticationMethod: 'combined_auth',
//                 strongAuthentication: true
//             },
//             accessToken,
//             refreshTokens: [{
//                 token: refreshToken,
//                 expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
//                 isRevoked: false,
//                 family: `fam_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
//             }],
//             isPersistent: this.requestData.rememberMe || false,
//             expiresAt: this.requestData.rememberMe
//                 ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
//                 : new Date(Date.now() + sessionDuration * 60 * 60 * 1000),
//             idleTimeoutAt: new Date(Date.now() + idleTimeout * 60 * 1000),
//             metadata: {
//                 loginMethod: 'combined_auth',
//                 browserInfo: {
//                     userAgent: this.requestData.deviceInfo.userAgent,
//                     browser: this.requestData.deviceInfo.browser,
//                     os: this.requestData.deviceInfo.os
//                 },
//                 newDevice: this.isNewDevice
//             }
//         });

//         this.session.addActivity({
//             action: 'combined_auth_login',
//             endpoint: this.event.path,
//             method: this.event.httpMethod,
//             statusCode: 200,
//             userAgent: this.requestData.deviceInfo.userAgent,
//             ip: this.clientIP
//         });

//         await this.session.save();
//     }

//     private calculateProfileCompletion(): { isComplete: boolean; percentage: number; missingFields: string[] } {
//         if (!this.account) return { isComplete: false, percentage: 0, missingFields: [] };

//         const requiredFields = ['firstName', 'lastName', 'email'];
//         const optionalFields = ['displayName', 'dateOfBirth', 'phone', 'country'];

//         const missingRequired: string[] = [];
//         let presentOptional = 0;

//         // Check required fields
//         requiredFields.forEach(field => {
//             if (field === 'email' && !this.account!.email) missingRequired.push(field);
//             else if (field === 'firstName' && !this.account!.profile?.firstName) missingRequired.push(field);
//             else if (field === 'lastName' && !this.account!.profile?.lastName) missingRequired.push(field);
//         });

//         // Count optional fields
//         if (this.account.profile?.displayName) presentOptional++;
//         if (this.account.profile?.dateOfBirth) presentOptional++;
//         if (this.account.phone) presentOptional++;
//         if (this.account.profile?.country) presentOptional++;

//         const isComplete = missingRequired.length === 0;
//         const percentage = Math.round(((requiredFields.length - missingRequired.length) / requiredFields.length +
//             (presentOptional / optionalFields.length)) * 50);

//         return {
//             isComplete,
//             percentage: Math.min(percentage, 100),
//             missingFields: missingRequired
//         };
//     }

//     // Utility methods
//     private getIdentifier(): string {
//         return this.requestData.email || this.requestData.phone || this.requestData.username || 'unknown';
//     }

//     private getPrimaryIdentifier(): string {
//         return this.requestData.email || this.requestData.phone || this.requestData.username || '';
//     }

//     private determineRegistrationMethod(): 'email' | 'phone' {
//         if (this.requestData.registrationMethod) {
//             return this.requestData.registrationMethod;
//         }
//         return this.requestData.email ? 'email' : 'phone';
//     }

//     private maskIdentifier(identifier: string): string {
//         if (identifier.includes('@')) {
//             const [username, domain] = identifier.split('@');
//             const maskedUsername = username.length > 2
//                 ? username.substring(0, 2) + '*'.repeat(username.length - 2)
//                 : '*'.repeat(username.length);
//             return `${maskedUsername}@${domain}`;
//         } else {
//             const visibleDigits = 4;
//             const maskedLength = identifier.length - visibleDigits;
//             return maskedLength > 0
//                 ? identifier.substring(0, 2) + '*'.repeat(maskedLength) + identifier.slice(-2)
//                 : identifier;
//         }
//     }

//     private maskContact(method: 'sms' | 'email' | 'totp'): string {
//         if (!this.account) return '';

//         if (method === 'sms') {
//             const phone = this.account.phone || '';
//             return phone.length > 4 ? `***${phone.slice(-4)}` : phone;
//         } else if (method === 'email') {
//             const email = this.account.email || '';
//             const [username, domain] = email.split('@');
//             if (username && domain) {
//                 const maskedUsername = username.length > 2
//                     ? username.substring(0, 2) + '*'.repeat(username.length - 2)
//                     : '*'.repeat(username.length);
//                 return `${maskedUsername}@${domain}`;
//             }
//         }
//         return 'Authenticator App';
//     }

//     private calculateRiskScore(): number {
//         let score = 0;
//         if (this.isNewDevice) score += 20;
//         if (!this.account?.security.trustedDevices.length) score += 10;
//         return score;
//     }

//     private generateAccessToken(): string {
//         if (!this.account) throw new Error("Account is missing");

//         const payload = {
//             accountId: this.account._id,
//             type: 'access'
//         };

//         const options: SignOptions = {
//             expiresIn: this.JWT_EXPIRES_IN as any
//         };

//         return jwt.sign(payload, this.JWT_SECRET, options);
//     }

//     private generateRefreshToken(): string {
//         return jwt.sign(
//             {
//                 accountId: this.account!._id,
//                 type: 'refresh'
//             },
//             this.REFRESH_TOKEN_SECRET,
//             { expiresIn: '7d' }
//         );
//     }

//     private parseJWTExpiration(expiresIn: string): number {
//         const unit = expiresIn.slice(-1);
//         const value = parseInt(expiresIn.slice(0, -1));

//         switch (unit) {
//             case 's': return value;
//             case 'm': return value * 60;
//             case 'h': return value * 60 * 60;
//             case 'd': return value * 24 * 60 * 60;
//             default: return 24 * 60 * 60;
//         }
//     }
// }

// // ==================== LAMBDA HANDLER ====================

// const CombinedAuthHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
//     const requestId = event.requestContext?.requestId || 'unknown';
//     const logger = createLogger('auth-service', requestId);

//     logger.appendPersistentKeys({
//         httpMethod: event.httpMethod,
//         path: event.path,
//         userAgent: event.headers?.['User-Agent'],
//         sourceIP: event.requestContext?.identity?.sourceIp
//     });

//     logger.info('Combined auth handler started');

//     // Parse request body
//     const parsedBody = parseRequestBody<CombinedAuthRequest>(event, logger);

//     // Connect to database
//     await connectDB();

//     // Process combined auth
//     const businessHandler = new CombinedAuthBusinessHandler(event, parsedBody);
//     const result = await businessHandler.processRequest();

//     logger.info('Combined auth handler completed successfully', {
//         authFlow: result.authFlow,
//         accountId: result.accountId,
//         isNewUser: result.isNewUser
//     });

//     logger.logBusinessEvent('LAMBDA_SUCCESS', {
//         operationType: 'combined_auth',
//         authFlow: result.authFlow,
//         accountId: result.accountId,
//         isNewUser: result.isNewUser
//     });

//     return SuccessResponse({
//         message: result.message,
//         data: result
//     });
// };

// // ==================== EXPORT ====================

// export const handler = lambdaMiddleware(CombinedAuthHandler, {
//     serviceName: 'auth-service',
//     enableRequestLogging: true,
//     enableResponseLogging: true,
//     enablePerformanceLogging: true,
//     logLevel: 'info'
// });