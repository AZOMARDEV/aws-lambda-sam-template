// import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
// import { connectDB } from '../../utils/dbconnect';
// import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
// import { createLogger } from '../../utils/logger';
// import { parseRequestBody } from '../../utils/requestParser';
// import HttpError from '../../exception/httpError';
// import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
// import bcrypt from 'bcryptjs';
// import { Account, IAccount } from '../../models/account.schema';
// import { VerificationCode } from '../../models/verification_codes.schema';
// import { Session, ISession } from '../../models/sessions.schema';
// import { SQSService } from '../../utils/lambdaSqs';
// import jwt, { SignOptions } from 'jsonwebtoken';
// import ProjectModel, { IProjectSettings } from '../../models/project.schema'; // Import the Project model

// // ==================== INTERFACES ====================

// interface LoginRequest {
//     // Primary identifier - one required
//     email?: string;
//     phone?: string;
//     username?: string;

//     // Password (required for initial auth unless 2FA step)
//     password?: string;

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

//     // Optional remember me
//     rememberMe?: boolean;

//     // Captcha for suspicious activity
//     captchaToken?: string;
//     captchaProvider?: 'recaptcha' | 'hcaptcha' | 'cloudflare';

//     // 2FA OTP code (for second step)
//     otpCode?: string;
//     mfaMethod?: 'sms' | 'email' | 'totp';

//     // Session continuation
//     loginSessionId?: string;
// }

// interface LoginResponseData {
//     success: boolean;
//     loginStatus: 'success' | 'requires_2fa' | 'requires_password_reset' | 'account_locked';
//     message: string;

//     // Full login success
//     accessToken?: string;
//     refreshToken?: string;
//     expiresIn?: number;
//     sessionId?: string;

//     // 2FA required
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
//     };

//     // Security info
//     lastLogin?: Date;
//     newDevice?: boolean;
//     securityAlerts?: string[];
// }

// // ==================== BUSINESS HANDLER CLASS ====================

// class LoginBusinessHandler {
//     private requestData: LoginRequest;
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
//     private project?: IProjectSettings; // Project configuration
//     private session?: ISession;
//     private clientIP: string = '';
//     private deviceLocation?: any;
//     private loginSessionId?: string;
//     private isNewDevice: boolean = false;
//     private securityAlerts: string[] = [];

//     constructor(event: APIGatewayProxyEvent, body: LoginRequest) {
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
//             functionName: 'login'
//         });
//     }

//     /**
//      * Main processing method
//      */
//     async processRequest(): Promise<LoginResponseData> {
//         this.logger.info('Starting login process');

//         // Step 1: Validate request data
//         this.validateRequestData();

//         // Step 2: Find account
//         await this.findAccount();

//         // Step 3: Load project configuration
//         await this.loadProjectConfiguration();

//         // Step 4: Check account status and security
//         this.checkAccountStatus();

//         // Step 5: Handle login flow based on project 2FA and current step
//         if (this.requestData.loginSessionId && this.requestData.otpCode) {
//             // Step 5A: 2FA verification step
//             return await this.handle2FAVerification();
//         } else {
//             // Step 5B: Initial login step
//             return await this.handleInitialLogin();
//         }
//     }

//     /**
//      * Step 1: Validate request data
//      */
//     private validateRequestData(): void {
//         this.logger.debug('Validating login request data');

//         // At least one identifier required
//         if (!this.requestData.email && !this.requestData.phone && !this.requestData.username) {
//             throw new HttpError('Email, phone, or username is required', 400);
//         }

//         // Device info validation
//         if (!this.requestData.deviceInfo?.os || !this.requestData.deviceInfo?.browser) {
//             throw new HttpError('Device information is required for security purposes', 400);
//         }

//         // 2FA step validation
//         if (this.requestData.loginSessionId && this.requestData.otpCode) {
//             if (!this.requestData.mfaMethod) {
//                 throw new HttpError('MFA method is required when providing OTP code', 400);
//             }
//             if (!/^\d{6}$/.test(this.requestData.otpCode)) {
//                 throw new HttpError('Invalid OTP code format', 400);
//             }
//             // For 2FA step, don't require password
//             return;
//         }

//         this.logger.debug('Request validation completed');
//     }

//     /**
//      * Step 2: Find account
//      */
//     private async findAccount(): Promise<void> {
//         this.logger.debug('Finding account');

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

//         const foundAccount = await Account.findOne({
//             $or: conditions,
//             accountStatus: { $ne: 'deactivated' }
//         });

//         this.account = foundAccount || undefined;

//         if (!this.account) {
//             // Log failed attempt for security monitoring
//             this.logger.warn('Account not found', {
//                 identifier: this.getIdentifier()
//             });
//             throw new HttpError('Invalid credentials', 401);
//         }

//         this.logger.debug('Account found', {
//             accountId: this.account._id,
//             accountStatus: this.account.accountStatus
//         });
//     }

//     /**
//      * Step 3: Load project configuration
//      */
//     private async loadProjectConfiguration(): Promise<void> {
//         this.logger.debug('Loading project configuration');

//         // Get the single project document from the DB
//         const project = await ProjectModel.findOne({ category: "AUTH" });

//         if (!project) {
//             this.logger.error('No project configuration found in database');
//             throw new HttpError('Project configuration not found. Please contact support.', 500);
//         }

//         this.project = project;
//     }

//     /**
//      * Step 4: Check account status and security
//      */
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

//         // Check for suspicious activity
//         this.checkDeviceAndLocation();
//     }

//     /**
//      * Step 5A: Handle initial login with project-based 2FA
//      */
//     private async handleInitialLogin(): Promise<LoginResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);
//         if (!this.project) throw new HttpError('Project configuration not found', 500);

//         this.logger.debug('Handling initial login step');

//         // Check account authentication setup
//         const accountHasPassword = !!this.account.password;
//         const userProvidedPassword = !!this.requestData.password;

//         // Check project 2FA configuration instead of account
//         const project2FAEnabled = this.project.settings?.mfa.enabled;
//         const project2FAMandatory = this.project.settings?.mfa.mandatory;

//         this.logger.debug('Authentication setup check', {
//             accountHasPassword,
//             userProvidedPassword,
//             project2FAEnabled,
//             project2FAMandatory,
//             accountAuthMethods: this.getAccountAuthMethods()
//         });

//         // EDGE CASE 3: Passwordless account without project 2FA (shouldn't happen but handle it)
//         if (!accountHasPassword && !project2FAEnabled) {
//             this.logger.error('Account has no authentication methods and project has no 2FA', {
//                 accountId: this.account._id
//             });

//             throw new HttpError(
//                 'Account authentication is not properly configured. Please contact support.',
//                 500,
//                 'INVALID_AUTH_CONFIG'
//             );
//         }


//         if (this.project.settings.mfa.enabled && this.hasAvailable2FAMethods()) {
//             this.logger.debug('Password verified, proceeding to project-configured 2FA');
//             return await this.handlePasswordlessAuth();
//         } else {

//             // EDGE CASE 2: Account has password but user didn't provide it
//             if (accountHasPassword && !userProvidedPassword) {
//                 this.logger.warn('Password required but not provided', {
//                     accountId: this.account._id,
//                     project2FA: { enabled: project2FAEnabled, mandatory: project2FAMandatory }
//                 });

//                 throw new HttpError(
//                     'Password is required for this account.',
//                     400,
//                     'PASSWORD_REQUIRED'
//                 );
//             }

//             // Standard password + optional project-configured 2FA flow
//             return await this.handlePasswordBasedAuth();

//         }
//     }

//     /**
//      * Handle password-based authentication with project 2FA
//      */
//     private async handlePasswordBasedAuth(): Promise<LoginResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);
//         if (!this.project) throw new HttpError('Project configuration not found', 500);

//         this.logger.debug('Processing password-based authentication');

//         // Verify password
//         const isValidPassword = await bcrypt.compare(this.requestData.password!, this.account.password!);

//         if (!isValidPassword) {
//             await this.handleFailedLogin();
//             throw new HttpError('Invalid credentials', 401);
//         }

//         // Password is valid - reset failed attempts
//         this.account.security.failedLoginAttempts = 0;
//         this.account.security.lockedUntil = undefined;


//         this.logger.debug('Password verified, completing login (no project 2FA required)');
//         return await this.completeLogin();

//     }

//     /**
//      * Handle passwordless authentication (project 2FA only)
//      */
//     private async handlePasswordlessAuth(): Promise<LoginResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);
//         if (!this.project) throw new HttpError('Project configuration not found', 500);

//         this.logger.debug('Processing passwordless authentication');

//         // For passwordless accounts, we directly proceed to project-configured 2FA
//         this.account.security.failedLoginAttempts = 0;
//         this.account.security.lockedUntil = undefined;

//         return await this.initiate2FA();
//     }

//     /**
//      * Get available authentication methods for the account
//      */
//     private getAccountAuthMethods(): string[] {
//         if (!this.account) return [];

//         const methods: string[] = [];

//         if (this.account.password) {
//             methods.push('password');
//         }

//         // Since mfaConfig is removed from account, we check what the account supports
//         // based on having phone/email for 2FA
//         if (this.account.phone) {
//             methods.push('sms');
//         }

//         if (this.account.email) {
//             methods.push('email_2fa');
//         }

//         // TOTP would need to be tracked differently now
//         // methods.push('totp'); // You might need to add this to account schema or track differently

//         return methods;
//     }

//     /**
//      * Step 5B: Handle 2FA verification
//      */
//     private async handle2FAVerification(): Promise<LoginResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         this.logger.debug('Handling 2FA verification step');

//         // Verify login session exists and is valid
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

//         // 2FA successful - mark as used and complete login
//         verificationCode.isUsed = true;
//         verificationCode.usedAt = new Date();
//         await verificationCode.save();

//         return await this.completeLogin();
//     }

//     /**
//      * Initiate 2FA process based on project configuration
//      */
//     private async initiate2FA(): Promise<LoginResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);
//         if (!this.project) throw new HttpError('Project configuration not found', 500);

//         this.logger.debug('Initiating project-configured 2FA process');

//         // Generate login session ID
//         this.loginSessionId = `login_${Date.now()}_${Math.random().toString(36).substring(2)}`;

//         // Determine available and preferred 2FA methods based on project config
//         const availableMethods = this.getAvailable2FAMethods();
//         const preferredMethod = this.getPreferred2FAMethod(availableMethods);

//         if (availableMethods.length === 0) {
//             throw new HttpError('No 2FA methods available for this account', 500);
//         }

//         // Generate OTP
//         const otpCode = VerificationCode.generateCode(6);

//         // Create verification code record
//         const verificationCode = new VerificationCode({
//             accountId: this.account._id,
//             code: otpCode,
//             hashedCode: VerificationCode.hashCode(otpCode),
//             type: 'mfa',
//             purpose: 'MFA verification for login',
//             method: preferredMethod,
//             deliveryInfo: {
//                 channel: preferredMethod === 'sms' ? 'sms' : 'email',
//                 provider: preferredMethod === 'sms' ? 'twilio' : 'ses',
//                 recipient: preferredMethod === 'sms'
//                     ? this.account.phone
//                     : this.account.email,
//                 deliveryStatus: 'pending'
//             },
//             maxAttempts: 3,
//             remainingAttempts: 3,
//             expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes for MFA
//             context: {
//                 initiatedBy: 'user',
//                 triggerEvent: 'login_mfa',
//                 metadata: {
//                     accountId: (this.account._id as string | number | { toString(): string }).toString(),
//                     loginSessionId: this.loginSessionId,
//                     mfaMethod: preferredMethod,
//                     projectMfaEnabled: this.project.settings?.mfa.enabled
//                 },
//                 sessionId: this.event.requestContext?.requestId,
//                 ip: this.clientIP,
//                 userAgent: this.requestData.deviceInfo.userAgent
//             },
//             security: {
//                 requiresSecureChannel: true,
//                 preventBruteForce: true,
//                 logAllAttempts: true,
//                 notifyOnFailure: true,
//                 riskScore: this.calculateRiskScore()
//             }
//         });

//         await verificationCode.save();

//         // Send OTP
//         await this.send2FAOTP(preferredMethod, otpCode);

//         // Add login history entry (partial)
//         this.account.security.loginHistory.push({
//             timestamp: new Date(),
//             ip: this.clientIP,
//             userAgent: this.requestData.deviceInfo.userAgent,
//             deviceId: this.requestData.deviceInfo.fingerprint?.hash,
//             success: false, // Will be true when 2FA completes
//             location: this.deviceLocation
//         });

//         await this.account.save();

//         return {
//             success: true,
//             loginStatus: 'requires_2fa',
//             message: '2FA verification required. Please check your device for the verification code.',
//             loginSessionId: this.loginSessionId,
//             mfaRequired: {
//                 methods: availableMethods,
//                 preferredMethod,
//                 maskedContact: this.maskContact(preferredMethod),
//                 expiresIn: 180 // 3 minutes
//             },
//             accountId: String(this.account._id)
//         };
//     }

//     /**
//      * Complete successful login - NOW WITH SESSION CREATION
//      */
//     private async completeLogin(): Promise<LoginResponseData> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         this.logger.debug('Completing successful login');

//         // Generate tokens
//         const accessToken = this.generateAccessToken();
//         const refreshToken = this.generateRefreshToken();

//         // Create session
//         await this.createSession(accessToken, refreshToken);

//         // Update account login info
//         this.account.lastLogin = new Date();
//         this.account.loginCount += 1;

//         // Add successful login to history
//         const loginEntry = {
//             timestamp: new Date(),
//             ip: this.clientIP,
//             userAgent: this.requestData.deviceInfo.userAgent,
//             deviceId: this.requestData.deviceInfo.fingerprint?.hash,
//             success: true,
//             location: this.deviceLocation
//         };

//         // Update or add login history entry
//         const existingEntryIndex = this.account.security.loginHistory.findIndex(
//             entry => entry.timestamp.getTime() > Date.now() - 5 * 60 * 1000 && // Within 5 minutes
//                 entry.ip === this.clientIP &&
//                 !entry.success
//         );

//         if (existingEntryIndex >= 0) {
//             // Update existing entry from 2FA step
//             this.account.security.loginHistory[existingEntryIndex] = loginEntry;
//         } else {
//             // Add new entry
//             this.account.security.loginHistory.push(loginEntry);
//         }

//         // Keep only last 50 login attempts
//         if (this.account.security.loginHistory.length > 50) {
//             this.account.security.loginHistory = this.account.security.loginHistory.slice(-50);
//         }

//         // Add device to trusted devices if new and successful
//         if (this.isNewDevice && this.requestData.deviceInfo.fingerprint?.hash) {
//             this.account.security.trustedDevices.push(this.requestData.deviceInfo.fingerprint.hash);
//             // Keep only last 10 trusted devices
//             if (this.account.security.trustedDevices.length > 10) {
//                 this.account.security.trustedDevices = this.account.security.trustedDevices.slice(-10);
//             }
//         }

//         await this.account.save();

//         this.logger.info('Login completed successfully', {
//             accountId: this.account._id,
//             sessionId: this.session?.sessionId,
//             newDevice: this.isNewDevice,
//             projectMfa: this.project?.settings?.mfa.enabled
//         });

//         return {
//             success: true,
//             loginStatus: 'success',
//             message: 'Login successful',
//             accessToken,
//             refreshToken,
//             expiresIn: this.parseJWTExpiration(this.JWT_EXPIRES_IN),
//             sessionId: this.session?.sessionId,
//             accountId: String(this.account._id),
//             profile: this.account.profile || {},
//             lastLogin: this.account.lastLogin,
//             newDevice: this.isNewDevice,
//             securityAlerts: this.securityAlerts
//         };
//     }

//     /**
//      * Create a new session
//      */
//     private async createSession(accessToken: string, refreshToken: string): Promise<void> {
//         if (!this.account) throw new HttpError('Account not found', 404);

//         this.logger.debug('Creating session');

//         // Check concurrent session limits
//         const activeSessions = await Session.countDocuments({
//             accountId: this.account._id,
//             isActive: true,
//             status: 'active'
//         });

//         const maxConcurrentSessions = 3; // You can make this configurable

//         if (activeSessions >= maxConcurrentSessions) {
//             // Terminate oldest session
//             const oldestSession = await Session.findOne({
//                 accountId: this.account._id,
//                 isActive: true,
//                 status: 'active'
//             }).sort({ lastActivityAt: 1 });

//             if (oldestSession) {
//                 oldestSession.terminate('max_sessions', 'system');
//                 await oldestSession.save();
//                 this.logger.info('Terminated oldest session due to max concurrent limit', {
//                     terminatedSessionId: oldestSession.sessionId
//                 });
//             }
//         }

//         // Add session duration from project settings
//         const sessionDuration = this.project?.settings?.sessionManagement?.maxSessionDurationHours || 8;
//         const idleTimeout = this.project?.settings?.sessionManagement?.idleTimeoutMinutes || 15;


//         // Create session
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
//                 authenticationMethod: 'password',
//                 strongAuthentication: this.project?.settings?.mfa.enabled || false
//             },
//             accessToken,
//             refreshTokens: [{
//                 token: refreshToken,
//                 expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
//                 isRevoked: false,
//                 family: `fam_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
//             }],
//             isPersistent: this.requestData.rememberMe || false,
//             roles: [], // Set based on account roles
//             permissions: [], // Set based on account permissions
//             scopes: ['read', 'write'], // Set appropriate scopes
//             expiresAt: this.requestData.rememberMe
//                 ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days if remember me
//                 : new Date(Date.now() + sessionDuration * 60 * 60 * 1000), // Use project setting

//             idleTimeoutAt: new Date(Date.now() + idleTimeout * 60 * 1000),
//             maxConcurrentAllowed: maxConcurrentSessions,
//             metadata: {
//                 loginMethod: this.project?.settings?.mfa.enabled ? '2fa' : 'password',
//                 browserInfo: {
//                     userAgent: this.requestData.deviceInfo.userAgent,
//                     browser: this.requestData.deviceInfo.browser,
//                     os: this.requestData.deviceInfo.os
//                 },
//                 captchaUsed: !!this.requestData.captchaToken,
//                 newDevice: this.isNewDevice
//             }
//         });

//         // Add initial activity
//         this.session.addActivity({
//             action: 'login',
//             endpoint: this.event.path,
//             method: this.event.httpMethod,
//             statusCode: 200,
//             userAgent: this.requestData.deviceInfo.userAgent,
//             ip: this.clientIP
//         });

//         await this.session.save();

//         this.logger.info('Session created successfully', {
//             sessionId: this.session.sessionId,
//             accountId: this.account._id,
//             expiresAt: this.session.expiresAt,
//             isPersistent: this.session.isPersistent
//         });
//     }

//     /**
//      * Handle failed login attempt
//      */
//     private async handleFailedLogin(): Promise<void> {
//         if (!this.account) return;

//         this.account.security.failedLoginAttempts += 1;

//         // Lock account after 5 failed attempts
//         if (this.account.security.failedLoginAttempts >= 5) {
//             this.account.security.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
//             this.logger.warn('Account locked due to failed login attempts', {
//                 accountId: this.account._id,
//                 attempts: this.account.security.failedLoginAttempts
//             });
//         }

//         // Add failed login to history
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

//     /**
//      * Send 2FA OTP via preferred method
//      */
//     private async send2FAOTP(method: 'sms' | 'email' | 'totp', otpCode: string): Promise<void> {
//         if (method === 'totp') return; // TOTP doesn't need sending

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
//                         expiryMinutes: 3,
//                         location: this.deviceLocation?.country || 'Unknown',
//                         device: this.requestData.deviceInfo.os,
//                         email: this.account!.email,

//                         // Additional placeholders
//                         otp: otpCode,
//                         login_time: new Date().toISOString(),
//                         ip_address: this.clientIP,
//                         location_info: this.deviceLocation?.country || 'Unknown',
//                         device_info: `${this.requestData.deviceInfo.browser} on ${this.requestData.deviceInfo.os}`,
//                         user_email: this.account!.email || 'Unknown',
//                         login_url: `${process.env.APP_URL}/login`,
//                         help_url: `${process.env.APP_URL}/help`,
//                         privacy_url: `${process.env.APP_URL}/privacy`,
//                         security_url: `${process.env.APP_URL}/account/security`,
//                         unsubscribe_url: `${process.env.APP_URL}/unsubscribe`,
//                     },
//                     recipient: this.account!.email
//                 }
//             },
//             priority: 'high'
//         };

//         await this.sqsservice.sendMessage(this.SQS_QUEUE_URL, sqsBody);
//     }

//     // ==================== HELPER METHODS ====================

//     private getIdentifier(): string {
//         return this.requestData.email || this.requestData.phone || this.requestData.username || 'unknown';
//     }

//     private checkDeviceAndLocation(): void {
//         if (!this.account || !this.project) return;

//         const deviceId = this.requestData.deviceInfo.fingerprint?.hash;
//         const trustedDevicesEnabled = this.project.settings?.mfa.trustedDevices.enabled;
//         const defaultExpirationDays = this.project.settings?.mfa.trustedDevices.defaultExpirationDays || 30;

//         if (deviceId && trustedDevicesEnabled) {
//             if (!this.account.security.trustedDevices.includes(deviceId)) {
//                 this.isNewDevice = true;
//                 this.securityAlerts.push('New device detected');
//             }
//         }

//         // TODO: Implement geolocation check
//         this.deviceLocation = { country: 'Unknown' };
//     }

//     /**
//      * Check if account has any available 2FA methods
//      */
//     private hasAvailable2FAMethods(): boolean {
//         if (!this.account || !this.project) return false;

//         // Check if project supports the methods and account has the required info
//         const projectMethods = this.project.settings?.mfa.methods || [];

//         // Check SMS - project supports it and account has phone
//         const hasSMS = projectMethods.includes('SMS') && !!this.account.phone;

//         // Check Email - project supports it and account has email
//         const hasEmail = projectMethods.includes('EMAIL') && !!this.account.email;

//         // Check TOTP - project supports it (would need additional logic to check if user has set up TOTP)
//         const hasTOTP = projectMethods.includes('TOTP'); // You might need to add TOTP setup tracking

//         return hasSMS || hasEmail || hasTOTP;
//     }

//     /**
//      * Get available 2FA methods based on project config and account capabilities
//      */
//     private getAvailable2FAMethods(): Array<'sms' | 'email' | 'totp'> {
//         if (!this.account || !this.project) return [];

//         const methods: Array<'sms' | 'email' | 'totp'> = [];
//         const projectMethods = this.project.settings?.mfa.methods || [];

//         // Check SMS
//         if (projectMethods.includes('SMS') && this.account.phone) {
//             methods.push('sms');
//         }

//         // Check Email
//         if (projectMethods.includes('EMAIL') && this.account.email) {
//             methods.push('email');
//         }

//         // Check TOTP
//         if (projectMethods.includes('TOTP')) {
//             // You might want to add additional checks here for TOTP setup
//             methods.push('totp');
//         }

//         return methods;
//     }

//     /**
//      * Get preferred 2FA method based on project and account
//      */
//     private getPreferred2FAMethod(availableMethods: Array<'sms' | 'email' | 'totp'>): 'sms' | 'email' | 'totp' {
//         // Priority: SMS > Email > TOTP (most user-friendly first)
//         if (availableMethods.includes('sms')) return 'sms';
//         if (availableMethods.includes('email')) return 'email';
//         return 'totp';
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
//             expiresIn: this.JWT_EXPIRES_IN as any // e.g., '1h'
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
//             default: return 24 * 60 * 60; // 24 hours default
//         }
//     }
// }

// // ==================== LAMBDA HANDLER ====================

// const LoginHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
//     const requestId = event.requestContext?.requestId || 'unknown';
//     const logger = createLogger('auth-service', requestId);

//     logger.appendPersistentKeys({
//         httpMethod: event.httpMethod,
//         path: event.path,
//         userAgent: event.headers?.['User-Agent'],
//         sourceIP: event.requestContext?.identity?.sourceIp
//     });

//     logger.info('Login handler started');

//     // Parse request body
//     const parsedBody = parseRequestBody<LoginRequest>(event, logger);

//     // Connect to database
//     await connectDB();

//     // Process login
//     const businessHandler = new LoginBusinessHandler(event, parsedBody);
//     const result = await businessHandler.processRequest();

//     logger.info('Login handler completed successfully');
//     logger.logBusinessEvent('LAMBDA_SUCCESS', {
//         operationType: 'login',
//         loginStatus: result.loginStatus,
//         accountId: result.accountId,
//         requires2FA: result.loginStatus === 'requires_2fa'
//     });

//     return SuccessResponse({
//         message: result.message,
//         data: result
//     });
// };

// // ==================== EXPORT ====================

// export const handler = lambdaMiddleware(LoginHandler, {
//     serviceName: 'auth-service',
//     enableRequestLogging: true,
//     enableResponseLogging: true,
//     enablePerformanceLogging: true,
//     logLevel: 'info'
// });