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
import { Session, ISession } from '../../models/sessions.schema';
import { SQSService } from '../../utils/lambdaSqs';
import jwt, { SignOptions } from 'jsonwebtoken';

// ==================== INTERFACES ====================

interface LoginRequest {
    // Primary identifier - one required
    email?: string;
    phone?: string;
    username?: string;

    // Password (required for initial auth unless 2FA step)
    password?: string;

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

    // Optional remember me
    rememberMe?: boolean;

    // Captcha for suspicious activity
    captchaToken?: string;
    captchaProvider?: 'recaptcha' | 'hcaptcha' | 'cloudflare';

    // 2FA OTP code (for second step)
    otpCode?: string;
    mfaMethod?: 'sms' | 'email' | 'totp';

    // Session continuation
    loginSessionId?: string;
}

interface LoginResponseData {
    success: boolean;
    loginStatus: 'success' | 'requires_2fa' | 'requires_password_reset' | 'account_locked';
    message: string;

    // Full login success
    accessToken?: string;
    refreshToken?: string;
    expiresIn?: number;
    sessionId?: string;

    // 2FA required
    loginSessionId?: string;
    mfaRequired?: {
        methods: Array<'sms' | 'email' | 'totp'>;
        preferredMethod: 'sms' | 'email' | 'totp';
        maskedContact?: string;
        expiresIn: number;
    };

    // Account info
    accountId?: string;
    profile?: {
        firstName?: string;
        lastName?: string;
        displayName?: string;
        avatar?: string;
    };

    // Security info
    lastLogin?: Date;
    newDevice?: boolean;
    securityAlerts?: string[];
}

// ==================== BUSINESS HANDLER CLASS ====================

class LoginBusinessHandler {
    private requestData: LoginRequest;
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
    private session?: ISession;
    private clientIP: string = '';
    private deviceLocation?: any;
    private loginSessionId?: string;
    private isNewDevice: boolean = false;
    private securityAlerts: string[] = [];

    constructor(event: APIGatewayProxyEvent, body: LoginRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

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
            functionName: 'login'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<LoginResponseData> {
        this.logger.info('Starting login process');

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Find account
        await this.findAccount();

        // Step 3: Check account status and security
        this.checkAccountStatus();

        // Step 4: Handle login flow based on 2FA and current step
        if (this.requestData.loginSessionId && this.requestData.otpCode) {
            // Step 4A: 2FA verification step
            return await this.handle2FAVerification();
        } else {
            // Step 4B: Initial login step
            return await this.handleInitialLogin();
        }
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating login request data');

        // At least one identifier required
        if (!this.requestData.email && !this.requestData.phone && !this.requestData.username) {
            throw new HttpError('Email, phone, or username is required', 400);
        }

        // Device info validation
        if (!this.requestData.deviceInfo?.os || !this.requestData.deviceInfo?.browser) {
            throw new HttpError('Device information is required for security purposes', 400);
        }

        // 2FA step validation
        if (this.requestData.loginSessionId && this.requestData.otpCode) {
            if (!this.requestData.mfaMethod) {
                throw new HttpError('MFA method is required when providing OTP code', 400);
            }
            if (!/^\d{6}$/.test(this.requestData.otpCode)) {
                throw new HttpError('Invalid OTP code format', 400);
            }
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

        if (!this.account) {
            // Log failed attempt for security monitoring
            this.logger.warn('Account not found', {
                identifier: this.getIdentifier()
            });
            throw new HttpError('Invalid credentials', 401);
        }

        this.logger.debug('Account found', {
            accountId: this.account._id,
            accountStatus: this.account.accountStatus
        });
    }

    /**
     * Step 3: Check account status and security
     */
    private checkAccountStatus(): void {
        if (!this.account) return;

        // Check if account is locked
        if (this.account.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
            const minutesRemaining = Math.ceil((this.account.security.lockedUntil.getTime() - Date.now()) / (1000 * 60));
            throw new HttpError(`Account is locked. Try again in ${minutesRemaining} minutes.`, 423);
        }

        // Check account status
        if (this.account.accountStatus === 'suspended') {
            throw new HttpError('Account is suspended. Please contact support.', 403);
        }

        if (this.account.accountStatus === 'pending_verification') {
            throw new HttpError('Account email verification is required. Please check your email.', 403);
        }

        // Check for suspicious activity
        this.checkDeviceAndLocation();
    }

    /**
     * Step 4A: Handle initial login (password verification + 2FA check)
     */
    private async handleInitialLogin(): Promise<LoginResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Handling initial login step');

        // Check if 2FA is enabled
        if (this.account.mfaConfig.enabled && this.has2FAMethod()) {
            // 2FA is enabled - send OTP and require second step
            return await this.initiate2FA();
        } else {
            // Verify password
            const isValidPassword = await bcrypt.compare(this.requestData.password!, this.account.password!);

            if (!isValidPassword) {
                await this.handleFailedLogin();
                throw new HttpError('Invalid credentials', 401);
            }

            // Password is valid - reset failed attempts
            this.account.security.failedLoginAttempts = 0;
            this.account.security.lockedUntil = undefined;

            // No 2FA - complete login
            return await this.completeLogin();
        }
    }

    /**
     * Step 4B: Handle 2FA verification
     */
    private async handle2FAVerification(): Promise<LoginResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Handling 2FA verification step');

        // Verify login session exists and is valid
        const verificationCode = await VerificationCode.findOne({
            'context.metadata.loginSessionId': this.requestData.loginSessionId,
            type: 'mfa',
            status: "active",
            expiresAt: { $gt: new Date() }
        });

        if (!verificationCode) {
            throw new HttpError('Invalid or expired login session. Please start login again.', 404);
        }

        // Verify OTP code
        const isValidOTP = verificationCode.verify(this.requestData.otpCode!, {});

        if (!isValidOTP) {
            await verificationCode.save();
            this.logger.warn('Invalid 2FA code provided', {
                accountId: this.account._id,
                remainingAttempts: verificationCode.remainingAttempts
            });
            throw new HttpError(
                `Invalid 2FA code. ${verificationCode.remainingAttempts} attempts remaining.`,
                400
            );
        }

        // 2FA successful - mark as used and complete login
        verificationCode.isUsed = true;
        verificationCode.usedAt = new Date();
        await verificationCode.save();

        // Update MFA last used
        this.account.mfaConfig.lastUsed = new Date();

        return await this.completeLogin();
    }

    /**
     * Initiate 2FA process
     */
    private async initiate2FA(): Promise<LoginResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Initiating 2FA process');

        // Generate login session ID
        this.loginSessionId = `login_${Date.now()}_${Math.random().toString(36).substring(2)}`;

        // Determine preferred 2FA method
        const availableMethods = this.getAvailable2FAMethods();
        const preferredMethod = this.getPreferred2FAMethod(availableMethods);

        // Generate OTP
        const otpCode = VerificationCode.generateCode(6);

        // Create verification code record
        const verificationCode = new VerificationCode({
            accountId: this.account._id,
            code: otpCode,
            hashedCode: VerificationCode.hashCode(otpCode),
            type: 'mfa',
            purpose: 'MFA verification for login',
            method: preferredMethod,
            deliveryInfo: {
                channel: preferredMethod === 'sms' ? 'sms' : 'email',
                provider: preferredMethod === 'sms' ? 'twilio' : 'ses',
                recipient: preferredMethod === 'sms'
                    ? this.account.mfaConfig.methods.sms?.phoneNumber || this.account.phone
                    : this.account.email,
                deliveryStatus: 'pending'
            },
            maxAttempts: 3,
            remainingAttempts: 3,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes for MFA
            context: {
                initiatedBy: 'user',
                triggerEvent: 'login_mfa',
                metadata: {
                    accountId: (this.account._id as string | number | { toString(): string }).toString(),
                    loginSessionId: this.loginSessionId,
                    mfaMethod: preferredMethod
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
        await this.send2FAOTP(preferredMethod, otpCode);

        // Add login history entry (partial)
        this.account.security.loginHistory.push({
            timestamp: new Date(),
            ip: this.clientIP,
            userAgent: this.requestData.deviceInfo.userAgent,
            deviceId: this.requestData.deviceInfo.fingerprint?.hash,
            success: false, // Will be true when 2FA completes
            location: this.deviceLocation
        });

        await this.account.save();

        return {
            success: true,
            loginStatus: 'requires_2fa',
            message: '2FA verification required. Please check your device for the verification code.',
            loginSessionId: this.loginSessionId,
            mfaRequired: {
                methods: availableMethods,
                preferredMethod,
                maskedContact: this.maskContact(preferredMethod),
                expiresIn: 180 // 3 minutes
            },
            accountId: String(this.account._id)
        };
    }

    /**
     * Complete successful login - NOW WITH SESSION CREATION
     */
    private async completeLogin(): Promise<LoginResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Completing successful login');

        // Generate tokens
        const accessToken = this.generateAccessToken();
        const refreshToken = this.generateRefreshToken();

        // Create session
        await this.createSession(accessToken, refreshToken);

        // Update account login info
        this.account.lastLogin = new Date();
        this.account.loginCount += 1;

        // Add successful login to history
        const loginEntry = {
            timestamp: new Date(),
            ip: this.clientIP,
            userAgent: this.requestData.deviceInfo.userAgent,
            deviceId: this.requestData.deviceInfo.fingerprint?.hash,
            success: true,
            location: this.deviceLocation
        };

        // Update or add login history entry
        const existingEntryIndex = this.account.security.loginHistory.findIndex(
            entry => entry.timestamp.getTime() > Date.now() - 5 * 60 * 1000 && // Within 5 minutes
                entry.ip === this.clientIP &&
                !entry.success
        );

        if (existingEntryIndex >= 0) {
            // Update existing entry from 2FA step
            this.account.security.loginHistory[existingEntryIndex] = loginEntry;
        } else {
            // Add new entry
            this.account.security.loginHistory.push(loginEntry);
        }

        // Keep only last 50 login attempts
        if (this.account.security.loginHistory.length > 50) {
            this.account.security.loginHistory = this.account.security.loginHistory.slice(-50);
        }

        // Add device to trusted devices if new and successful
        if (this.isNewDevice && this.requestData.deviceInfo.fingerprint?.hash) {
            this.account.security.trustedDevices.push(this.requestData.deviceInfo.fingerprint.hash);
            // Keep only last 10 trusted devices
            if (this.account.security.trustedDevices.length > 10) {
                this.account.security.trustedDevices = this.account.security.trustedDevices.slice(-10);
            }
        }

        await this.account.save();

        this.logger.info('Login completed successfully', {
            accountId: this.account._id,
            sessionId: this.session?.sessionId,
            newDevice: this.isNewDevice
        });

        return {
            success: true,
            loginStatus: 'success',
            message: 'Login successful',
            accessToken,
            refreshToken,
            expiresIn: this.parseJWTExpiration(this.JWT_EXPIRES_IN),
            sessionId: this.session?.sessionId,
            accountId: String(this.account._id),
            profile: {
                firstName: this.account.profile.firstName,
                lastName: this.account.profile.lastName,
                displayName: this.account.profile.displayName,
                avatar: this.account.profile.avatar
            },
            lastLogin: this.account.lastLogin,
            newDevice: this.isNewDevice,
            securityAlerts: this.securityAlerts
        };
    }

    /**
     * Create a new session
     */
    private async createSession(accessToken: string, refreshToken: string): Promise<void> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Creating session');

        // Check concurrent session limits
        const activeSessions = await Session.countDocuments({
            accountId: this.account._id,
            isActive: true,
            status: 'active'
        });

        const maxConcurrentSessions = 3; // You can make this configurable

        if (activeSessions >= maxConcurrentSessions) {
            // Terminate oldest session
            const oldestSession = await Session.findOne({
                accountId: this.account._id,
                isActive: true,
                status: 'active'
            }).sort({ lastActivityAt: 1 });

            if (oldestSession) {
                oldestSession.terminate('max_sessions', 'system');
                await oldestSession.save();
                this.logger.info('Terminated oldest session due to max concurrent limit', {
                    terminatedSessionId: oldestSession.sessionId
                });
            }
        }

        // Create session
        this.session = new Session({
            accountId: this.account._id,
            deviceInfo: {
                deviceId: this.requestData.deviceInfo.fingerprint?.hash,
                deviceType: this.requestData.deviceInfo.deviceType || 'unknown',
                os: this.requestData.deviceInfo.os,
                browser: this.requestData.deviceInfo.browser,
                userAgent: this.requestData.deviceInfo.userAgent,
                // Add other device info as needed
            },
            location: {
                ip: this.clientIP,
                country: this.deviceLocation?.country,
                // Add other location info as available
            },
            securityContext: {
                riskScore: this.calculateRiskScore(),
                riskFactors: this.securityAlerts,
                isTrusted: !this.isNewDevice,
                requiresMfa: this.account.mfaConfig.enabled,
                mfaCompleted: this.account.mfaConfig.enabled,
                authenticationMethod: 'password',
                strongAuthentication: this.account.mfaConfig.enabled
            },
            accessToken,
            refreshTokens: [{
                token: refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                isRevoked: false,
                family: `fam_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
            }],
            isPersistent: this.requestData.rememberMe || false,
            roles: [], // Set based on account roles
            permissions: [], // Set based on account permissions
            scopes: ['read', 'write'], // Set appropriate scopes
            expiresAt: this.requestData.rememberMe
                ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days if remember me
                : new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours normal
            maxConcurrentAllowed: maxConcurrentSessions,
            metadata: {
                loginMethod: this.account.mfaConfig.enabled ? '2fa' : 'password',
                browserInfo: {
                    userAgent: this.requestData.deviceInfo.userAgent,
                    browser: this.requestData.deviceInfo.browser,
                    os: this.requestData.deviceInfo.os
                },
                captchaUsed: !!this.requestData.captchaToken,
                newDevice: this.isNewDevice
            }
        });

        // Add initial activity
        this.session.addActivity({
            action: 'login',
            endpoint: this.event.path,
            method: this.event.httpMethod,
            statusCode: 200,
            userAgent: this.requestData.deviceInfo.userAgent,
            ip: this.clientIP
        });

        await this.session.save();

        this.logger.info('Session created successfully', {
            sessionId: this.session.sessionId,
            accountId: this.account._id,
            expiresAt: this.session.expiresAt,
            isPersistent: this.session.isPersistent
        });
    }

    /**
     * Handle failed login attempt
     */
    private async handleFailedLogin(): Promise<void> {
        if (!this.account) return;

        this.account.security.failedLoginAttempts += 1;

        // Lock account after 5 failed attempts
        if (this.account.security.failedLoginAttempts >= 5) {
            this.account.security.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
            this.logger.warn('Account locked due to failed login attempts', {
                accountId: this.account._id,
                attempts: this.account.security.failedLoginAttempts
            });
        }

        // Add failed login to history
        this.account.security.loginHistory.push({
            timestamp: new Date(),
            ip: this.clientIP,
            userAgent: this.requestData.deviceInfo.userAgent,
            deviceId: this.requestData.deviceInfo.fingerprint?.hash,
            success: false,
            location: this.deviceLocation
        });

        await this.account.save();
    }

    /**
     * Send 2FA OTP via preferred method
     */
    private async send2FAOTP(method: 'sms' | 'email' | 'totp', otpCode: string): Promise<void> {
        if (method === 'totp') return; // TOTP doesn't need sending

        const sqsBody = {
            notificationType: method === 'sms' ? 'sms_2fa' : 'email_2fa',
            channels: [method === 'sms' ? 'sms' : 'email'],
            content: method === 'sms' ? {
                sms: {
                    message: `Your verification code is: ${otpCode}. This code expires in 3 minutes.`,
                    recipient: this.account!.mfaConfig.methods.sms?.phoneNumber || this.account!.phone
                }
            } : {
                email: {
                    subject: 'Login Verification Code',
                    template: 'login-2fa',
                    data: {
                        name: this.account!.profile.firstName || 'User',
                        otp: otpCode,
                        expiryMinutes: 3,
                        location: this.deviceLocation?.country || 'Unknown',
                        device: this.requestData.deviceInfo.os
                    },
                    recipient: this.account!.email
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

    private checkDeviceAndLocation(): void {
        if (!this.account) return;

        const deviceId = this.requestData.deviceInfo.fingerprint?.hash;

        if (deviceId && !this.account.security.trustedDevices.includes(deviceId)) {
            this.isNewDevice = true;
            this.securityAlerts.push('New device detected');
        }

        // TODO: Implement geolocation check
        this.deviceLocation = { country: 'Unknown' };
    }

    private has2FAMethod(): boolean {
        if (!this.account) return false;

        return (
            (!!this.account.mfaConfig.methods.sms?.enabled && !!this.account.mfaConfig.methods.sms?.verified) ||
            (!!this.account.mfaConfig.methods.email?.enabled && !!this.account.mfaConfig.methods.email?.verified) ||
            (!!this.account.mfaConfig.methods.totp?.enabled && !!this.account.mfaConfig.methods.totp?.verified)
        );
    }

    private getAvailable2FAMethods(): Array<'sms' | 'email' | 'totp'> {
        if (!this.account) return [];

        const methods: Array<'sms' | 'email' | 'totp'> = [];

        if (this.account.mfaConfig.methods.sms?.enabled && this.account.mfaConfig.methods.sms?.verified) {
            methods.push('sms');
        }
        if (this.account.mfaConfig.methods.email?.enabled && this.account.mfaConfig.methods.email?.verified) {
            methods.push('email');
        }
        if (this.account.mfaConfig.methods.totp?.enabled && this.account.mfaConfig.methods.totp?.verified) {
            methods.push('totp');
        }

        return methods;
    }

    private getPreferred2FAMethod(availableMethods: Array<'sms' | 'email' | 'totp'>): 'sms' | 'email' | 'totp' {
        // Priority: SMS > Email > TOTP (most user-friendly first)
        if (availableMethods.includes('sms')) return 'sms';
        if (availableMethods.includes('email')) return 'email';
        return 'totp';
    }

    private maskContact(method: 'sms' | 'email' | 'totp'): string {
        if (!this.account) return '';

        if (method === 'sms') {
            const phone = this.account.mfaConfig.methods.sms?.phoneNumber || this.account.phone || '';
            return phone.length > 4 ? `***${phone.slice(-4)}` : phone;
        } else if (method === 'email') {
            const email = this.account.email || '';
            const [username, domain] = email.split('@');
            if (username && domain) {
                const maskedUsername = username.length > 2
                    ? username.substring(0, 2) + '*'.repeat(username.length - 2)
                    : '*'.repeat(username.length);
                return `${maskedUsername}@${domain}`;
            }
        }
        return 'Authenticator App';
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
            expiresIn: this.JWT_EXPIRES_IN as any // e.g., '1h'
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
            default: return 24 * 60 * 60; // 24 hours default
        }
    }
}

// ==================== LAMBDA HANDLER ====================

const LoginHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Login handler started');

    // Parse request body
    const parsedBody = parseRequestBody<LoginRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process login
    const businessHandler = new LoginBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Login handler completed successfully');
    logger.logBusinessEvent('LAMBDA_SUCCESS', {
        operationType: 'login',
        loginStatus: result.loginStatus,
        accountId: result.accountId,
        requires2FA: result.loginStatus === 'requires_2fa'
    });

    return SuccessResponse({
        message: result.message,
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(LoginHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});