import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import bcrypt from 'bcryptjs';
import { Account, IAccount } from '../../models/account.schema';
import { Session, ISession } from '../../models/sessions.schema';
import { SQSService } from '../../utils/lambdaSqs';
import jwt, { SignOptions } from 'jsonwebtoken';
import ProjectSettingsModel, { IProjectSettings } from '../../models/project.schema';

// ==================== INTERFACES ====================

interface LoginRequest {
    // Primary identifier - one required
    email?: string;
    phone?: string;
    username?: string;

    // Password (required for initial auth unless 2FA step)
    password: string;

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
    private project?: IProjectSettings; // Project configuration
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

        await this.loadProjectConfiguration();

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Find account
        await this.findAccount();

        // Step 4: Check account status and security
        this.checkAccountStatus();

        // Standard password
        return await this.handlePasswordBasedAuth();

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

        if (!this.requestData.password) {
            throw new HttpError('Password is required', 400);
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

    /**
     * Step 4: Check account status and security
     */
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

        if (this.account.accountStatus.status === 'pending_verification') {
            throw new HttpError('Account email verification is required. Please check your email.', 403);
        }
    }


    /**
     * Handle password-based authentication with project 2FA
     */
    private async handlePasswordBasedAuth(): Promise<LoginResponseData> {
        if (!this.account) throw new HttpError('Account not found', 404);

        this.logger.debug('Handling initial login step');

        // Check account authentication setup
        const accountHasPassword = !!this.account.password;
        const userProvidedPassword = !!this.requestData.password;

        this.logger.debug('Authentication setup check', {
            accountHasPassword,
            userProvidedPassword,
            accountAuthMethods: this.getAccountAuthMethods()
        });

        // EDGE CASE 3: Passwordless account without project 2FA (shouldn't happen but handle it)
        if (!accountHasPassword) {
            this.logger.error('Account has no authentication methods and project has no 2FA', {
                accountId: this.account._id
            });

            throw new HttpError(
                'Account authentication is not properly configured. Please contact support.',
                500,
                'INVALID_AUTH_CONFIG'
            );
        }


        this.logger.debug('Processing password-based authentication');

        // Verify password
        const isValidPassword = await bcrypt.compare(this.requestData.password!, this.account.password!);

        if (!isValidPassword) {
            await this.handleFailedLogin();
            throw new HttpError('Invalid credentials', 401);
        }

        // Password is valid - reset failed attempts
        this.account.security.failedLoginAttempts = 0;
        this.account.security.lockedUntil = undefined;


        this.logger.debug('Password verified, completing login (no project 2FA required)');
        return await this.completeLogin();

    }

    /**
     * Get available authentication methods for the account
     */
    private getAccountAuthMethods(): string[] {
        if (!this.account) return [];

        const methods: string[] = [];

        if (this.account.password) {
            methods.push('password');
        }

        // Since mfaConfig is removed from account, we check what the account supports
        // based on having phone/email for 2FA
        if (this.account.phone) {
            methods.push('sms');
        }

        if (this.account.email) {
            methods.push('email_2fa');
        }

        return methods;
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
            newDevice: this.isNewDevice,
            projectMfa: this.project?.settings?.mfa.enabled
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
            profile: this.account.profile || {},
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

        // Add session duration from project settings
        const sessionDuration = this.project?.settings?.sessionManagement?.maxSessionDurationHours || 8;
        const idleTimeout = this.project?.settings?.sessionManagement?.idleTimeoutMinutes || 15;


        // Create session
        this.session = new Session({
            accountId: this.account._id,
            deviceInfo: {
                deviceId: this.requestData.deviceInfo.fingerprint?.hash,
                deviceType: this.requestData.deviceInfo.deviceType || 'unknown',
                os: this.requestData.deviceInfo.os,
                browser: this.requestData.deviceInfo.browser,
                userAgent: this.requestData.deviceInfo.userAgent,
            },
            location: {
                ip: this.clientIP,
                country: this.deviceLocation?.country,
            },
            securityContext: {
                riskScore: this.calculateRiskScore(),
                riskFactors: this.securityAlerts,
                isTrusted: !this.isNewDevice,
                requiresMfa: this.project?.settings?.mfa.enabled || false,
                mfaCompleted: this.project?.settings?.mfa.enabled || false,
                authenticationMethod: 'password',
                strongAuthentication: this.project?.settings?.mfa.enabled || false
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
                : new Date(Date.now() + sessionDuration * 60 * 60 * 1000), // Use project setting

            idleTimeoutAt: new Date(Date.now() + idleTimeout * 60 * 1000),
            maxConcurrentAllowed: maxConcurrentSessions,
            metadata: {
                loginMethod: this.project?.settings?.mfa.enabled ? '2fa' : 'password',
                browserInfo: {
                    userAgent: this.requestData.deviceInfo.userAgent,
                    browser: this.requestData.deviceInfo.browser,
                    os: this.requestData.deviceInfo.os
                },
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
                    recipient: this.account!.phone
                }
            } : {
                email: {
                    subject: 'Login Verification Code',
                    template: 'login-2fa',
                    data: {
                        name: this.account!.profile.firstName || 'User',
                        expiryMinutes: 3,
                        location: this.deviceLocation?.country || 'Unknown',
                        device: this.requestData.deviceInfo.os,
                        email: this.account!.email,

                        // Additional placeholders
                        otp: otpCode,
                        login_time: new Date().toISOString(),
                        ip_address: this.clientIP,
                        location_info: this.deviceLocation?.country || 'Unknown',
                        device_info: `${this.requestData.deviceInfo.browser} on ${this.requestData.deviceInfo.os}`,
                        user_email: this.account!.email || 'Unknown',
                        login_url: `${process.env.APP_URL}/login`,
                        help_url: `${process.env.APP_URL}/help`,
                        privacy_url: `${process.env.APP_URL}/privacy`,
                        security_url: `${process.env.APP_URL}/account/security`,
                        unsubscribe_url: `${process.env.APP_URL}/unsubscribe`,
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

    /**
     * Get preferred 2FA method based on project and account
     */
    private getPreferred2FAMethod(availableMethods: Array<'sms' | 'email' | 'totp'>): 'sms' | 'email' | 'totp' {
        // Priority: SMS > Email > TOTP (most user-friendly first)
        if (availableMethods.includes('sms')) return 'sms';
        if (availableMethods.includes('email')) return 'email';
        return 'totp';
    }

    private maskContact(method: 'sms' | 'email' | 'totp'): string {
        if (!this.account) return '';

        if (method === 'sms') {
            const phone = this.account.phone || '';
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