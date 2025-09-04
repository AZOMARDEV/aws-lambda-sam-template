import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import bcrypt from 'bcryptjs';
import { Account, IAccount } from '../../models/account.schema';
import { TempAccount, ITempAccount } from '../../models/temp_account.schema';
import { VerificationCode } from '../../models/verification_codes.schema';
import { Session, ISession } from '../../models/sessions.schema';
import { SQSService } from '../../utils/lambdaSqs';
import jwt, { SignOptions } from 'jsonwebtoken';
import ProjectModel, { IProjectSettings } from '../../models/project.schema';

// ==================== INTERFACES ====================

interface CombinedAuthRequest {
    // Primary identifier - one required
    email?: string;
    phone?: string;

    tempId: string;

    // Password (optional for first-time users)
    password: string;

    // Profile information (required for new registrations)
    firstName: string;
    lastName: string;
    displayName: string;
    dateOfBirth?: string;

    gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
    language?: string;
    timezone?: string;
    country?: string;

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

    // Compliance (for new registrations)
    termsAccepted?: boolean;
    privacyPolicyAccepted?: boolean;
    termsVersion?: string;
    privacyVersion?: string;

    // Optional flags
    rememberMe?: boolean;
}

interface CombinedAuthResponseData {
    success: boolean;
    authFlow: 'login_success' | 'registration_pending' | 'profile_completion_required' | 'requires_2fa' | 'account_locked';
    message: string;

    // Successful login data
    accessToken?: string;
    refreshToken?: string;
    expiresIn?: number;
    sessionId?: string;

    // Registration/profile completion data
    tempId?: string;
    profileCompletionToken?: string;
    nextStep?: {
        action: 'verify_email' | 'verify_phone' | 'complete_profile';
        identifier?: string;
        expiresIn?: number;
        requiredFields?: string[];
    };

    // 2FA data
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
        isComplete?: boolean;
        completionPercentage?: number;
    };

    // Security/status info
    lastLogin?: Date;
    newDevice?: boolean;
    securityAlerts?: string[];
    verificationRequired?: {
        email: boolean;
        phone: boolean;
    };
    accountCreated?: boolean;
    isNewUser?: boolean;
}

// ==================== BUSINESS HANDLER CLASS ====================

class CombinedAuthBusinessHandler {
    private requestData: CombinedAuthRequest;
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
    private securityAlerts: string[] = [];
    private authFlow: 'login' | 'register' | 'profile_completion' | '2fa_verification' = 'login';

    constructor(event: APIGatewayProxyEvent, body: CombinedAuthRequest) {
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
            functionName: 'combined-auth'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<CombinedAuthResponseData> {
        this.logger.info('Starting combined auth process');


        // Step 2: Load project configuration
        await this.loadProjectConfiguration();

        // Step 1: Basic validation
        this.validateRequestData();

        return await this.handleProfileCompletion();

    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating registration request data');

        if (!this.project?.settings?.mfa.enabled) {
            this.logger.error('MFA configuration is missing');
            throw new HttpError('MFA configuration not found', 500);
        }

        // Get required fields from the settings
        const requiredFields: string[] = this.project.settings.mfa.profileCompletionFields || ['firstName', 'lastName', 'email'];

        // Optional: map custom messages dynamically
        const customMessages: Record<string, string> = requiredFields.reduce((acc, field) => {
            acc[field] = `${this.formatFieldName(field)} is required`;
            return acc;
        }, {} as Record<string, string>);

        validateRequiredFields(this.requestData, requiredFields, customMessages);


        this.logger.debug('Request validation completed');
    }

    // Helper to prettify field names for messages
    private formatFieldName(field: string): string {
        return field
            .replace(/([A-Z])/g, ' $1') // split camelCase
            .replace(/^./, str => str.toUpperCase()); // capitalize first letter
    }


    /**
     * Step 2: Load project configuration
     */
    private async loadProjectConfiguration(): Promise<void> {
        this.logger.debug('Loading project configuration');

        const project = await ProjectModel.findOne({ category: "AUTH" });

        if (!project) {
            this.logger.error('No project configuration found in database');
            throw new HttpError('Project configuration not found. Please contact support.', 500);
        }

        this.project = project;
    }

    /**
     * Handle profile completion for verified temp accounts
     */
    private async handleProfileCompletion(): Promise<CombinedAuthResponseData> {

        const tempAccount = await TempAccount.findOne({
            tempId: this.requestData.tempId,
            status: { $in: ['verified', 'partial'] }, // Only verified temp accounts can complete profile
            expiresAt: { $gt: new Date() }
        });

        if (!tempAccount) {
            throw new HttpError('Temp account not found', 404);
        }

        this.tempAccount = tempAccount;
        this.logger.debug('Handling profile completion', {
            tempId: this.tempAccount.tempId
        });

        // Validate profile completion data
        this.validateProfileCompletionData();

        if (!this.tempAccount.profile) {
            this.tempAccount.profile = {};
        }

        // Now safe to set fields
        if (this.requestData.firstName) this.tempAccount.profile.firstName = this.requestData.firstName;
        if (this.requestData.lastName) this.tempAccount.profile.lastName = this.requestData.lastName;
        if (this.requestData.displayName) this.tempAccount.profile.displayName = this.requestData.displayName;
        if (this.requestData.dateOfBirth) this.tempAccount.profile.dateOfBirth = new Date(this.requestData.dateOfBirth);
        if (this.requestData.gender) this.tempAccount.profile.gender = this.requestData.gender;
        if (this.requestData.country) this.tempAccount.profile.country = this.requestData.country;


        // Hash password if provided
        if (this.requestData.password && !this.tempAccount?.password) {
            this.tempAccount.password = await bcrypt.hash(this.requestData.password, 12);
        }

        // Update compliance data if provided
        if (this.requestData.termsAccepted !== undefined) {
            this.tempAccount.complianceData.termsAccepted.accepted = this.requestData.termsAccepted;
            this.tempAccount.complianceData.termsAccepted.version = this.requestData.termsVersion || '1.0';
            this.tempAccount.complianceData.termsAccepted.acceptedAt = new Date();
        }

        if (this.requestData.privacyPolicyAccepted !== undefined) {
            this.tempAccount.complianceData.privacyPolicyAccepted.accepted = this.requestData.privacyPolicyAccepted;
            this.tempAccount.complianceData.privacyPolicyAccepted.version = this.requestData.privacyVersion || '1.0';
            this.tempAccount.complianceData.privacyPolicyAccepted.acceptedAt = new Date();
        }

        // Mark as complete and convert to real account
        this.tempAccount.status = 'completed';
        this.tempAccount.metadata.hasCompleteProfile = true;

        this.tempAccount.addAuditLog(
            'profile_completed',
            'User completed profile information',
            this.clientIP,
            this.requestData.deviceInfo.userAgent
        );

        await this.tempAccount.save();

        // Convert temp account to real account
        const newAccount = await this.convertTempToRealAccount();
        this.account = newAccount;

        // Complete login directly
        return await this.completeLogin(true); // true indicates new account
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
            userAgent: this.requestData.deviceInfo.userAgent,
            deviceId: this.requestData.deviceInfo.fingerprint?.hash,
            success: true,
            location: this.deviceLocation
        });

        // Manage trusted devices
        if (this.isNewDevice && this.requestData.deviceInfo.fingerprint?.hash) {
            this.account.security.trustedDevices.push(this.requestData.deviceInfo.fingerprint.hash);
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
                ...this.account.profile,
                isComplete: profileCompletion.isComplete,
                completionPercentage: profileCompletion.percentage
            },
            lastLogin: this.account.lastLogin,
            newDevice: this.isNewDevice,
            securityAlerts: this.securityAlerts,
            accountCreated: isNewAccount,
            isNewUser: isNewAccount
        };
    }

    // ==================== HELPER METHODS ====================

    private validateProfileCompletionData(): void {
        if (!this.requestData.firstName || !this.requestData.lastName) {
            throw new HttpError('First name and last name are required to complete profile', 400);
        }

        if (!this.requestData.termsAccepted || !this.requestData.privacyPolicyAccepted) {
            throw new HttpError('You must accept the terms and privacy policy to complete registration', 400);
        }
    }


    private async convertTempToRealAccount(): Promise<IAccount> {
        if (!this.tempAccount) throw new HttpError('Temp account not found', 500);

        this.logger.debug('Converting temp account to real account', {
            tempId: this.tempAccount.tempId
        });

        const accountData = {
            email: this.tempAccount.email,
            phone: this.tempAccount.phone,
            username: this.tempAccount.username,
            password: this.tempAccount.password,
            profile: this.tempAccount.profile,
            accountStatus: {
                status: 'active',
                isComplete: false,
                verificationLevel: 'basic',
                lastActive: new Date(),
                registrationDate: new Date(),
                accountType: 'standard',
                membershipTier: 'basic',
                strikeCount: 0,
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
                language: this.tempAccount?.profile?.language || 'en',
                timezone: this.tempAccount?.profile?.timezone || 'UTC',
                notifications: {
                    email: this.tempAccount?.complianceData?.marketingConsent?.email,
                    sms: this.tempAccount?.complianceData?.marketingConsent?.sms,
                    push: this.tempAccount?.complianceData?.marketingConsent?.push
                }
            },
            registrationContext: this.tempAccount?.registrationContext,
            complianceData: this.tempAccount?.complianceData,
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
            this.requestData.deviceInfo.userAgent
        );
        await this.tempAccount.save();

        this.logger.info('Temp account converted to real account', {
            tempId: this.tempAccount.tempId,
            accountId: newAccount._id
        });

        return newAccount;
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
                    userAgent: this.requestData.deviceInfo.userAgent,
                    browser: this.requestData.deviceInfo.browser,
                    os: this.requestData.deviceInfo.os
                },
                newDevice: this.isNewDevice
            }
        });

        this.session.addActivity({
            action: 'combined_auth_login',
            endpoint: this.event.path,
            method: this.event.httpMethod,
            statusCode: 200,
            userAgent: this.requestData.deviceInfo.userAgent,
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

    // Utility methods
    private getIdentifier(): string {
        return this.requestData.email || this.requestData.phone || 'unknown';
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
    logLevel: 'info'
});