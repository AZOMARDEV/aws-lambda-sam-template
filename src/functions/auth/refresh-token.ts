import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { extractAuthData, ExtractedAuthData, SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Account, IAccount } from '../../models/account.schema';
import { Session, ISession } from '../../models/sessions.schema';
import jwt, { SignOptions } from 'jsonwebtoken';

// ==================== INTERFACES ====================

interface RefreshTokenRequest {
    refreshToken: string;

    // Optional session context
    sessionId?: string;
}

interface RefreshTokenResponseData {
    success: boolean;
    message: string;
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    sessionId: string;
    accountId: string;

    // Account info
    profile?: {
        firstName?: string;
        lastName?: string;
        displayName?: string;
        avatar?: string;
    };

    // Security info
    tokenRotated: boolean;
    sessionExtended: boolean;
    securityAlerts?: string[];
}

// ==================== BUSINESS HANDLER CLASS ====================

class RefreshTokenBusinessHandler {
    private requestData: RefreshTokenRequest;
    private authdata: ExtractedAuthData;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;

    // Environment variables
    private readonly JWT_SECRET: string;
    private readonly JWT_EXPIRES_IN: string;
    private readonly REFRESH_TOKEN_SECRET: string;

    // Data holders
    private account?: IAccount;
    private session?: ISession;
    private clientIP: string = '';
    private decodedRefreshToken?: any;
    private securityAlerts: string[] = [];
    private deviceChanged: boolean = false;

    constructor(event: APIGatewayProxyEvent, body: RefreshTokenRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
        this.authdata = extractAuthData(event.headers as Record<string, string>);
        // Get environment variables
        this.JWT_SECRET = process.env.JWT_SECRET || '';
        this.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
        this.REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            functionName: 'refreshToken'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<RefreshTokenResponseData> {
        this.logger.info('Starting refresh token process');

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Verify and decode refresh token
        await this.verifyRefreshToken();

        // Step 3: Find and validate account
        await this.findAndValidateAccount();

        // Step 4: Find and validate session
        await this.findAndValidateSession();

        // Step 5: Perform security checks
        this.performSecurityChecks();

        // Step 6: Generate new tokens and update session
        return await this.generateNewTokensAndUpdate();
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating refresh token request data');

        // Validate required fields
        validateRequiredFields(this.requestData, ['refreshToken']);

        // Validate refresh token format
        if (!this.requestData.refreshToken || typeof this.requestData.refreshToken !== 'string') {
            throw new HttpError('Invalid refresh token format', 400);
        }

        // Device info validation
        if (!this.authdata.metadata.device.os || !this.authdata.metadata.device.browser) {
            throw new HttpError('Device information is required for security purposes', 400);
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Verify and decode refresh token
     */
    private async verifyRefreshToken(): Promise<void> {
        this.logger.debug('Verifying refresh token');

        try {
            // Verify token signature and expiration
            this.decodedRefreshToken = jwt.verify(this.requestData.refreshToken, this.REFRESH_TOKEN_SECRET);

            // Validate token type
            if (this.decodedRefreshToken.type !== 'refresh') {
                throw new HttpError('Invalid token type', 401);
            }

            this.logger.debug('Refresh token verified successfully', {
                accountId: this.decodedRefreshToken.accountId,
                tokenType: this.decodedRefreshToken.type
            });

        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                this.logger.warn('Refresh token expired', {
                    expiredAt: error.expiredAt
                });
                throw new HttpError('Refresh token expired. Please login again.', 401);
            } else if (error instanceof jwt.JsonWebTokenError) {
                this.logger.warn('Invalid refresh token', {
                    error: error.message
                });
                throw new HttpError('Invalid refresh token. Please login again.', 401);
            } else {
                throw error;
            }
        }
    }

    /**
     * Step 3: Find and validate account
     */
    private async findAndValidateAccount(): Promise<void> {
        this.logger.debug('Finding and validating account');

        const accountId = this.decodedRefreshToken.accountId;

        const accountData = await Account.findOne({
            _id: accountId,
            accountStatus: { $nin: ['deactivated', 'suspended'] }
        });

        if (!accountData) {
            this.logger.warn('Account not found or invalid status', {
                accountId
            });
            throw new HttpError('Account not found or access denied', 401);
        }

        this.account = accountData;
        // Check account status
        if (this.account.accountStatus.status === 'pending_verification') {
            throw new HttpError('Account verification required', 403);
        }

        // Check if account is locked
        if (this.account.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
            const minutesRemaining = Math.ceil((this.account.security.lockedUntil.getTime() - Date.now()) / (1000 * 60));
            throw new HttpError(`Account is locked. Try again in ${minutesRemaining} minutes.`, 423);
        }

        this.logger.debug('Account validated successfully', {
            accountId: this.account._id,
            accountStatus: this.account.accountStatus
        });
    }

    /**
     * Step 4: Find and validate session
     */
    private async findAndValidateSession(): Promise<void> {
        this.logger.debug('Finding and validating session');

        // Try to find session by sessionId if provided, otherwise by refresh token
        let sessionQuery: any = {
            accountId: this.account!._id,
            isActive: true,
            status: 'active'
        };

        if (this.requestData.sessionId) {
            sessionQuery.sessionId = this.requestData.sessionId;
        } else {
            // Find session that contains this refresh token
            sessionQuery['refreshTokens.token'] = this.requestData.refreshToken;
        }

        const sessionData = await Session.findOne(sessionQuery);

        if (!sessionData) {
            this.logger.warn('Session not found or inactive', {
                accountId: this.account!._id,
                sessionId: this.requestData.sessionId
            });
            throw new HttpError('Invalid session. Please login again.', 401);
        }

        this.session = sessionData;
        // Validate session hasn't expired
        if (this.session.expiresAt && this.session.expiresAt <= new Date()) {
            this.session.terminate('expired', 'system');
            await this.session.save();
            throw new HttpError('Session expired. Please login again.', 401);
        }

        // Find the specific refresh token in the session
        const refreshTokenEntry = this.session.refreshTokens.find(rt => rt.token === this.requestData.refreshToken);

        if (!refreshTokenEntry) {
            this.logger.warn('Refresh token not found in session', {
                sessionId: this.session.sessionId
            });
            throw new HttpError('Invalid refresh token. Please login again.', 401);
        }

        // Check if refresh token is revoked
        if (refreshTokenEntry.isRevoked) {
            // Possible token theft - terminate session
            this.session.terminate('token_theft_suspected', 'system');
            await this.session.save();

            this.logger.error('Revoked refresh token used - possible token theft', {
                sessionId: this.session.sessionId,
                accountId: this.account!._id,
                tokenFamily: refreshTokenEntry.family
            });

            throw new HttpError('Security violation detected. Please login again.', 401);
        }

        // Check if refresh token has expired
        if (refreshTokenEntry.expiresAt <= new Date()) {
            throw new HttpError('Refresh token expired. Please login again.', 401);
        }

        this.logger.debug('Session validated successfully', {
            sessionId: this.session.sessionId,
            tokenFamily: refreshTokenEntry.family
        });
    }

    /**
     * Step 5: Perform security checks
     */
    private performSecurityChecks(): void {
        this.logger.debug('Performing security checks');

        if (!this.session) return;

        // Check if device characteristics have changed significantly
        const sessionDevice = this.session.deviceInfo;
        const currentDevice = this.authdata.metadata.device;

        if (sessionDevice.deviceId && currentDevice.deviceId &&
            sessionDevice.deviceId !== currentDevice.deviceId) {
            this.deviceChanged = true;
            this.securityAlerts.push('Device fingerprint changed');
        }

        // Check IP address changes (optional warning, not blocking)
        if (this.session.location.ip !== this.clientIP) {
            this.securityAlerts.push('IP address changed');
        }

        // Check for suspicious activity patterns
        const now = new Date();
        const lastActivity = this.session.lastActivityAt;
        const timeSinceLastActivity = now.getTime() - lastActivity.getTime();

        // If it's been more than 7 days since last activity, that's suspicious for a refresh
        if (timeSinceLastActivity > 7 * 24 * 60 * 60 * 1000) {
            this.securityAlerts.push('Long period of inactivity');
        }

        // Log security findings
        if (this.securityAlerts.length > 0) {
            this.logger.warn('Security alerts detected during token refresh', {
                alerts: this.securityAlerts,
                sessionId: this.session.sessionId,
                deviceChanged: this.deviceChanged
            });
        }
    }

    /**
     * Step 6: Generate new tokens and update session
     */
    private async generateNewTokensAndUpdate(): Promise<RefreshTokenResponseData> {
        if (!this.account || !this.session) {
            throw new HttpError('Account or session not found', 404);
        }

        this.logger.debug('Generating new tokens and updating session');

        // Generate new access token
        const newAccessToken = this.generateAccessToken();

        // Generate new refresh token (token rotation for security)
        const newRefreshToken = this.generateRefreshToken();

        // Find current refresh token entry
        const currentRefreshTokenEntry = this.session.refreshTokens.find(
            rt => rt.token === this.requestData.refreshToken
        );

        if (!currentRefreshTokenEntry) {
            throw new HttpError('Refresh token not found in session', 401);
        }

        // Revoke the old refresh token
        currentRefreshTokenEntry.isRevoked = true;
        currentRefreshTokenEntry.revokedAt = new Date();
        currentRefreshTokenEntry.revokedReason = 'rotated';

        // Add new refresh token to the same family
        this.session.refreshTokens.push({
            token: newRefreshToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            isRevoked: false,
            family: currentRefreshTokenEntry.family // Keep same family for rotation tracking
        });

        // Update session
        this.session.accessToken = newAccessToken;
        this.session.lastActivityAt = new Date();

        // Update security context if device changed
        if (this.deviceChanged) {
            this.session.securityContext.riskScore = this.calculateRiskScore();
            this.session.securityContext.riskFactors = this.securityAlerts;
        }

        // Add activity log
        this.session.addActivity({
            action: 'token_refresh',
            endpoint: this.event.path,
            method: this.event.httpMethod,
            statusCode: 200,
            userAgent: this.authdata.metadata.device.userAgent || 'unknown',
            ip: this.clientIP,
            timestamp: new Date(),
        });

        // Extend session expiry if it's persistent and within extension window
        let sessionExtended = false;
        if (this.session.isPersistent) {
            const timeUntilExpiry = this.session.expiresAt.getTime() - Date.now();
            const oneDayInMs = 24 * 60 * 60 * 1000;

            // If session expires within 24 hours, extend it
            if (timeUntilExpiry < oneDayInMs) {
                this.session.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Extend by 30 days
                sessionExtended = true;
            }
        }

        // Clean up old refresh tokens (keep only last 3 in each family)
        const familyTokens = this.session.refreshTokens
            .filter(rt => rt.family === currentRefreshTokenEntry.family)
            .sort((a, b) => (b.revokedAt?.getTime() ?? 0) - (a.revokedAt?.getTime() ?? 0));


        if (familyTokens.length > 3) {
            const tokensToRemove = familyTokens.slice(3);
            this.session.refreshTokens = this.session.refreshTokens.filter(
                rt => !tokensToRemove.some(tr => tr.token === rt.token)
            );
        }

        await this.session.save();

        this.logger.info('Token refresh completed successfully', {
            accountId: this.account._id,
            sessionId: this.session.sessionId,
            tokenRotated: true,
            sessionExtended,
            securityAlertsCount: this.securityAlerts.length
        });

        return {
            success: true,
            message: 'Tokens refreshed successfully',
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            expiresIn: this.parseJWTExpiration(this.JWT_EXPIRES_IN),
            sessionId: this.session.sessionId,
            accountId: String(this.account._id),
            profile: this.account.profile || {},
            tokenRotated: true,
            sessionExtended,
            securityAlerts: this.securityAlerts.length > 0 ? this.securityAlerts : undefined
        };
    }

    // ==================== HELPER METHODS ====================

    private calculateRiskScore(): number {
        let score = this.session?.securityContext.riskScore || 0;

        if (this.deviceChanged) score += 15;
        if (this.securityAlerts.includes('IP address changed')) score += 10;
        if (this.securityAlerts.includes('Long period of inactivity')) score += 20;

        return Math.min(score, 100); // Cap at 100
    }

    private generateAccessToken(): string {
        if (!this.account) throw new Error("Account is missing");

        const payload = {
            accountId: this.account._id,
            type: 'access',
            sessionId: this.session?.sessionId
        };

        const options: SignOptions = {
            expiresIn: this.JWT_EXPIRES_IN as any
        };

        return jwt.sign(payload, this.JWT_SECRET, options);
    }

    private generateRefreshToken(): string {
        if (!this.account) throw new Error("Account is missing");

        return jwt.sign(
            {
                accountId: this.account._id,
                type: 'refresh',
                sessionId: this.session?.sessionId
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

const RefreshTokenHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Refresh token handler started');

    // Parse request body
    const parsedBody = parseRequestBody<RefreshTokenRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process refresh token
    const businessHandler = new RefreshTokenBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Refresh token handler completed successfully');
    logger.logBusinessEvent('LAMBDA_SUCCESS', {
        operationType: 'refresh_token',
        accountId: result.accountId,
        sessionId: result.sessionId,
        tokenRotated: result.tokenRotated,
        sessionExtended: result.sessionExtended,
        securityAlertsCount: result.securityAlerts?.length || 0
    });

    return SuccessResponse({
        message: result.message,
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(RefreshTokenHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});