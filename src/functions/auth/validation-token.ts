import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import jwt, { JsonWebTokenError, TokenExpiredError, JwtPayload } from 'jsonwebtoken';
import { Account, IAccount } from '../../models/account.schema';
import { Session, ISession } from '../../models/sessions.schema';

// ==================== INTERFACES ====================

interface TokenValidationRequest {
    token: string;
    tokenType?: 'access' | 'refresh';
    includeAccountInfo?: boolean;
    includeSessionInfo?: boolean;
    checkSessionActive?: boolean;
}

interface TokenValidationResponseData {
    valid: boolean;
    tokenType: 'access' | 'refresh';
    accountId?: string;
    sessionId?: string;
    expiresAt?: Date;
    issuedAt?: Date;
    remainingTime?: number;
    invalidReason?: string; // Added to help debug why token is invalid

    account?: {
        accountId: string;
        email?: string;
        phone?: string;
        accountStatus: any;
        profile: {
            firstName?: string;
            lastName?: string;
            displayName?: string;
            avatar?: string;
        };
        roles?: string[];
        permissions?: string[];
        lastLogin?: Date;
    };

    session?: {
        sessionId: string;
        isActive: boolean;
        status: string;
        deviceInfo?: {
            deviceType?: string;
            os?: string;
            browser?: string;
        };
        location?: {
            ip?: string;
            country?: string;
        };
        createdAt?: Date;
        lastActivityAt?: Date;
        expiresAt?: Date;
        isPersistent?: boolean;
        terminatedAt?: Date;
        terminationReason?: string;
    };

    securityContext?: {
        riskScore?: number;
        isTrusted?: boolean;
        requiresMfa?: boolean;
        newDevice?: boolean;
    };
}

interface JWTPayload extends JwtPayload {
    accountId: string;
    type: 'access' | 'refresh';
    sessionId?: string;
}

// ==================== BUSINESS HANDLER CLASS ====================

class TokenValidationBusinessHandler {
    private requestData: TokenValidationRequest;
    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;

    private readonly JWT_SECRET: string;
    private readonly REFRESH_TOKEN_SECRET: string;

    private decodedToken?: JWTPayload;
    private account?: IAccount;
    private session?: ISession;
    private clientIP: string = '';
    private invalidReason?: string;

    constructor(event: APIGatewayProxyEvent, requestData: TokenValidationRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = requestData;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

        this.JWT_SECRET = process.env.JWT_SECRET || '';
        this.REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            tokenType: this.requestData.tokenType || 'unknown',
            functionName: 'validateToken'
        });
    }

    async processRequest(): Promise<TokenValidationResponseData> {
        this.logger.info('Starting token validation process');

        try {
            this.validateRequestData();
            await this.verifyToken();
            
            // CRITICAL: Always check session status for logout detection
            await this.checkSessionStatus();
            
            if (this.requestData.includeAccountInfo) {
                await this.loadAccount();
            }

            await this.performSecurityChecks();
            return this.buildValidationResponse();

        } catch (error) {
            this.logger.error('Token validation failed', { 
                error: error instanceof Error ? error.message : 'Unknown error',
                invalidReason: this.invalidReason 
            });

            return {
                valid: false,
                tokenType: this.requestData.tokenType || 'access',
                invalidReason: this.invalidReason || (error instanceof Error ? error.message : 'Unknown error')
            };
        }
    }

    private validateRequestData(): void {
        this.logger.debug('Validating token validation request data');

        if (!this.requestData.token) {
            this.invalidReason = 'Token is required';
            throw new HttpError('Token is required', 400);
        }

        if (!this.requestData.token.trim()) {
            this.invalidReason = 'Token cannot be empty';
            throw new HttpError('Token cannot be empty', 400);
        }

        const tokenParts = this.requestData.token.split('.');
        if (tokenParts.length !== 3) {
            this.invalidReason = 'Invalid token format';
            throw new HttpError('Invalid token format', 400);
        }

        this.logger.debug('Request validation completed');
    }

    private async verifyToken(): Promise<void> {
        this.logger.debug('Verifying JWT token');

        try {
            const unverifiedPayload = jwt.decode(this.requestData.token) as JWTPayload;

            if (!unverifiedPayload || typeof unverifiedPayload !== 'object') {
                this.invalidReason = 'Invalid token payload';
                throw new HttpError('Invalid token payload', 401);
            }

            const tokenType = unverifiedPayload.type || this.requestData.tokenType || 'access';
            const secret = tokenType === 'refresh' ? this.REFRESH_TOKEN_SECRET : this.JWT_SECRET;

            if (!secret) {
                this.invalidReason = 'Token validation configuration error';
                throw new HttpError('Token validation configuration error', 500);
            }

            const payload = jwt.verify(this.requestData.token, secret) as JWTPayload;

            if (!payload.accountId) {
                this.invalidReason = 'Token missing required claims';
                throw new HttpError('Token missing required claims', 401);
            }

            this.decodedToken = {
                ...payload,
                type: tokenType
            };

            this.logger.debug('Token verification successful', {
                accountId: this.decodedToken.accountId,
                tokenType: this.decodedToken.type,
                sessionId: this.decodedToken.sessionId
            });

        } catch (error) {
            if (error instanceof TokenExpiredError) {
                this.invalidReason = 'Token has expired';
                this.logger.warn('Token has expired', { expiredAt: error.expiredAt });
                throw new HttpError('Token has expired', 401);
            } else if (error instanceof JsonWebTokenError) {
                this.invalidReason = 'Invalid token signature';
                this.logger.warn('Invalid token signature or format', { error: error.message });
                throw new HttpError('Invalid token', 401);
            } else {
                this.invalidReason = 'Token verification failed';
                this.logger.error('Token verification error', {
                    error: error instanceof Error ? error.message : 'Unknown error'
                });
                throw new HttpError('Token validation failed', 401);
            }
        }
    }

    /**
     * CRITICAL: Check if the session exists and is still active
     * This catches logout scenarios where the session was terminated
     */
    private async checkSessionStatus(): Promise<void> {
        if (!this.decodedToken?.accountId) return;

        this.logger.debug('Checking session status for logout detection');

        // Search for the session without the isActive filter first
        // to see if it exists but was terminated (logout)
        const sessionQuery: any = {
            accountId: this.decodedToken.accountId,
            $or: [
                { accessToken: this.requestData.token },
                { 'refreshTokens.token': this.requestData.token }
            ]
        };

        const sessionData = await Session.findOne(sessionQuery);

        if (!sessionData) {
            // Session not found - token might be invalid or revoked
            this.invalidReason = 'Session not found - token may have been revoked';
            this.logger.warn('Session not found for token', {
                accountId: this.decodedToken.accountId,
                tokenType: this.decodedToken.type
            });
            throw new HttpError('Session not found or has been revoked', 401);
        }

        this.session = sessionData;

        // Check if user logged out (session terminated)
        if (!this.session.isActive || this.session.status === 'terminated') {
            this.invalidReason = `Session was terminated: ${this.session.terminationReason || 'logout'}`;
            this.logger.warn('Token belongs to terminated session (user logged out)', {
                sessionId: this.session.sessionId,
                status: this.session.status,
                terminationReason: this.session.terminationReason,
                terminatedAt: this.session.terminatedAt,
                terminatedBy: this.session.terminatedBy
            });
            throw new HttpError('Session has been terminated - user logged out', 401);
        }

        // Check if session is expired
        if (this.session.expiresAt && this.session.expiresAt < new Date()) {
            this.invalidReason = 'Session has expired';
            this.logger.warn('Session has expired', {
                sessionId: this.session.sessionId,
                expiresAt: this.session.expiresAt
            });
            throw new HttpError('Session has expired', 401);
        }

        // Check session status
        if (this.session.status !== 'active') {
            this.invalidReason = `Session is ${this.session.status}`;
            this.logger.warn('Session is not active', {
                sessionId: this.session.sessionId,
                status: this.session.status
            });
            throw new HttpError(`Session is ${this.session.status}`, 401);
        }

        // For refresh tokens, check if the specific token is revoked
        if (this.decodedToken.type === 'refresh') {
            const refreshToken = this.session.refreshTokens.find(
                rt => rt.token === this.requestData.token
            );

            if (refreshToken?.isRevoked) {
                this.invalidReason = `Refresh token was revoked: ${refreshToken.revokedReason || 'unknown'}`;
                this.logger.warn('Refresh token was revoked', {
                    sessionId: this.session.sessionId,
                    revokedAt: refreshToken.revokedAt,
                    revokedReason: refreshToken.revokedReason
                });
                throw new HttpError('Refresh token has been revoked', 401);
            }
        }

        // Update last activity
        this.session.lastActivityAt = new Date();
        await this.session.save();

        this.logger.debug('Session status check passed - session is active', {
            sessionId: this.session.sessionId,
            status: this.session.status,
            isActive: this.session.isActive
        });
    }

    private async loadAccount(): Promise<void> {
        if (!this.decodedToken?.accountId) return;

        this.logger.debug('Loading account information');

        const accountData = await Account.findById(this.decodedToken.accountId);

        if (!accountData) {
            this.invalidReason = 'Account not found';
            throw new HttpError('Account not found', 404);
        }

        this.account = accountData;

        if (this.account.accountStatus.status === 'deactivated') {
            this.invalidReason = 'Account has been deactivated';
            throw new HttpError('Account has been deactivated', 403);
        }

        if (this.account.accountStatus.status === 'suspended') {
            this.invalidReason = 'Account is suspended';
            throw new HttpError('Account is suspended', 403);
        }

        this.logger.debug('Account loaded successfully', {
            accountId: this.account._id,
            accountStatus: this.account.accountStatus
        });
    }

    private async performSecurityChecks(): Promise<void> {
        this.logger.debug('Performing security checks');

        if (this.account?.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
            this.invalidReason = 'Account is currently locked';
            throw new HttpError('Account is currently locked', 423);
        }

        this.logger.debug('Security checks passed');
    }

    private buildValidationResponse(): TokenValidationResponseData {
        if (!this.decodedToken) {
            throw new Error('Token not decoded');
        }

        const response: TokenValidationResponseData = {
            valid: true,
            tokenType: this.decodedToken.type,
            accountId: this.decodedToken.accountId,
            sessionId: this.session?.sessionId,
            expiresAt: this.decodedToken.exp ? new Date(this.decodedToken.exp * 1000) : undefined,
            issuedAt: this.decodedToken.iat ? new Date(this.decodedToken.iat * 1000) : undefined,
            remainingTime: this.decodedToken.exp ? Math.max(0, this.decodedToken.exp - Math.floor(Date.now() / 1000)) : undefined
        };

        if (this.requestData.includeAccountInfo && this.account) {
            response.account = {
                accountId: String(this.account._id),
                email: this.account.email,
                phone: this.account.phone,
                accountStatus: this.account.accountStatus,
                profile: this.account.profile || {},
                lastLogin: this.account.lastLogin
            };
        }

        if (this.requestData.includeSessionInfo && this.session) {
            response.session = {
                sessionId: this.session.sessionId,
                isActive: this.session.isActive,
                status: this.session.status,
                deviceInfo: {
                    deviceType: this.session.deviceInfo?.deviceType,
                    os: this.session.deviceInfo?.os,
                    browser: this.session.deviceInfo?.browser
                },
                location: {
                    ip: this.session.location?.ip,
                    country: this.session.location?.country
                },
                createdAt: this.session.createdAt,
                lastActivityAt: this.session.lastActivityAt,
                expiresAt: this.session.expiresAt,
                isPersistent: this.session.isPersistent,
                terminatedAt: this.session.terminatedAt,
                terminationReason: this.session.terminationReason
            };
        }

        if (this.session?.securityContext) {
            response.securityContext = {
                riskScore: this.session.securityContext.riskScore,
                isTrusted: this.session.securityContext.isTrusted,
                requiresMfa: this.session.securityContext.requiresMfa,
                newDevice: this.session.metadata?.newDevice
            };
        }

        return response;
    }
}

// ==================== LAMBDA HANDLER ====================

const TokenValidationHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Token validation handler started');

    try {
        let tokenRequest: TokenValidationRequest;

        if (event.httpMethod === 'POST' && event.body) {
            const body = JSON.parse(event.body);
            tokenRequest = {
                token: body.token,
                tokenType: body.tokenType,
                includeAccountInfo: body.includeAccountInfo || false,
                includeSessionInfo: body.includeSessionInfo || false,
                checkSessionActive: body.checkSessionActive !== false // Default to true
            };
        } else {
            const authHeader = event.headers?.Authorization || event.headers?.authorization;
            if (!authHeader) {
                throw new HttpError('Authorization header is required', 401);
            }

            const token = authHeader.startsWith('Bearer ')
                ? authHeader.substring(7)
                : authHeader;

            tokenRequest = {
                token,
                tokenType: 'access',
                includeAccountInfo: event.queryStringParameters?.includeAccountInfo === 'true',
                includeSessionInfo: event.queryStringParameters?.includeSessionInfo === 'true',
                checkSessionActive: true // Always check session for header-based validation
            };
        }

        // ALWAYS connect to database to check session status
        await connectDB();

        const businessHandler = new TokenValidationBusinessHandler(event, tokenRequest);
        const result = await businessHandler.processRequest();

        logger.info('Token validation handler completed successfully', {
            valid: result.valid,
            tokenType: result.tokenType,
            accountId: result.accountId
        });

        logger.logBusinessEvent('TOKEN_VALIDATION_SUCCESS', {
            operationType: 'token_validation',
            tokenType: result.tokenType,
            accountId: result.accountId,
            valid: result.valid
        });

        return SuccessResponse({
            message: result.valid ? 'Token is valid' : 'Token is invalid',
            data: result
        });

    } catch (error) {
        logger.error('Token validation handler failed', {
            error: error instanceof Error ? error.message : 'Unknown error'
        });

        logger.logBusinessEvent('TOKEN_VALIDATION_FAILED', {
            operationType: 'token_validation',
            error: error instanceof Error ? error.message : 'Unknown error'
        });

        if (error instanceof HttpError && [400, 422].includes(error.statusCode)) {
            throw error;
        }

        return SuccessResponse({
            message: 'Token validation failed',
            data: {
                valid: false,
                tokenType: 'access',
                invalidReason: error instanceof Error ? error.message : 'Unknown error'
            }
        });
    }
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(TokenValidationHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});