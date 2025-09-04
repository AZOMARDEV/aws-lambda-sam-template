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
    remainingTime?: number; // seconds until expiration

    // Account info (if requested)
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

    // Session info (if requested)
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
    };

    // Security info
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

    // Environment variables
    private readonly JWT_SECRET: string;
    private readonly REFRESH_TOKEN_SECRET: string;

    // Data holders
    private decodedToken?: JWTPayload;
    private account?: IAccount;
    private session?: ISession;
    private clientIP: string = '';

    constructor(event: APIGatewayProxyEvent, requestData: TokenValidationRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = requestData;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

        // Get environment variables
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

    /**
     * Main processing method
     */
    async processRequest(): Promise<TokenValidationResponseData> {
        this.logger.info('Starting token validation process');

        try {
            // Step 1: Validate request data
            this.validateRequestData();

            // Step 2: Decode and verify JWT token
            await this.verifyToken();

            // Step 3: Load account if needed
            if (this.requestData.includeAccountInfo || this.requestData.checkSessionActive) {
                await this.loadAccount();
            }

            // Step 4: Load session if needed
            if (this.requestData.includeSessionInfo || this.requestData.checkSessionActive) {
                await this.loadSession();
            }

            // Step 5: Additional security checks
            await this.performSecurityChecks();

            // Step 6: Build response
            return this.buildValidationResponse();

        } catch (error) {
            this.logger.error('Token validation failed', { error: error instanceof Error ? error.message : 'Unknown error' });

            // Return invalid response for any validation failure
            return {
                valid: false,
                tokenType: this.requestData.tokenType || 'access'
            };
        }
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating token validation request data');

        if (!this.requestData.token) {
            throw new HttpError('Token is required', 400);
        }

        if (!this.requestData.token.trim()) {
            throw new HttpError('Token cannot be empty', 400);
        }

        // Basic JWT format check (should have 3 parts separated by dots)
        const tokenParts = this.requestData.token.split('.');
        if (tokenParts.length !== 3) {
            throw new HttpError('Invalid token format', 400);
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Decode and verify JWT token
     */
    private async verifyToken(): Promise<void> {
        this.logger.debug('Verifying JWT token');

        try {
            // First, try to decode without verification to get the token type
            const unverifiedPayload = jwt.decode(this.requestData.token) as JWTPayload;

            if (!unverifiedPayload || typeof unverifiedPayload !== 'object') {
                throw new HttpError('Invalid token payload', 401);
            }

            const tokenType = unverifiedPayload.type || this.requestData.tokenType || 'access';

            // Choose the correct secret based on token type
            const secret = tokenType === 'refresh' ? this.REFRESH_TOKEN_SECRET : this.JWT_SECRET;

            if (!secret) {
                throw new HttpError('Token validation configuration error', 500);
            }

            // Verify the token with the correct secret
            const payload = jwt.verify(this.requestData.token, secret) as JWTPayload;

            if (!payload.accountId) {
                throw new HttpError('Token missing required claims', 401);
            }

            this.decodedToken = {
                ...payload,
                type: tokenType
            };

            this.logger.debug('Token verification successful', {
                accountId: this.decodedToken.accountId,
                tokenType: this.decodedToken.type,
                expiresAt: this.decodedToken.exp ? new Date(this.decodedToken.exp * 1000) : undefined
            });

        } catch (error) {
            if (error instanceof TokenExpiredError) {
                this.logger.warn('Token has expired', {
                    expiredAt: error.expiredAt
                });
                throw new HttpError('Token has expired', 401);
            } else if (error instanceof JsonWebTokenError) {
                this.logger.warn('Invalid token signature or format', {
                    error: error.message
                });
                throw new HttpError('Invalid token', 401);
            } else {
                this.logger.error('Token verification error', {
                    error: error instanceof Error ? error.message : 'Unknown error'
                });
                throw new HttpError('Token validation failed', 401);
            }
        }
    }

    /**
     * Step 3: Load account if needed
     */
    private async loadAccount(): Promise<void> {
        if (!this.decodedToken?.accountId) return;

        this.logger.debug('Loading account information');

        const accountData = await Account.findById(this.decodedToken.accountId);

        if (!accountData) {
            throw new HttpError('Account not found', 404);
        }

        this.account = accountData;

        // Check if account is still active
        if (this.account.accountStatus.status === 'deactivated') {
            throw new HttpError('Account has been deactivated', 403);
        }

        if (this.account.accountStatus.status === 'suspended') {
            throw new HttpError('Account is suspended', 403);
        }

        this.logger.debug('Account loaded successfully', {
            accountId: this.account._id,
            accountStatus: this.account.accountStatus
        });
    }

    /**
     * Step 4: Load session if needed
     */
    private async loadSession(): Promise<void> {
        if (!this.decodedToken?.accountId) return;

        this.logger.debug('Loading session information');

        // Try to find session by token (for access tokens)
        const sessionData = await Session.findOne({
            accountId: this.decodedToken.accountId,
            $or: [
                { accessToken: this.requestData.token },
                { 'refreshTokens.token': this.requestData.token }
            ],
            isActive: true
        });

        if (!sessionData && this.requestData.checkSessionActive) {
            throw new HttpError('Session not found or inactive', 401);
        }


        if (sessionData) {
            this.session = sessionData;

            // Check if session is expired
            if (this.session.expiresAt && this.session.expiresAt < new Date()) {
                throw new HttpError('Session has expired', 401);
            }

            // Check if session status is active
            if (this.session.status !== 'active') {
                throw new HttpError(`Session is ${this.session.status}`, 401);
            }

            // Update last activity
            this.session.lastActivityAt = new Date();
            await this.session.save();

            this.logger.debug('Session loaded and updated', {
                sessionId: this.session.sessionId,
                status: this.session.status
            });
        }
    }

    /**
     * Step 5: Perform additional security checks
     */
    private async performSecurityChecks(): Promise<void> {
        this.logger.debug('Performing security checks');

        // Check if account is locked
        if (this.account?.security.lockedUntil && this.account.security.lockedUntil > new Date()) {
            throw new HttpError('Account is currently locked', 423);
        }

        // Log token validation for security monitoring
        if (this.account) {
            // You could add this to a security log or update account activity
            this.logger.debug('Security checks passed');
        }
    }

    /**
     * Step 6: Build validation response
     */
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

        // Include account info if requested
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

        // Include session info if requested
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
                isPersistent: this.session.isPersistent
            };
        }

        // Include security context if session available
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
        // Extract token from Authorization header or body
        let tokenRequest: TokenValidationRequest;

        if (event.httpMethod === 'POST' && event.body) {
            // Token in request body
            const body = JSON.parse(event.body);
            tokenRequest = {
                token: body.token,
                tokenType: body.tokenType,
                includeAccountInfo: body.includeAccountInfo || false,
                includeSessionInfo: body.includeSessionInfo || false,
                checkSessionActive: body.checkSessionActive || false
            };
        } else {
            // Token in Authorization header
            const authHeader = event.headers?.Authorization || event.headers?.authorization;
            if (!authHeader) {
                throw new HttpError('Authorization header is required', 401);
            }

            const token = authHeader.startsWith('Bearer ')
                ? authHeader.substring(7)
                : authHeader;

            tokenRequest = {
                token,
                tokenType: 'access', // Default for header-based validation
                includeAccountInfo: event.queryStringParameters?.includeAccountInfo === 'true',
                includeSessionInfo: event.queryStringParameters?.includeSessionInfo === 'true',
                checkSessionActive: event.queryStringParameters?.checkSessionActive === 'true'
            };
        }

        // Connect to database if account/session info is needed
        if (tokenRequest.includeAccountInfo || tokenRequest.includeSessionInfo || tokenRequest.checkSessionActive) {
            await connectDB();
        }

        // Process token validation
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

        // For token validation, we want to return a 200 with valid: false
        // rather than throwing errors, unless it's a request format issue
        if (error instanceof HttpError && [400, 422].includes(error.statusCode)) {
            throw error;
        }

        return SuccessResponse({
            message: 'Token validation failed',
            data: {
                valid: false,
                tokenType: 'access'
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