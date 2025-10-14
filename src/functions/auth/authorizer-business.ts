import { APIGatewayTokenAuthorizerEvent, APIGatewayAuthorizerResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { createLogger } from '../../utils/logger';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import jwt, { JsonWebTokenError, TokenExpiredError, JwtPayload } from 'jsonwebtoken';
import { Account, IAccount } from '../../models/account.schema';
import { Session, ISession } from '../../models/sessions.schema';

// ==================== INTERFACES ====================

interface AuthorizerRequest {
    token: string;
    methodArn: string;
}

interface AuthorizerResponseData {
    principalId: string;
    policyDocument: {
        Version: string;
        Statement: Array<{
            Action: string;
            Effect: 'Allow' | 'Deny';
            Resource: string;
        }>;
    };
    context?: {
        accountId: string;
        email?: string;
        phone?: string;
        accountStatus: string;
        firstName?: string;
        lastName?: string;
        displayName?: string;
        roles?: string;
        permissions?: string;
        sessionId?: string;
        tokenType: string;
        lastLogin?: string;
    };
}

interface JWTPayload extends JwtPayload {
    accountId: string;
    type: 'access' | 'refresh';
    sessionId?: string;
}

// ==================== BUSINESS HANDLER CLASS ====================

class AuthorizerBusinessHandler {
    private requestData: AuthorizerRequest;
    private event: APIGatewayTokenAuthorizerEvent;
    private logger: ReturnType<typeof createLogger>;

    // Environment variables
    private readonly JWT_SECRET: string;

    // Data holders
    private decodedToken?: JWTPayload;
    private account?: IAccount;
    private session?: ISession;

    constructor(event: APIGatewayTokenAuthorizerEvent, requestData: AuthorizerRequest) {
        const requestId = 'auth-' + Date.now();
        this.event = event;
        this.requestData = requestData;

        // Get environment variables
        this.JWT_SECRET = process.env.JWT_SECRET || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            methodArn: event.methodArn,
            tokenType: 'access', // Default for authorizer
            functionName: 'authorizer'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<AuthorizerResponseData> {
        this.logger.info('Starting token authorization process');

        try {
            // Step 1: Validate request data
            this.validateRequestData();

            // Step 2: Decode and verify JWT token
            await this.verifyToken();

            // Step 3: Load account information
            await this.loadAccount();

            // Step 4: Load session information (optional)
            await this.loadSession();

            // Step 5: Additional security checks
            await this.performSecurityChecks();

            // Step 6: Build authorization response
            return this.buildAuthorizerResponse('Allow');

        } catch (error) {
            this.logger.error('Token authorization failed', {
                error: error instanceof Error ? error.message : 'Unknown error'
            });

            // Return deny response for any authorization failure
            return this.buildAuthorizerResponse('Deny');
        }
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating authorizer request data');

        if (!this.requestData.token) {
            throw new HttpError('Token is required', 401);
        }

        if (!this.requestData.token.trim()) {
            throw new HttpError('Token cannot be empty', 401);
        }

        // Basic JWT format check (should have 3 parts separated by dots)
        const tokenParts = this.requestData.token.split('.');
        if (tokenParts.length !== 3) {
            throw new HttpError('Invalid token format', 401);
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

            const tokenType = unverifiedPayload.type || 'access';

            // Only allow access tokens for API Gateway authorization
            if (tokenType !== 'access') {
                throw new HttpError('Invalid token type for authorization', 401);
            }

            // Choose the correct secret (access tokens use JWT_SECRET)
            const secret = this.JWT_SECRET;

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
     * Step 3: Load account information
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
     * Step 4: Load session information (optional for authorizer)
     */
    private async loadSession(): Promise<void> {
        if (!this.decodedToken?.accountId) return;

        this.logger.debug('Loading session information');

        // Try to find session by token
        const sessionData = await Session.findOne({
            accountId: this.decodedToken.accountId,
            accessToken: this.requestData.token,
            isActive: true
        });

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

        // Log authorization for security monitoring
        if (this.account) {
            this.logger.debug('Security checks passed');
        }
    }

    /**
     * Step 6: Build authorization response
     */
    private buildAuthorizerResponse(effect: 'Allow' | 'Deny'): AuthorizerResponseData {
        const response: AuthorizerResponseData = {
            principalId: this.decodedToken?.accountId || 'unauthorized',
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: effect,
                        Resource: this.requestData.methodArn
                    }
                ]
            }
        };

        // Include account context if authorization is allowed and account is loaded
        if (effect === 'Allow' && this.account && this.decodedToken) {
            response.context = {
                accountId: String(this.account._id),
                email: this.account.email || '',
                phone: this.account.phone || '',
                accountStatus: this.account.accountStatus.status,
                firstName: this.account.profile?.firstName || '',
                lastName: this.account.profile?.lastName || '',
                displayName: this.account.profile?.displayName || '',
                sessionId: this.session?.sessionId || '',
                tokenType: this.decodedToken.type,
                lastLogin: this.account.lastLogin?.toISOString() || ''
            };
        }

        return response;
    }
}

// ==================== LAMBDA HANDLER ====================

export const AuthorizerHandler = async (event: APIGatewayTokenAuthorizerEvent): Promise<APIGatewayAuthorizerResult> => {
    const requestId = 'auth-' + Date.now();
    const logger = createLogger('auth-service', requestId);

    logger.appendPersistentKeys({
        methodArn: event.methodArn,
        functionName: 'authorizer'
    });

    logger.info('Lambda authorizer started');

    try {
        // Extract token from authorization token
        const token = event.authorizationToken?.replace('Bearer ', '') || event.authorizationToken;

        if (!token) {
            throw new HttpError('No authorization token provided', 401);
        }

        const authorizerRequest: AuthorizerRequest = {
            token,
            methodArn: event.methodArn
        };

        // Connect to database
        await connectDB();

        // Process authorization
        const businessHandler = new AuthorizerBusinessHandler(event, authorizerRequest);
        const result = await businessHandler.processRequest();

        logger.info('Lambda authorizer completed successfully', {
            principalId: result.principalId,
            effect: result.policyDocument.Statement[0].Effect,
            accountId: result.context?.accountId
        });

        logger.logBusinessEvent('AUTHORIZATION_SUCCESS', {
            operationType: 'authorization',
            principalId: result.principalId,
            effect: result.policyDocument.Statement[0].Effect,
            accountId: result.context?.accountId
        });

        return result;

    } catch (error) {
        logger.error('Lambda authorizer failed', {
            error: error instanceof Error ? error.message : 'Unknown error'
        });

        logger.logBusinessEvent('AUTHORIZATION_FAILED', {
            operationType: 'authorization',
            error: error instanceof Error ? error.message : 'Unknown error'
        });

        // Return deny policy for any error
        return {
            principalId: 'unauthorized',
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: 'Deny',
                        Resource: event.methodArn
                    }
                ]
            }
        };
    }
};