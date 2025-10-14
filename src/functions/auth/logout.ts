import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { extractAuthData, ExtractedAuthData, SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Account, IAccount } from '../../models/account.schema';
import { Session, ISession } from '../../models/sessions.schema';
import jwt from 'jsonwebtoken';

// ==================== INTERFACES ====================

interface LogoutRequest {

    // Specific session to logout
    sessionId?: string;

    // Logout type
    logoutType?: 'current' | 'all_sessions' | 'all_other_sessions';

    // Reason for logout (optional)
    reason?: 'user_initiated' | 'security' | 'admin' | 'session_timeout' | 'password_change';
}

interface LogoutResponseData {
    success: boolean;
    message: string;
    logoutType: 'current' | 'all_sessions' | 'all_other_sessions';
    sessionsTerminated: number;
    accountId?: string;

    // Security info
    securityLogout?: boolean;
    tokensRevoked?: number;

    // Session details
    terminatedSessions?: Array<{
        sessionId: string;
        deviceInfo: string;
        lastActivity: Date;
        terminationReason: string;
    }>;
}

// ==================== BUSINESS HANDLER CLASS ====================

class LogoutBusinessHandler {
    private requestData: LogoutRequest;
    private authdata: ExtractedAuthData;

    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;

    // Environment variables
    private readonly JWT_SECRET: string;
    private readonly REFRESH_TOKEN_SECRET: string;

    // Data holders
    private account: IAccount | null = null;
    private currentSession: ISession | null = null;
    private clientIP: string = '';
    private decodedToken?: any;
    private accountId?: string;

    constructor(event: APIGatewayProxyEvent, body: LogoutRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
        this.authdata = extractAuthData(event.headers as Record<string, string>);

        // Get environment variables
        this.JWT_SECRET = process.env.JWT_SECRET || '';
        this.REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || '';

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            functionName: 'logout'
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<LogoutResponseData> {
        this.logger.info('Starting logout process', {
            logoutType: this.requestData.logoutType || 'current',
            reason: this.requestData.reason || 'user_initiated'
        });

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Extract account information
        await this.extractAccountInformation();

        // Step 3: Find account (if we have accountId)
        if (this.accountId) {
            await this.findAccount();
        }

        // Step 4: Perform logout based on type
        return await this.performLogout();
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating logout request data');

        // At least token or sessionId required
        if (!this.authdata.authorization && !this.requestData.sessionId) {
            throw new HttpError('Token or sessionId is required for logout', 400);
        }

        // Validate logout type
        const validLogoutTypes = ['current', 'all_sessions', 'all_other_sessions'];
        if (this.requestData.logoutType && !validLogoutTypes.includes(this.requestData.logoutType)) {
            throw new HttpError('Invalid logout type', 400);
        }

        // Set default logout type
        if (!this.requestData.logoutType) {
            this.requestData.logoutType = 'current';
        }

        // Validate reason
        const validReasons = ['user_initiated', 'security', 'admin', 'session_timeout', 'password_change'];
        if (this.requestData.reason && !validReasons.includes(this.requestData.reason)) {
            throw new HttpError('Invalid logout reason', 400);
        }

        // Set default reason
        if (!this.requestData.reason) {
            this.requestData.reason = 'user_initiated';
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Extract account information from token or session
     */
    private async extractAccountInformation(): Promise<void> {
        this.logger.debug('Extracting account information');

        if (this.authdata.authorization) {
            await this.decodeToken();
        } else if (this.requestData.sessionId) {
            await this.findSessionById();
        }

        if (!this.accountId) {
            throw new HttpError('Unable to identify account for logout', 400);
        }

        this.logger.debug('Account information extracted', {
            accountId: this.accountId
        });
    }

    /**
     * Decode token to get account information
     */
    private async decodeToken(): Promise<void> {
        if (!this.authdata.authorization) return;

        try {
            // Try as access token first
            this.decodedToken = jwt.verify(this.authdata.authorization, this.JWT_SECRET);
            this.accountId = this.decodedToken.accountId;

            this.logger.debug('Token decoded as access token', {
                tokenType: this.decodedToken.type,
                accountId: this.accountId
            });

        } catch (accessTokenError) {
            try {
                // Try as refresh token
                this.decodedToken = jwt.verify(this.authdata.authorization, this.REFRESH_TOKEN_SECRET);
                this.accountId = this.decodedToken.accountId;

                this.logger.debug('Token decoded as refresh token', {
                    tokenType: this.decodedToken.type,
                    accountId: this.accountId
                });

            } catch (refreshTokenError) {
                // Token might be expired or invalid, but we can still try to extract accountId
                try {
                    // Decode without verification to get accountId
                    const decoded = jwt.decode(this.authdata.authorization) as any;
                    if (decoded && decoded.accountId) {
                        this.accountId = decoded.accountId;
                        this.logger.warn('Used expired/invalid token for logout - extracted accountId', {
                            accountId: this.accountId
                        });
                    } else {
                        throw new HttpError('Invalid token format', 400);
                    }
                } catch (decodeError) {
                    throw new HttpError('Invalid token provided for logout', 400);
                }
            }
        }
    }

    /**
     * Find session by sessionId to get account information
     */
    private async findSessionById(): Promise<void> {
        if (!this.requestData.sessionId) return;

        const session = await Session.findOne({
            sessionId: this.requestData.sessionId,
            isActive: true
        });

        if (!session) {
            throw new HttpError('Session not found', 404);
        }

        this.accountId = session.accountId.toString();
        this.currentSession = session;
    }

    /**
     * Step 3: Find account
     */
    private async findAccount(): Promise<void> {
        if (!this.accountId) return;

        this.logger.debug('Finding account');

        this.account = await Account.findOne({
            _id: this.accountId
        });

        if (!this.account) {
            this.logger.warn('Account not found during logout', {
                accountId: this.accountId
            });
            // Don't throw error - we can still proceed with session cleanup
        }

        this.logger.debug('Account lookup completed', {
            accountId: this.accountId,
            accountFound: !!this.account
        });
    }

    /**
     * Step 4: Perform logout based on type
     */
    private async performLogout(): Promise<LogoutResponseData> {
        if (!this.accountId) {
            throw new HttpError('Account ID not found', 400);
        }

        this.logger.debug('Performing logout', {
            logoutType: this.requestData.logoutType,
            accountId: this.accountId
        });

        let terminatedSessions: Array<{
            sessionId: string;
            deviceInfo: string;
            lastActivity: Date;
            terminationReason: string;
        }> = [];
        let sessionsTerminated = 0;
        let tokensRevoked = 0;

        switch (this.requestData.logoutType) {
            case 'current':
                const currentResult = await this.logoutCurrentSession();
                terminatedSessions = currentResult.terminatedSessions;
                sessionsTerminated = currentResult.sessionsTerminated;
                tokensRevoked = currentResult.tokensRevoked;
                break;

            case 'all_sessions':
                const allResult = await this.logoutAllSessions();
                terminatedSessions = allResult.terminatedSessions;
                sessionsTerminated = allResult.sessionsTerminated;
                tokensRevoked = allResult.tokensRevoked;
                break;

            case 'all_other_sessions':
                const otherResult = await this.logoutAllOtherSessions();
                terminatedSessions = otherResult.terminatedSessions;
                sessionsTerminated = otherResult.sessionsTerminated;
                tokensRevoked = otherResult.tokensRevoked;
                break;
        }

        // Update account last logout time
        // if (this.account) {
        //     // this.account.lastLogout = new Date();
        //     // await this.account.save();
        // }

        this.logger.info('Logout completed successfully', {
            accountId: this.accountId,
            logoutType: this.requestData.logoutType,
            sessionsTerminated,
            tokensRevoked,
            reason: this.requestData.reason
        });

        return {
            success: true,
            message: this.getLogoutMessage(),
            logoutType: this.requestData.logoutType!,
            sessionsTerminated,
            accountId: this.accountId,
            securityLogout: this.requestData.reason === 'security',
            tokensRevoked,
            terminatedSessions: terminatedSessions.length > 0 ? terminatedSessions : undefined
        };
    }

    /**
     * Logout current session only
     */
    private async logoutCurrentSession(): Promise<{
        terminatedSessions: Array<{
            sessionId: string;
            deviceInfo: string;
            lastActivity: Date;
            terminationReason: string;
        }>;
        sessionsTerminated: number;
        tokensRevoked: number;
    }> {
        this.logger.debug('Logging out current session');

        let session: ISession | null = this.currentSession;

        // If we don't have current session, find it by token or sessionId
        if (!session) {
            if (this.requestData.sessionId) {
                session = await Session.findOne({
                    sessionId: this.requestData.sessionId,
                    accountId: this.accountId,
                    isActive: true
                });
            } else if (this.decodedToken?.sessionId) {
                session = await Session.findOne({
                    sessionId: this.decodedToken.sessionId,
                    accountId: this.accountId,
                    isActive: true
                });
            } else {
                // Find session by access token
                session = await Session.findOne({
                    accessToken: this.authdata.authorization,
                    accountId: this.accountId,
                    isActive: true
                });
            }
        }

        if (!session) {
            this.logger.warn('No active session found to logout');
            return {
                terminatedSessions: [],
                sessionsTerminated: 0,
                tokensRevoked: 0
            };
        }

        // Add logout activity
        session.addActivity({
            action: 'logout',
            endpoint: this.event.path,
            method: this.event.httpMethod,
            statusCode: 200,
            userAgent: this.authdata.metadata.device.userAgent || 'unknown',
            ip: this.clientIP,
            timestamp: new Date()
        });

        // Terminate session
        session.terminate(this.requestData.reason!, 'user');
        await session.save();

        const tokensRevoked = session.refreshTokens.filter(rt => !rt.isRevoked).length;

        const terminatedSession = {
            sessionId: session.sessionId,
            deviceInfo: this.formatDeviceInfo(session.deviceInfo),
            lastActivity: session.lastActivityAt,
            terminationReason: this.requestData.reason!
        };

        return {
            terminatedSessions: [terminatedSession],
            sessionsTerminated: 1,
            tokensRevoked
        };
    }

    /**
     * Logout all sessions for the account
     */
    private async logoutAllSessions(): Promise<{
        terminatedSessions: Array<{
            sessionId: string;
            deviceInfo: string;
            lastActivity: Date;
            terminationReason: string;
        }>;
        sessionsTerminated: number;
        tokensRevoked: number;
    }> {
        this.logger.debug('Logging out all sessions');

        const sessions = await Session.find({
            accountId: this.accountId,
            isActive: true,
            status: 'active'
        });

        if (sessions.length === 0) {
            return {
                terminatedSessions: [],
                sessionsTerminated: 0,
                tokensRevoked: 0
            };
        }

        let totalTokensRevoked = 0;
        const terminatedSessions: Array<{
            sessionId: string;
            deviceInfo: string;
            lastActivity: Date;
            terminationReason: string;
        }> = [];

        // Terminate all sessions
        for (const session of sessions) {
            // Add logout activity
            session.addActivity({
                action: 'logout_all',
                endpoint: this.event.path,
                method: this.event.httpMethod,
                statusCode: 200,
                userAgent: this.authdata.metadata.device.userAgent || 'unknown',
                ip: this.clientIP,
                timestamp: new Date()
            });

            // Count tokens to be revoked
            totalTokensRevoked += session.refreshTokens.filter(rt => !rt.isRevoked).length;

            // Terminate session
            session.terminate(this.requestData.reason!, 'user');
            await session.save();

            terminatedSessions.push({
                sessionId: session.sessionId,
                deviceInfo: this.formatDeviceInfo(session.deviceInfo),
                lastActivity: session.lastActivityAt,
                terminationReason: this.requestData.reason!
            });
        }

        return {
            terminatedSessions,
            sessionsTerminated: sessions.length,
            tokensRevoked: totalTokensRevoked
        };
    }

    /**
     * Logout all other sessions (keep current session active)
     */
    private async logoutAllOtherSessions(): Promise<{
        terminatedSessions: Array<{
            sessionId: string;
            deviceInfo: string;
            lastActivity: Date;
            terminationReason: string;
        }>;
        sessionsTerminated: number;
        tokensRevoked: number;
    }> {
        this.logger.debug('Logging out all other sessions');

        // Find current session ID
        let currentSessionId = this.requestData.sessionId;

        if (!currentSessionId && this.decodedToken?.sessionId) {
            currentSessionId = this.decodedToken.sessionId;
        }

        if (!currentSessionId && this.authdata.authorization) {
            // Try to find session by access token
            const currentSession = await Session.findOne({
                accessToken: this.authdata.authorization,
                accountId: this.accountId,
                isActive: true
            });
            currentSessionId = currentSession?.sessionId;
        }

        // Find all sessions except current
        const query: any = {
            accountId: this.accountId,
            isActive: true,
            status: 'active'
        };

        if (currentSessionId) {
            query.sessionId = { $ne: currentSessionId };
        }

        const sessions = await Session.find(query);

        if (sessions.length === 0) {
            return {
                terminatedSessions: [],
                sessionsTerminated: 0,
                tokensRevoked: 0
            };
        }

        let totalTokensRevoked = 0;
        const terminatedSessions: Array<{
            sessionId: string;
            deviceInfo: string;
            lastActivity: Date;
            terminationReason: string;
        }> = [];

        // Terminate other sessions
        for (const session of sessions) {
            // Add logout activity
            session.addActivity({
                action: 'logout_others',
                endpoint: this.event.path,
                method: this.event.httpMethod,
                statusCode: 200,
                userAgent: this.authdata.metadata.device.userAgent || 'unknown',
                ip: this.clientIP,
                timestamp: new Date()
            });

            // Count tokens to be revoked
            totalTokensRevoked += session.refreshTokens.filter(rt => !rt.isRevoked).length;

            // Terminate session
            session.terminate(this.requestData.reason!, 'user');
            await session.save();

            terminatedSessions.push({
                sessionId: session.sessionId,
                deviceInfo: this.formatDeviceInfo(session.deviceInfo),
                lastActivity: session.lastActivityAt,
                terminationReason: this.requestData.reason!
            });
        }

        return {
            terminatedSessions,
            sessionsTerminated: sessions.length,
            tokensRevoked: totalTokensRevoked
        };
    }

    // ==================== HELPER METHODS ====================

    private formatDeviceInfo(deviceInfo: any): string {
        if (!deviceInfo) return 'Unknown Device';

        const parts = [];
        if (deviceInfo.os) parts.push(deviceInfo.os);
        if (deviceInfo.browser) parts.push(deviceInfo.browser);

        return parts.length > 0 ? parts.join(' on ') : 'Unknown Device';
    }

    private getLogoutMessage(): string {
        switch (this.requestData.logoutType) {
            case 'all_sessions':
                return 'Successfully logged out from all sessions';
            case 'all_other_sessions':
                return 'Successfully logged out from all other sessions';
            case 'current':
            default:
                return 'Successfully logged out';
        }
    }
}

// ==================== LAMBDA HANDLER ====================

const LogoutHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId || 'unknown';
    const logger = createLogger('auth-service', requestId);

    console.log(event);

    logger.appendPersistentKeys({
        httpMethod: event.httpMethod,
        path: event.path,
        userAgent: event.headers?.['User-Agent'],
        sourceIP: event.requestContext?.identity?.sourceIp
    });

    logger.info('Logout handler started');

    // Parse request body
    const parsedBody = parseRequestBody<LogoutRequest>(event, logger);

    // Connect to database
    await connectDB();

    // Process logout
    const businessHandler = new LogoutBusinessHandler(event, parsedBody);
    const result = await businessHandler.processRequest();

    logger.info('Logout handler completed successfully');
    logger.logBusinessEvent('LAMBDA_SUCCESS', {
        operationType: 'logout',
        logoutType: result.logoutType,
        accountId: result.accountId,
        sessionsTerminated: result.sessionsTerminated,
        securityLogout: result.securityLogout,
        tokensRevoked: result.tokensRevoked
    });

    return SuccessResponse({
        message: result.message,
        data: result
    });
};

// ==================== EXPORT ====================

export const handler = lambdaMiddleware(LogoutHandler, {
    serviceName: 'auth-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});