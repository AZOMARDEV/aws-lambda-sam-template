import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { extractAuthData, ExtractedAuthData, SuccessResponse } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Session, ISession, validReasons } from '../../models/sessions.schema';

// ==================== INTERFACES ====================

interface LogoutRequest {
    // Specific session to logout
    sessionId?: string;

    // Logout type
    logoutType?: 'current' | 'all_sessions' | 'all_other_sessions';

    // Reason for logout (optional)
    reason?: 'logout' | 'timeout' | 'admin' | 'security' | 'max_sessions' | 'token_theft' | 'session_timeout' | 'password_change';
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

// Interface for authorizer context
interface AuthorizerContext {
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
}

// ==================== BUSINESS HANDLER CLASS ====================

class LogoutBusinessHandler {
    private requestData: LogoutRequest;
    private authdata: ExtractedAuthData;
    private authContext: AuthorizerContext;

    private event: APIGatewayProxyEvent;
    private logger: ReturnType<typeof createLogger>;

    // Data holders
    private clientIP: string = '';

    constructor(event: APIGatewayProxyEvent, body: LogoutRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.event = event;
        this.requestData = body;
        this.clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
        this.authdata = extractAuthData(event.headers as Record<string, string>);

        // Extract authorizer context - this comes from the CustomAuthorizer
        this.authContext = (event.requestContext?.authorizer || {}) as AuthorizerContext;

        // Validate that accountId exists in context
        if (!this.authContext.accountId) {
            throw new HttpError('Authorization context missing - accountId not found', 401);
        }

        this.logger = createLogger('auth-service', requestId);

        this.logger.appendPersistentKeys({
            userAgent: event.headers?.['User-Agent'],
            sourceIP: this.clientIP,
            functionName: 'logout',
            accountId: this.authContext.accountId,
            sessionId: this.authContext.sessionId
        });
    }

    /**
     * Main processing method
     */
    async processRequest(): Promise<LogoutResponseData> {
        this.logger.info('Starting logout process', {
            logoutType: this.requestData.logoutType || 'current',
            reason: this.requestData.reason || 'user_initiated',
            accountId: this.authContext.accountId,
            sessionId: this.authContext.sessionId
        });

        // Step 1: Validate request data
        this.validateRequestData();

        // Step 2: Perform logout based on type
        return await this.performLogout();
    }

    /**
     * Step 1: Validate request data
     */
    private validateRequestData(): void {
        this.logger.debug('Validating logout request data');

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
        if (this.requestData.reason && !validReasons.includes(this.requestData.reason)) {
            throw new HttpError('Invalid logout reason', 400);
        }

        // Set default reason
        if (!this.requestData.reason) {
            this.requestData.reason = 'logout';
        }

        this.logger.debug('Request validation completed');
    }

    /**
     * Step 2: Perform logout based on type
     */
    private async performLogout(): Promise<LogoutResponseData> {
        this.logger.debug('Performing logout', {
            logoutType: this.requestData.logoutType,
            accountId: this.authContext.accountId
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

        this.logger.info('Logout completed successfully', {
            accountId: this.authContext.accountId,
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
            accountId: this.authContext.accountId,
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

        let session: ISession | null = null;

        // Priority 1: Use sessionId from authorizer context
        if (this.authContext.sessionId) {
            session = await Session.findOne({
                sessionId: this.authContext.sessionId,
                accountId: this.authContext.accountId,
                isActive: true
            });
        }

        // Priority 2: Use sessionId from request body
        if (!session && this.requestData.sessionId) {
            session = await Session.findOne({
                sessionId: this.requestData.sessionId,
                accountId: this.authContext.accountId,
                isActive: true
            });
        }

        // Priority 3: Find session by access token
        if (!session && this.authdata.authorization) {
            session = await Session.findOne({
                accessToken: this.authdata.authorization,
                accountId: this.authContext.accountId,
                isActive: true
            });
        }

        if (!session) {
            this.logger.warn('No active session found to logout', {
                authContextSessionId: this.authContext.sessionId,
                requestSessionId: this.requestData.sessionId
            });
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

        // Count tokens to be revoked
        const tokensRevoked = session.refreshTokens.filter(rt => !rt.isRevoked).length;

        // Terminate session
        session.terminate(this.requestData.reason!, 'user');
        await session.save();

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
            accountId: this.authContext.accountId,
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

        // Use sessionId from authorizer context or request
        let currentSessionId = this.authContext.sessionId || this.requestData.sessionId;

        // If still no sessionId, try to find by access token
        if (!currentSessionId && this.authdata.authorization) {
            const currentSession = await Session.findOne({
                accessToken: this.authdata.authorization,
                accountId: this.authContext.accountId,
                isActive: true
            });
            currentSessionId = currentSession?.sessionId;
        }

        // Find all sessions except current
        const query: any = {
            accountId: this.authContext.accountId,
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