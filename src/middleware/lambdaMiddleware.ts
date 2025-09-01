import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { createLogger } from '../utils/logger';
import { ErrorResponse } from '../utils/helper';
import HttpError from '../exception/httpError';

type LambdaHandler = (event: APIGatewayProxyEvent, context?: Context) => Promise<APIGatewayProxyResult>;

interface MiddlewareConfig {
    serviceName?: string;
    enableRequestLogging?: boolean;
    enableResponseLogging?: boolean;
    enablePerformanceLogging?: boolean;
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

const DEFAULT_CONFIG: MiddlewareConfig = {
    serviceName: 'lambda-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
};

export const lambdaMiddleware = (handler: LambdaHandler, config: MiddlewareConfig = {}) => {
    const middlewareConfig = { ...DEFAULT_CONFIG, ...config };

    return async (event: APIGatewayProxyEvent, context?: Context): Promise<APIGatewayProxyResult> => {
        const startTime = Date.now();
        const requestId = event.requestContext?.requestId || context?.awsRequestId || 'unknown';

        const logger = createLogger(middlewareConfig.serviceName!, requestId);

        logger.appendPersistentKeys({
            httpMethod: event.httpMethod,
            path: event.path,
            resource: event.resource,
            stage: event.requestContext?.stage,
            userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent'],
            sourceIP: event.requestContext?.identity?.sourceIp,
            userId: event.requestContext?.authorizer?.userId || event.headers?.['x-user-id'],
            correlationId: event.headers?.['x-correlation-id'] || requestId,
            functionName: context?.functionName,
            functionVersion: context?.functionVersion,
            memoryLimitInMB: context?.memoryLimitInMB,
            remainingTimeInMillis: context?.getRemainingTimeInMillis?.()
        });

        try {
            if (middlewareConfig.enableRequestLogging) {
                logger.info('Lambda request started', {
                    operation: 'middleware_request_start',
                    httpMethod: event.httpMethod,
                    path: event.path,
                    headers: sanitizeHeaders(event.headers || {}),
                    bodySize: event.body?.length || 0,
                    isBase64Encoded: event.isBase64Encoded || false
                });

                if (event.body && middlewareConfig.logLevel === 'debug') {
                    try {
                        const parsedBody = JSON.parse(event.body);
                        logger.debug('Request body', {
                            bodyFields: Object.keys(parsedBody)
                        });
                    } catch {
                        logger.debug('Request body (non-JSON)', {
                            bodySize: event.body.length
                        });
                    }
                }
            }

            logger.logBusinessEvent('REQUEST_STARTED', {
                httpMethod: event.httpMethod,
                path: event.path,
                userId: event.requestContext?.authorizer?.userId || event.headers?.['x-user-id']
            });

            const response = await handler(event, context);

            const totalDuration = Date.now() - startTime;
            const remainingTime = context?.getRemainingTimeInMillis?.() || 0;

            if (middlewareConfig.enableResponseLogging) {
                logger.info('Lambda request success', {
                    operation: 'middleware_request_success',
                    statusCode: response.statusCode,
                    duration: totalDuration,
                    responseSize: response.body?.length || 0
                });

                if (response.body && middlewareConfig.logLevel === 'debug') {
                    try {
                        const parsed = JSON.parse(response.body);
                        logger.debug('Response body', {
                            hasData: !!parsed.data,
                            hasError: !!parsed.error,
                            message: parsed.message
                        });
                    } catch {
                        logger.debug('Response body (non-JSON)', {
                            bodySize: response.body.length
                        });
                    }
                }
            }

            if (middlewareConfig.enablePerformanceLogging) {
                logger.logPerformance('total_request_duration', totalDuration);

                if (totalDuration > 10000) {
                    logger.warn('Slow request', { duration: totalDuration });
                }

                if (remainingTime < 5000) {
                    logger.warn('Low remaining execution time', {
                        remainingTimeInMillis: remainingTime
                    });
                }
            }

            logger.logBusinessEvent('REQUEST_COMPLETED', {
                statusCode: response.statusCode,
                duration: totalDuration
            });

            return addSecurityHeaders(response);
        } catch (error: any) {
            const totalDuration = Date.now() - startTime;
            const remainingTime = context?.getRemainingTimeInMillis?.() || 0;

            logger.error('Lambda error', {
                operation: 'middleware_request_error',
                error: error.message,
                errorType: error.constructor.name,
                stack: error.stack,
                duration: totalDuration
            });

            logger.logBusinessEvent('REQUEST_FAILED', {
                error: error.message,
                errorType: error.constructor.name,
                duration: totalDuration,
                httpMethod: event.httpMethod,
                path: event.path
            });

            let errorResponse: APIGatewayProxyResult;

            if (error instanceof HttpError) {
                errorResponse = ErrorResponse({
                    status: error.status || error.statusCode as any || 500,
                    message: error.message,
                    data: error.data
                });
            } else if (error.name === 'ValidationError') {
                errorResponse = ErrorResponse({
                    status: 400,
                    message: 'Validation failed: ' + error.message,
                    data: {
                        type: 'ValidationError',
                        details: error.details || null
                    }
                });
            } else if (error.name === 'TimeoutError' || error.message?.includes('timeout')) {
                errorResponse = ErrorResponse({
                    status: 408,
                    message: 'Request timeout',
                    data: {
                        type: 'TimeoutError',
                        duration: totalDuration
                    }
                });
            } else if (error.name === 'DatabaseError' || error.message?.includes('database')) {
                errorResponse = ErrorResponse({
                    status: 503,
                    message: 'Database operation failed',
                    data: {
                        type: 'DatabaseError'
                    }
                });
            } else {
                errorResponse = ErrorResponse({
                    status: 500,
                    message: 'Internal server error',
                    data: {
                        type: 'InternalError',
                        requestId
                    }
                });
            }

            return addSecurityHeaders(errorResponse);
        }
    };
};

function sanitizeHeaders(headers: Record<string, string | undefined>): Record<string, string | undefined> {
    const sensitive = ['authorization', 'x-api-key', 'cookie', 'set-cookie', 'x-access-token', 'x-refresh-token'];
    const cleanHeaders: Record<string, string | undefined> = {};

    for (const key in headers) {
        const lowerKey = key.toLowerCase();
        cleanHeaders[key] = sensitive.includes(lowerKey) ? '[REDACTED]' : headers[key];
    }

    return cleanHeaders;
}

function addSecurityHeaders(response: APIGatewayProxyResult): APIGatewayProxyResult {
    const securityHeaders = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'",
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    };

    return {
        ...response,
        headers: {
            ...(response.headers || {}),
            ...securityHeaders
        }
    };
}

export const createLambdaMiddleware = (config: MiddlewareConfig) => {
    return (handler: LambdaHandler) => lambdaMiddleware(handler, config);
};

export const middlewareVariants = {
    minimal: createLambdaMiddleware({
        enableRequestLogging: false,
        enableResponseLogging: false,
        enablePerformanceLogging: true,
        logLevel: 'warn'
    }),
    debug: createLambdaMiddleware({
        enableRequestLogging: true,
        enableResponseLogging: true,
        enablePerformanceLogging: true,
        logLevel: 'debug'
    }),
    production: createLambdaMiddleware({
        enableRequestLogging: true,
        enableResponseLogging: false,
        enablePerformanceLogging: true,
        logLevel: 'info'
    })
};
