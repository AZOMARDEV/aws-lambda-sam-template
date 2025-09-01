import { APIGatewayProxyEvent } from 'aws-lambda';
import HttpError from '../exception/httpError';
import { Logger } from './logger';
/**
 * Options for request body parsing
 */
interface ParseOptions {
    required?: boolean;
    maxSize?: number; // in bytes
    allowEmpty?: boolean;
}

/**
 * Request body parser utility class
 */
export class RequestBodyParser {
    private logger?: Logger;

    constructor(logger?: Logger) {
        this.logger = logger;
    }

    /**
     * Parse JSON request body from API Gateway event
     */
    parseBody<T = Record<string, any>>(
        event: APIGatewayProxyEvent,
        options: ParseOptions = {}
    ): T {
        const { required = true, maxSize = 1024 * 1024, allowEmpty = false } = options;

        // Check if body exists
        if (!event.body) {
            if (required) {
                this.logger?.error('Request body is required but not provided');
                throw new HttpError('Request body is required', 400);
            }
            return {} as T;
        }

        // Check body size
        if (event.body.length > maxSize) {
            this.logger?.error('Request body exceeds maximum size', {
                bodySize: event.body.length,
                maxSize
            });
            throw new HttpError('Request body too large', 413);
        }

        // Check for empty body
        if (!allowEmpty && event.body.trim() === '') {
            this.logger?.error('Request body is empty');
            throw new HttpError('Request body cannot be empty', 400);
        }

        try {
            const parsedBody = JSON.parse(event.body) as T;

            this.logger?.debug('Request body parsed successfully', {
                bodySize: event.body.length,
                fieldsCount: typeof parsedBody === 'object' && parsedBody !== null
                    ? Object.keys(parsedBody).length
                    : 0
            });

            return parsedBody;
        } catch (error) {
            this.logger?.error('JSON parsing failed', {
                error: (error as Error).message,
                bodySize: event.body.length,
                bodyPreview: event.body.substring(0, 100) // First 100 chars for debugging
            });
            throw new HttpError('Invalid JSON in request body', 400);
        }
    }

    /**
     * Parse body with type safety and validation
     */
    parseBodyWithValidation<T = Record<string, any>>(
        event: APIGatewayProxyEvent,
        validator: (body: any) => body is T,
        options: ParseOptions = {}
    ): T {
        const parsedBody = this.parseBody(event, options);

        if (!validator(parsedBody)) {
            this.logger?.error('Request body validation failed', {
                body: parsedBody
            });
            throw new HttpError('Invalid request body structure', 400);
        }

        return parsedBody;
    }

    /**
     * Parse body and extract specific fields
     */
    parseAndExtract<T extends Record<string, any>>(
        event: APIGatewayProxyEvent,
        requiredFields: (keyof T)[],
        optionalFields: (keyof T)[] = [],
        options: ParseOptions = {}
    ): T {
        const parsedBody = this.parseBody(event, options);

        // Check required fields
        const missingFields = requiredFields.filter(field =>
            !(field in parsedBody) || (parsedBody as any)[field] === undefined || (parsedBody as any)[field] === null
        );

        if (missingFields.length > 0) {
            this.logger?.error('Missing required fields', {
                missingFields,
                providedFields: Object.keys(parsedBody)
            });
            throw new HttpError(`Missing required fields: ${missingFields.join(', ')}`, 400);
        }

        // Extract only specified fields
        const result = {} as T;
        [...requiredFields, ...optionalFields].forEach(field => {
            if (field in parsedBody) {
                result[field] = parsedBody[field as string];
            }
        });

        return result;
    }
}

/**
 * Standalone function for simple JSON parsing (most common use case)
 */
export const parseRequestBody = <T = Record<string, any>>(
    event: APIGatewayProxyEvent,
    logger?: Logger,
    options: ParseOptions = {}
): T => {
    const parser = new RequestBodyParser(logger);
    return parser.parseBody<T>(event, options);
};

/**
 * Standalone function for parsing with required fields validation
 */
export const parseRequestBodyWithFields = <T extends Record<string, any>>(
    event: APIGatewayProxyEvent,
    requiredFields: (keyof T)[],
    optionalFields: (keyof T)[] = [],
    logger?: Logger,
    options: ParseOptions = {}
): T => {
    const parser = new RequestBodyParser(logger);
    return parser.parseAndExtract<T>(event, requiredFields, optionalFields, options);
};

/**
 * Common request body types for reuse
 */
export interface BaseRequest {
    requestId?: string;
    timestamp?: string;
}

export interface PaginatedRequest extends BaseRequest {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface SearchRequest extends PaginatedRequest {
    query?: string;
    filters?: Record<string, any>;
}