import { AuthMetadata } from "../beans/request";
import HttpError from "../exception/httpError";

/**
 * Generates a numeric OTP of specified length.
 */
export const generateOTP = (length: number = 6): string => {
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;
    return Math.floor(Math.random() * (max - min + 1) + min).toString();
};

/**
 * Validates the structure of metadata.
 */
const validateMetadata = (metadata: any): boolean => {
    if (!metadata || typeof metadata !== 'object') return false;

    const requiredFields = ['language', 'location', 'device', 'added_date'];
    return requiredFields.every(field => field in metadata);
};

/**
 * Extracts and validates metadata from headers.
 */
const extractAuthData = (headers: Record<string, any>): AuthMetadata => {
    try {
        let authorization: string | null = null;
        let metadata: any = null;

        const metadataHeader = headers['metadata'];

        if (!metadataHeader) {
            throw new HttpError('Metadata is required', 400);
        }

        try {
            metadata = JSON.parse(metadataHeader);
        } catch {
            throw new HttpError('Invalid metadata format (must be JSON)', 400);
        }

        if (!validateMetadata(metadata)) {
            throw new HttpError('Invalid metadata structure. Required fields: language, location, device, added_date', 400);
        }

        return { metadata, authorization };
    } catch (error: any) {
        if (error instanceof HttpError) throw error;
        throw new HttpError('Error processing authentication metadata', 400);
    }
};

/**
 * Validates presence of required fields in an object.
 */
const validateRequiredFields = (
    data: Record<string, any>,
    requiredFields: string[],
    customMessages: Record<string, string> = {}
): void => {
    const missingFields = requiredFields.filter(field => {
        const value = data[field];
        return value === undefined || value === null || value === '';
    });

    if (missingFields.length > 0) {
        const messages = missingFields.map(field =>
            customMessages[field] || `${field} is required`
        );
        throw new HttpError(`Missing required fields: ${messages.join(', ')}`, 400);
    }
};

/**
 * Creates a success response for Lambda.
 */
function SuccessResponse(response: { message?: string; data?: any }) {
    return {
        statusCode: 200,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization,Metadata'
        },
        body: JSON.stringify({
            status: 200,
            message: response.message || 'Success',
            data: response.data
        })
    };
}

/**
 * Creates an error response for Lambda.
 */
function ErrorResponse(response: { status?: number; message?: string; data?: any; type?: string }) {
    return {
        statusCode: response?.status || 500,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization,Metadata'
        },
        body: JSON.stringify({
            status: response?.status || 500,
            message: response?.message || 'An error occurred',
            type: response?.type || 'UnknownError',
            details: response?.data || response
        })
    };
}

export {
    SuccessResponse,
    ErrorResponse,
    validateRequiredFields,
    extractAuthData
};
