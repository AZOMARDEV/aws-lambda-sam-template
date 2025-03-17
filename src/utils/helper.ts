import { AuthMetadata } from "../beans/request";
import HttpError from "../exception/httpError";

/**
 * Validates metadata structure
 */
const validateMetadata = (metadata: any): boolean => {
    if (!metadata) return false;

    const requiredFields = ['language', 'location', 'device', "added_date"];
    return requiredFields.every(field => metadata[field]);
};

/**
 * Extracts and validates auth data and metadata from headers
 */
const extractAuthData = (headers: Record<string, any>): AuthMetadata => {
    try {

        let authorization = null;
        // Parse and validate metadata
        let metadata = null;
        const metadataHeader = headers["metadata"];

        if (!metadataHeader) {
            throw new HttpError('Metadata is required', 400);
        }

        try {
            metadata = JSON.parse(metadataHeader);
        } catch (error) {
            throw new HttpError('Invalid metadata format', 400);
        }

        if (!validateMetadata(metadata)) {
            throw new HttpError('Invalid metadata structure. Required fields', 400);
        }


        return { metadata, authorization };
    } catch (error) {
        if (error instanceof HttpError) throw error;
        throw new HttpError('Error processing authentication data', 400);
    }
};

/**
 * Validates required fields in an object
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
 * Creates a success response object.
 */
function SuccessResponse(response: { message?: string; data?: any }) {
    return {
        statusCode: 200,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization,Metadata",
        },
        body: JSON.stringify({ message: response.message || "Success", ...response?.data, status: 200 }),
    };
}

/**
 * Creates an error response object.
 */
function ErrorResponse(response: { status: any; message: any; data: any; type?: any; }) {

    return {
        statusCode: response?.status || 500, // Default to 500 if no status is provided
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization,Metadata",
        },
        body: JSON.stringify({
            status: response?.status, // Add a status field for consistency
            message: response?.message || "An error occurred", // Default error message
            type: response?.type || "UnknownError", // Provide an error type if available
            details: response?.data || response, // Include additional error details or the full response object
        }),
    };
}




export { SuccessResponse, ErrorResponse, validateRequiredFields, extractAuthData };
