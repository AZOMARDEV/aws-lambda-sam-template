import HttpError from "../exception/httpError";
import crypto from 'crypto';

/**
 * Generates a numeric OTP of specified length.
 */
export const generateOTP = (length: number = 6): string => {
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;
    return Math.floor(Math.random() * (max - min + 1) + min).toString();
};

const generateDeviceIdFromHeaders = (headers: Record<string, string>) => {
    const str = `${headers['user-agent'] || ''}|${headers['device-os'] || ''}|${headers['device-type'] || ''}`;
    return crypto.createHash('sha256').update(str).digest('hex').slice(0, 12); // 12-char deviceId
};


// Types for better type safety
interface DeviceInfo {
    type: 'mobile' | 'desktop' | 'tablet';
    os: string;
    browser?: string;
    version?: string;
    deviceId: string; // Unique device identifier
    screenResolution?: string;
    userAgent: string;
}

interface LocationInfo {
    country?: string;
    city?: string;
    timezone: string;
    coordinates?: {
        latitude: number;
        longitude: number;
    };
    ipAddress: string;
}

interface AuthMetadata {
    language: string;
    location: LocationInfo;
    device: DeviceInfo;
    addedDate: string; // ISO date string
    fcmToken?: string; // Firebase Cloud Messaging token for notifications
    sessionId?: string; // Optional session identifier
}

interface ExtractedAuthData {
    metadata: AuthMetadata;
    authorization: string | null;
}

/**
 * Validates the metadata structure to ensure all required fields are present
 */
const validateMetadata = (metadata: any): metadata is AuthMetadata => {
    if (!metadata || typeof metadata !== 'object') {
        return false;
    }

    // Check required top-level fields
    const requiredFields = ['language', 'location', 'device', 'addedDate'];
    for (const field of requiredFields) {
        if (!metadata[field]) {
            return false;
        }
    }

    // Validate device info
    const device = metadata.device;
    if (!device.type || !device.os || !device.deviceId || !device.userAgent) {
        return false;
    }

    if (!['mobile', 'desktop', 'tablet'].includes(device.type)) {
        return false;
    }

    // Validate location info
    const location = metadata.location;
    if (!location.timezone || !location.ipAddress) {
        return false;
    }

    // Validate date format
    if (isNaN(Date.parse(metadata.addedDate))) {
        return false;
    }

    return true;
};

const detectDeviceInfo = (userAgent: string) => {
    let browser = 'unknown';
    let version = undefined;
    let os = 'unknown';
    let type: 'mobile' | 'tablet' | 'desktop' = 'desktop';

    if (!userAgent) return { browser, version, os, type };

    // Detect browser and version
    if (/Chrome\/([0-9.]+)/.test(userAgent) && !/Edge/.test(userAgent) && !/OPR/.test(userAgent)) {
        browser = 'Chrome';
        version = userAgent.match(/Chrome\/([0-9.]+)/)?.[1];
    } else if (/Firefox\/([0-9.]+)/.test(userAgent)) {
        browser = 'Firefox';
        version = userAgent.match(/Firefox\/([0-9.]+)/)?.[1];
    } else if (/Safari\/([0-9.]+)/.test(userAgent) && !/Chrome/.test(userAgent)) {
        browser = 'Safari';
        version = userAgent.match(/Version\/([0-9.]+)/)?.[1];
    } else if (/Edge\/([0-9.]+)/.test(userAgent)) {
        browser = 'Edge';
        version = userAgent.match(/Edge\/([0-9.]+)/)?.[1];
    } else if (/OPR\/([0-9.]+)/.test(userAgent)) {
        browser = 'Opera';
        version = userAgent.match(/OPR\/([0-9.]+)/)?.[1];
    }

    // Detect OS
    if (/Windows NT/.test(userAgent)) os = 'Windows';
    else if (/Mac OS X/.test(userAgent)) os = 'MacOS';
    else if (/Android/.test(userAgent)) os = 'Android';
    else if (/iPhone|iPad|iPod/.test(userAgent)) os = 'iOS';
    else if (/Linux/.test(userAgent)) os = 'Linux';

    // Detect device type
    if (/Mobi|Android/i.test(userAgent)) type = 'mobile';
    else if (/Tablet|iPad/i.test(userAgent)) type = 'tablet';

    return { browser, version, os, type };
};

const extractAuthData = (headers: Record<string, string>): ExtractedAuthData => {
    let authorization: string | null = null;
    let metadata: AuthMetadata | null = null;

    // Extract authorization
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader) {
        authorization = authHeader.startsWith('Bearer ')
            ? authHeader.substring(7)
            : authHeader;
    }

    // Extract metadata header if provided
    const metadataHeader = headers['metadata'] || headers['Metadata'];
    if (metadataHeader) {
        try {
            const parsed = JSON.parse(metadataHeader);
            if (validateMetadata(parsed)) metadata = parsed;
        } catch { }
    }

    // Generate metadata from headers if missing
    if (!metadata) {
        const userAgent = headers['user-agent'] || 'unknown';
        const deviceInfo = detectDeviceInfo(userAgent);

        metadata = {
            language: headers['language'] || 'en',
            addedDate: new Date().toISOString(),
            location: {
                timezone: headers['timezone'] || 'UTC',
                ipAddress: headers['ip-address'] || headers['x-forwarded-for'] || '0.0.0.0',
                country: headers['country'] || 'unknown',
                city: headers['city'] || 'unknown',
                coordinates: {
                    latitude: parseFloat(headers['latitude'] || '0'),
                    longitude: parseFloat(headers['longitude'] || '0'),
                },
            },
            device: {
                ...deviceInfo,
                userAgent,
                screenResolution: headers['screen-resolution'] || undefined,
                deviceId: headers['device-id'] || generateDeviceIdFromHeaders(headers)
            },
        };
    }

    return { metadata, authorization };
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
    extractAuthData,
    ExtractedAuthData
};
