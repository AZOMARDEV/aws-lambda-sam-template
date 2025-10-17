import { lambdaMiddleware } from "../../middleware/lambdaMiddleware";
import axios, { AxiosError } from 'axios';
import { SuccessResponse } from "../../utils/helper";
import AWS from 'aws-sdk';
import Handlebars from 'handlebars';

// Register Handlebars helpers (keeping your existing ones)
Handlebars.registerHelper('eq', function (a: any, b: any) {
    return a === b;
});

Handlebars.registerHelper('gt', function (a: any, b: any) {
    return a > b;
});

Handlebars.registerHelper('getImage', function (images: any[], index: number = 0) {
    if (Array.isArray(images) && images.length > index && index >= 0) {
        return images[index];
    }
    return '';
});

Handlebars.registerHelper('safeImage', function (images: any[], index: number = 0, fallback: string = '/default-image.jpg') {
    if (Array.isArray(images) && images.length > index && index >= 0 && images[index]) {
        return images[index];
    }
    return fallback;
});

Handlebars.registerHelper('arrayGet', function (array: any[], index: number) {
    if (Array.isArray(array) && array.length > index && index >= 0) {
        return array[index];
    }
    return '';
});

Handlebars.registerHelper('first', function (array: any[]) {
    if (Array.isArray(array) && array.length > 0) {
        return array[0];
    }
    return '';
});

Handlebars.registerHelper('forEach', function (this: any, array: any[], options: any) {
    if (!Array.isArray(array) || array.length === 0) {
        return options.inverse(this);
    }

    let result = '';
    for (let i = 0; i < array.length; i++) {
        const data = Handlebars.createFrame(options.data || {});
        data.index = i;
        data.first = i === 0;
        data.last = i === array.length - 1;
        data.length = array.length;

        result += options.fn(array[i], { data });
    }
    return result;
});

Handlebars.registerHelper('range', function (start: number, end: number, options: any) {
    let result = '';
    const actualStart = typeof start === 'number' ? start : 0;
    const actualEnd = typeof end === 'number' ? end : 0;

    for (let i = actualStart; i < actualEnd; i++) {
        const data = Handlebars.createFrame(options.data || {});
        data.index = i;
        data.first = i === actualStart;
        data.last = i === actualEnd - 1;
        data.value = i;

        result += options.fn(i, { data });
    }
    return result;
});

Handlebars.registerHelper('repeat', function (this: any, count: number, options: any) {
    const actualCount = typeof count === 'number' && count > 0 ? count : 0;
    let result = '';

    for (let i = 0; i < actualCount; i++) {
        const data = Handlebars.createFrame(options.data || {});
        data.index = i;
        data.first = i === 0;
        data.last = i === actualCount - 1;
        data.count = actualCount;

        result += options.fn(this, { data });
    }
    return result;
});

Handlebars.registerHelper('unless', function (this: any, conditional: any, options: any) {
    if (!conditional) {
        return options.fn(this);
    } else {
        return options.inverse(this);
    }
});

Handlebars.registerHelper('hasLength', function (array: any[]) {
    return Array.isArray(array) && array.length > 0;
});

Handlebars.registerHelper('safe', function (obj: any, path: string) {
    const keys = path.split('.');
    let result = obj;
    for (const key of keys) {
        if (result && typeof result === 'object' && key in result) {
            result = result[key];
        } else {
            return '';
        }
    }
    return result || '';
});

// Add these Handlebars helpers to your existing helper registrations
// Place these after your existing Handlebars.registerHelper calls

// Less than or equal to
Handlebars.registerHelper('lte', function (a: any, b: any) {
    return a <= b;
});

// Less than
Handlebars.registerHelper('lt', function (a: any, b: any) {
    return a < b;
});

// Greater than or equal to
Handlebars.registerHelper('gte', function (a: any, b: any) {
    return a >= b;
});

// Not equal
Handlebars.registerHelper('ne', function (a: any, b: any) {
    return a !== b;
});

// And operation
Handlebars.registerHelper('and', function (...args: any[]) {
    // Remove the options object from args
    const values = args.slice(0, -1);
    return values.every(val => !!val);
});

// Or operation
Handlebars.registerHelper('or', function (...args: any[]) {
    // Remove the options object from args
    const values = args.slice(0, -1);
    return values.some(val => !!val);
});

// Not operation
Handlebars.registerHelper('not', function (value: any) {
    return !value;
});

// Add operation
Handlebars.registerHelper('add', function (a: any, b: any) {
    return Number(a) + Number(b);
});

// Subtract operation
Handlebars.registerHelper('subtract', function (a: any, b: any) {
    return Number(a) - Number(b);
});

// Multiply operation
Handlebars.registerHelper('multiply', function (a: any, b: any) {
    return Number(a) * Number(b);
});

// Divide operation
Handlebars.registerHelper('divide', function (a: any, b: any) {
    return Number(a) / Number(b);
});

// Modulo operation
Handlebars.registerHelper('mod', function (a: any, b: any) {
    return Number(a) % Number(b);
});

// String contains check
Handlebars.registerHelper('contains', function (str: string, substring: string) {
    if (typeof str !== 'string' || typeof substring !== 'string') {
        return false;
    }
    return str.includes(substring);
});

// String starts with check
Handlebars.registerHelper('startsWith', function (str: string, prefix: string) {
    if (typeof str !== 'string' || typeof prefix !== 'string') {
        return false;
    }
    return str.startsWith(prefix);
});

// String ends with check
Handlebars.registerHelper('endsWith', function (str: string, suffix: string) {
    if (typeof str !== 'string' || typeof suffix !== 'string') {
        return false;
    }
    return str.endsWith(suffix);
});

// Format number with commas
Handlebars.registerHelper('formatNumber', function (num: any) {
    const number = Number(num);
    if (isNaN(number)) return num;
    return number.toLocaleString();
});

// Format currency
Handlebars.registerHelper('formatCurrency', function (amount: any, currency: string = 'USD') {
    const number = Number(amount);
    if (isNaN(number)) return amount;

    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency
    }).format(number);
});

// Default value helper
Handlebars.registerHelper('default', function (value: any, defaultValue: any) {
    return value || defaultValue;
});

// Capitalize first letter
Handlebars.registerHelper('capitalize', function (str: string) {
    if (typeof str !== 'string') return str;
    return str.charAt(0).toUpperCase() + str.slice(1);
});

// Uppercase
Handlebars.registerHelper('upper', function (str: string) {
    if (typeof str !== 'string') return str;
    return str.toUpperCase();
});

// Lowercase
Handlebars.registerHelper('lower', function (str: string) {
    if (typeof str !== 'string') return str;
    return str.toLowerCase();
});

// JSON stringify for debugging
Handlebars.registerHelper('json', function (obj: any) {
    return JSON.stringify(obj, null, 2);
});

// Format date
Handlebars.registerHelper('formatDate', function (date: any, format: string = 'YYYY-MM-DD') {
    if (!date) return '';

    const dateObj = new Date(date);
    if (isNaN(dateObj.getTime())) return date;

    // Simple date formatting - you might want to use a proper date library like moment.js or date-fns
    const year = dateObj.getFullYear();
    const month = String(dateObj.getMonth() + 1).padStart(2, '0');
    const day = String(dateObj.getDate()).padStart(2, '0');

    switch (format) {
        case 'MM/DD/YYYY':
            return `${month}/${day}/${year}`;
        case 'DD/MM/YYYY':
            return `${day}/${month}/${year}`;
        case 'YYYY-MM-DD':
            return `${year}-${month}-${day}`;
        default:
            return dateObj.toLocaleDateString();
    }
});

// Truncate string
Handlebars.registerHelper('truncate', function (str: string, length: number = 50, suffix: string = '...') {
    if (typeof str !== 'string') return str;
    if (str.length <= length) return str;
    return str.substring(0, length) + suffix;
});

// Updated Types for Multi-Channel Support
type NotificationChannel = 'email' | 'sms' | 'push' | 'webhook';

interface NotificationData {
    email?: string;
    phone?: string;
    [key: string]: any;
}

interface EmailContent {
    subject: string;
    template: string;
    data: NotificationData;
    recipient: string;
    metadata?: Record<string, any>;
    pdfAttachment?: {
        s3Key?: string;
        s3Bucket?: string;
        url?: string;
        fileName?: string;
    };
}

interface SmsContent {
    message: string;
    recipient: string;
    data: NotificationData;
    metadata?: Record<string, any>;
}

interface NotificationContent {
    email?: EmailContent;
    sms?: SmsContent;
    // Future channels can be added here
    push?: any;
    webhook?: any;
}

interface MessageBody {
    notificationType: string; // Type/purpose of notification (e.g., 'welcome', 'booking_confirmation')
    channels: NotificationChannel[]; // Array of channels to send through
    content: NotificationContent; // Content for each channel
    priority?: 'high' | 'medium' | 'low';
    scheduledAt?: Date; // For future scheduling support
}

interface EmailAttachment {
    content: string;
    name: string;
}

interface EmailSenderPayload {
    sender: {
        name: string;
        email: string;
    };
    to: Array<{ email: string }>;
    subject: string;
    htmlContent: string;
    attachment?: EmailAttachment[];
}

// Configuration
interface NotificationConfig {
    EMAIL_SENDER: {
        NAME: string;
        EMAIL: string;
    };
    EMAIL_API_KEY: string;
    EMAIL_API_URL: string;
    TEMPLATE_BUCKET: string;
    PDF_BUCKET: string;
    MONGODB_URI: string;
    SMS_API_KEY: string;  // Make required
    SMS_API_URL: string;  // Make required
    SMS_INTERFACE_ID: string;  // Add new
}

const CONFIG: NotificationConfig = {
    EMAIL_SENDER: {
        NAME: process.env.EMAIL_SENDER_NAME || 'OtoParking',
        EMAIL: process.env.EMAIL_SENDER_EMAIL || 'omaar.azhaarii@gmail.com'
    },
    EMAIL_API_KEY: process.env.BREVO_API_KEY || '',
    EMAIL_API_URL: 'https://api.brevo.com/v3/smtp/email',
    TEMPLATE_BUCKET: process.env.TEMPLATE_BUCKET || '',
    PDF_BUCKET: process.env.PDF_BUCKET || process.env.TEMPLATE_BUCKET || '',
    MONGODB_URI: process.env.MONGODB_URI || '',
    SMS_API_KEY: process.env.SMS_API_KEY || '123456-SECRET-API-KEY',
    SMS_API_URL: process.env.SMS_API_URL || 'http://161.97.113.215:8888/SMSGateway/api/sms/send',
    SMS_INTERFACE_ID: process.env.SMS_INTERFACE_ID || '101'
};

interface SmsPayload {
    channelId: string;
    gsmNumber: string;
    gsmCountry: string;
    gsmPrefix: string;
    languageCode: string;
    smsText: string;
}

/**
 * Base Notification Service Interface
 */
interface INotificationService {
    sendNotification(content: any, data: NotificationData, metadata: Record<string, any>): Promise<any>;
    validateContent(content: any): boolean;
    extractRecipient(data: NotificationData): string;
}

/**
 * Email Service Class - Handles email notifications
 */
class EmailService implements INotificationService {
    private s3: AWS.S3;
    private config: NotificationConfig;

    constructor(config: NotificationConfig) {
        this.config = config;
        this.s3 = new AWS.S3();
    }

    /**
     * Validate email content
     */
    validateContent(content: EmailContent): boolean {
        return !!(content.subject && content.template && content.data);
    }

    /**
     * Extract email from data object
     */
    extractRecipient(content: EmailContent): string {
        const { data , recipient} = content;

        // Recipient email
        if(recipient){
            return recipient;
        }

        // Direct email property
        if (data.email) {
            return data.email;
        }

        // Email in client object (for booking emails)
        if (data.client?.email) {
            return data.client.email;
        }

        // Email in user object
        if (data.user?.email) {
            return data.user.email;
        }

        // Email in customer object
        if (data.customer?.email) {
            return data.customer.email;
        }

        // Email in recipient object
        if (data.recipient?.email) {
            return data.recipient.email;
        }

        // Email in to object
        if (data.to?.email) {
            return data.to.email;
        }

        throw new Error('No email address found in data object. Please include email in one of these paths: email, client.email, user.email, customer.email, recipient.email, or to.email');
    }

    /**
     * Log email to database
     */
    // private async logEmail(
    //     notificationType: string,
    //     payload: EmailSenderPayload,
    //     template: string,
    //     metadata: Record<string, any>,
    //     status: 'sent' | 'failed' | 'pending',
    //     response: { type: 'success' | 'error'; message: string, messageId?: string },
    //     hasAttachment: boolean = false,
    //     attachmentCount: number = 0
    // ): Promise<void> {
    //     try {
    //         await connectDB();

    //         const emailLog = new EmailLogsModel({
    //             type: notificationType,
    //             sender: {
    //                 name: payload.sender.name,
    //                 email: payload.sender.email
    //             },
    //             receiver: {
    //                 email: payload.to[0].email,
    //                 name: metadata.name || ''
    //             },
    //             subject: payload.subject,
    //             status,
    //             sentAt: new Date(),
    //             htmlContent: payload.htmlContent,
    //             response,
    //             template,
    //             hasAttachment,
    //             attachmentCount,
    //             metadata: metadata,
    //             createdAt: new Date(),
    //             updatedAt: new Date()
    //         });

    //         await emailLog.save();
    //         console.log('Email log saved successfully');
    //     } catch (error) {
    //         console.error('Error saving email log:', error);
    //     }
    // }

    /**
     * Determine if template needs compilation or simple replacement
     */
    private needsHandlebarsCompilation(template: string): boolean {
        const handlebarsPatterns = [
            /\{\{#[^}]+\}\}/,
            /\{\{\/[^}]+\}\}/,
            /\{\{[^}]+\s+[^}]+\}\}/,
            /\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_.]*\s*\}\}/
        ];

        return handlebarsPatterns.some(pattern => pattern.test(template));
    }

    /**
     * Send email notification
     */
    async sendNotification(content: EmailContent): Promise<any> {
        const { subject, template, data } = content;

        try {
            const recipientEmail = this.extractRecipient(content);
            const emailTemplate = await this.getEmailTemplate(template);

            let emailBody: string;

            if (this.needsHandlebarsCompilation(emailTemplate)) {
                const compiledTemplate = Handlebars.compile(emailTemplate);
                emailBody = compiledTemplate(data);
            } else {
                emailBody = this.performSimpleReplacements(emailTemplate, data);
            }

            const emailPayload: EmailSenderPayload = {
                sender: {
                    name: this.config.EMAIL_SENDER.NAME,
                    email: this.config.EMAIL_SENDER.EMAIL,
                },
                to: [{ email: recipientEmail }],
                subject,
                htmlContent: emailBody,
            };

            const hasAttachment = !!content.pdfAttachment;
            const attachmentCount = hasAttachment ? 1 : 0;

            const result = await this.sendEmail(emailPayload, content.pdfAttachment);

            // await this.logEmail(
            //     'email',
            //     emailPayload,
            //     template,
            //     { ...emailData, ...metadata },
            //     'sent',
            //     {
            //         type: 'success',
            //         message: `Email sent successfully. MessageId: ${result.messageId || 'N/A'}`,
            //         messageId: result.messageId
            //     },
            //     hasAttachment,
            //     attachmentCount
            // );

            return {
                channel: 'email',
                status: 'sent',
                result: result,
                recipient: recipientEmail
            };
        } catch (error) {
            console.error('Error sending email:', error);
            throw error;
        }
    }

    /**
     * Perform simple variable replacements
     */
    private performSimpleReplacements(template: string, data: any): string {
        let result = template;
        const simpleVarPattern = /\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g;
        result = result.replace(simpleVarPattern, (match, varName) => {
            return data[varName] !== undefined ? String(data[varName]) : match;
        });
        return result;
    }

    /**
     * Fetch email template from S3
     */
    private async getEmailTemplate(templateName: string): Promise<string> {
        if (!this.config.TEMPLATE_BUCKET) {
            throw new Error("TEMPLATE_BUCKET environment variable is not configured");
        }

        try {
            const params = {
                Bucket: this.config.TEMPLATE_BUCKET,
                Key: `email-templates/${templateName}.html`
            };

            const data = await this.s3.getObject(params).promise();

            if (!data.Body) {
                throw new Error(`Template "${templateName}.html" not found or is empty`);
            }

            return data.Body.toString('utf-8');
        } catch (error) {
            console.error(`Error retrieving template "${templateName}":`, error);
            throw new Error(`Failed to load email template "${templateName}"`);
        }
    }

    /**
     * Send email using Brevo API
     */
    private async sendEmail(payload: EmailSenderPayload, pdfAttachment?: EmailContent['pdfAttachment']): Promise<any> {
        if (!this.config.EMAIL_API_KEY) {
            throw new Error("BREVO_API_KEY environment variable is not configured");
        }

        try {
            if (pdfAttachment) {
                const attachment = await this.handlePDFAttachment(pdfAttachment);
                payload.attachment = [attachment];
            }

            const response = await axios.post(
                this.config.EMAIL_API_URL,
                payload,
                {
                    headers: {
                        "api-key": this.config.EMAIL_API_KEY,
                        "Content-Type": "application/json",
                    },
                }
            );

            console.log("Email sent successfully:", response.data);
            return response.data;
        } catch (error) {
            const axiosError = error as AxiosError;
            console.error("Failed to send email:", {
                status: axiosError.response?.status,
                data: axiosError.response?.data,
                message: axiosError.message
            });
            throw new Error(`Failed to send email: ${axiosError.message}`);
        }
    }

    /**
     * Handle PDF attachment
     */
    private async handlePDFAttachment(pdfAttachment: EmailContent['pdfAttachment']): Promise<EmailAttachment> {
        if (!pdfAttachment) {
            throw new Error("PDF attachment configuration is required");
        }

        let base64Content: string;
        let attachmentName: string;

        if (pdfAttachment.s3Key) {
            base64Content = await this.downloadPDFFromS3(pdfAttachment.s3Key, pdfAttachment.s3Bucket);
            attachmentName = pdfAttachment.fileName || pdfAttachment.s3Key.split('/').pop() || 'document.pdf';
        } else if (pdfAttachment.url) {
            base64Content = await this.downloadPDFFromUrl(pdfAttachment.url);
            attachmentName = pdfAttachment.fileName || pdfAttachment.url.split('/').pop() || 'document.pdf';
        } else {
            throw new Error("PDF attachment must have either s3Key or url specified");
        }

        return {
            content: base64Content,
            name: attachmentName
        };
    }

    /**
     * Download PDF from S3
     */
    private async downloadPDFFromS3(s3Key: string, bucket?: string): Promise<string> {
        const bucketName = bucket || this.config.PDF_BUCKET;

        if (!bucketName) {
            throw new Error("PDF_BUCKET or TEMPLATE_BUCKET environment variable is not configured");
        }

        try {
            const params = {
                Bucket: bucketName,
                Key: s3Key
            };

            const data = await this.s3.getObject(params).promise();

            if (!data.Body) {
                throw new Error(`PDF file "${s3Key}" not found or is empty`);
            }

            const buffer = data.Body as Buffer;
            return buffer.toString('base64');
        } catch (error) {
            console.error(`Error downloading PDF from S3 "${s3Key}":`, error);
            throw new Error(`Failed to download PDF from S3: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Download PDF from URL
     */
    private async downloadPDFFromUrl(pdfUrl: string): Promise<string> {
        try {
            const response = await axios.get(pdfUrl, {
                responseType: 'arraybuffer'
            });

            const buffer = Buffer.from(response.data);
            return buffer.toString('base64');
        } catch (error) {
            throw new Error(`Failed to download PDF from URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}

/**
 * SMS Service Class - Handles SMS notifications
 */
class SmsService implements INotificationService {
    private config: NotificationConfig;

    constructor(config: NotificationConfig) {
        this.config = config;
    }

    /**
     * Validate SMS content
     */
    validateContent(content: SmsContent): boolean {
        return !!(content.message && content.data);
    }

    /**
     * Extract phone number from content or data object
     */
    extractRecipient(content: SmsContent): string {
        // First check content.recipient
        if (content.recipient) {
            return content.recipient;
        }

        const { data } = content;

        // Direct phone property
        if (data.phone) {
            return data.phone;
        }

        // Phone in client object
        if (data.client?.phone) {
            return data.client.phone;
        }

        // Phone in user object
        if (data.user?.phone) {
            return data.user.phone;
        }

        // Phone in customer object
        if (data.customer?.phone) {
            return data.customer.phone;
        }

        // Phone in recipient object
        if (data.recipient?.phone) {
            return data.recipient.phone;
        }

        // Phone in to object
        if (data.to?.phone) {
            return data.to.phone;
        }

        throw new Error('No phone number found. Please include phone in: recipient, phone, client.phone, user.phone, customer.phone, recipient.phone, or to.phone');
    }

    /**
     * Send SMS notification
     */
    async sendNotification(content: SmsContent, data: NotificationData, metadata: Record<string, any>): Promise<any> {
        console.log('SMS Service: Starting to send SMS');

        try {
            // Validate API configuration
            if (!this.config.SMS_API_KEY || !this.config.SMS_API_URL || !this.config.SMS_INTERFACE_ID) {
                throw new Error('SMS configuration is incomplete. Please check SMS_API_KEY, SMS_API_URL, and SMS_INTERFACE_ID environment variables.');
            }

            // Extract recipient phone number
            const recipientPhone = this.extractRecipient(content);
            console.log('SMS Service: Recipient phone:', recipientPhone);

            // Process the message with variable substitution
            const processedMessage = this.processMessage(content.message, content.data);
            console.log('SMS Service: Processed message length:', processedMessage.length);

            // Parse phone number to extract country code and number
            const { gsmNumber, gsmPrefix, gsmCountry } = this.parsePhoneNumber(recipientPhone);

            // Prepare SMS payload
            const smsPayload: SmsPayload = {
                channelId: "WEB",
                gsmNumber: gsmNumber,
                gsmCountry: gsmCountry,
                gsmPrefix: gsmPrefix,
                languageCode: metadata?.languageCode || content.metadata?.languageCode || "fr",
                smsText: processedMessage
            };

            console.log('SMS Service: Sending SMS with payload:', {
                channelId: smsPayload.channelId,
                gsmNumber: smsPayload.gsmNumber,
                gsmCountry: smsPayload.gsmCountry,
                gsmPrefix: smsPayload.gsmPrefix,
                languageCode: smsPayload.languageCode,
                messageLength: smsPayload.smsText.length,
                messagePreview: smsPayload.smsText.substring(0, 50) + '...'
            });

            // Send SMS via API
            const response = await axios.post(
                this.config.SMS_API_URL,
                smsPayload,
                {
                    headers: {
                        "Content-Type": "application/json",
                        "X-Interface-Id": this.config.SMS_INTERFACE_ID,
                        "X-Api-Key": this.config.SMS_API_KEY
                    },
                    timeout: 30000 // 30 seconds timeout
                }
            );

            console.log("SMS Service: SMS sent successfully:", response.data);

            return {
                channel: 'sms',
                status: 'sent',
                result: response.data,
                recipient: recipientPhone,
                messageId: response.data?.messageId || response.data?.id || 'N/A',
                details: {
                    gsmNumber,
                    gsmPrefix,
                    gsmCountry,
                    messageLength: processedMessage.length
                }
            };

        } catch (error) {
            const axiosError = error as AxiosError;
            
            console.error('SMS Service: Error sending SMS:', {
                status: axiosError.response?.status,
                statusText: axiosError.response?.statusText,
                data: axiosError.response?.data,
                message: axiosError.message,
                code: axiosError.code
            });

            // Return detailed error information
            return {
                channel: 'sms',
                status: 'error',
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                recipient: 'unknown',
                details: {
                    httpStatus: axiosError.response?.status,
                    errorData: axiosError.response?.data,
                    errorCode: axiosError.code
                }
            };
        }
    }

    /**
     * Parse phone number to extract components
     * Supports multiple country formats
     */
    private parsePhoneNumber(phone: string): { gsmNumber: string; gsmPrefix: string; gsmCountry: string } {
        // Remove all non-digit characters except +
        let cleanPhone = phone.replace(/[^\d+]/g, '');

        // Country codes mapping
        const countryCodes: Record<string, { prefix: string; country: string; length: number }> = {
            '212': { prefix: '+212', country: 'Morocco', length: 3 },
            '213': { prefix: '+213', country: 'Algeria', length: 3 },
            '216': { prefix: '+216', country: 'Tunisia', length: 3 },
            '1': { prefix: '+1', country: 'USA/Canada', length: 1 },
            '33': { prefix: '+33', country: 'France', length: 2 },
            '44': { prefix: '+44', country: 'UK', length: 2 },
            '49': { prefix: '+49', country: 'Germany', length: 2 },
            '34': { prefix: '+34', country: 'Spain', length: 2 },
            '39': { prefix: '+39', country: 'Italy', length: 2 },
            '966': { prefix: '+966', country: 'Saudi Arabia', length: 3 },
            '971': { prefix: '+971', country: 'UAE', length: 3 },
        };

        let gsmPrefix = '+212'; // Default to Morocco
        let gsmCountry = 'Morocco';
        let gsmNumber = '';

        // Check if phone starts with +
        if (cleanPhone.startsWith('+')) {
            // Try to match country codes
            let matched = false;
            for (const [code, info] of Object.entries(countryCodes)) {
                if (cleanPhone.startsWith('+' + code)) {
                    gsmPrefix = info.prefix;
                    gsmCountry = info.country;
                    gsmNumber = cleanPhone.substring(info.length + 1); // +1 for the + sign
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                // Unknown country code, keep as is
                const possibleCode = cleanPhone.substring(1, 4);
                gsmPrefix = '+' + possibleCode;
                gsmCountry = 'Unknown';
                gsmNumber = cleanPhone.substring(4);
            }
        } else {
            // No + sign, try to detect country code
            let matched = false;
            for (const [code, info] of Object.entries(countryCodes)) {
                if (cleanPhone.startsWith(code)) {
                    gsmPrefix = info.prefix;
                    gsmCountry = info.country;
                    gsmNumber = cleanPhone.substring(info.length);
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                // Check if starts with 0 (local format)
                if (cleanPhone.startsWith('0')) {
                    // Assume Morocco local format
                    gsmPrefix = '+212';
                    gsmCountry = 'Morocco';
                    gsmNumber = cleanPhone; // Keep the 0 for local format
                } else {
                    // No recognizable format, assume Morocco
                    gsmPrefix = '+212';
                    gsmCountry = 'Morocco';
                    gsmNumber = cleanPhone;
                }
            }
        }

        // Clean up gsmNumber - remove leading zeros if in international format
        if (!phone.startsWith('0') && gsmNumber.startsWith('0')) {
            gsmNumber = gsmNumber.substring(1);
        }

        console.log('SMS Service: Parsed phone number:', {
            original: phone,
            cleaned: cleanPhone,
            gsmPrefix,
            gsmCountry,
            gsmNumber
        });

        return { gsmNumber, gsmPrefix, gsmCountry };
    }

    /**
     * Process SMS message with data substitution
     * Supports Handlebars-style variables
     */
    private processMessage(message: string, data: NotificationData): string {
        let processedMessage = message;

        // Handle nested properties (e.g., {{client.name}})
        const nestedPattern = /\{\{([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_.]*)\}\}/g;
        processedMessage = processedMessage.replace(nestedPattern, (match, path) => {
            const keys = path.split('.');
            let value: any = data;
            
            for (const key of keys) {
                if (value && typeof value === 'object' && key in value) {
                    value = value[key];
                } else {
                    return match; // Keep original if path not found
                }
            }
            
            return value !== undefined && value !== null ? String(value) : match;
        });

        // Handle simple variables (e.g., {{name}})
        const simplePattern = /\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g;
        processedMessage = processedMessage.replace(simplePattern, (match, varName) => {
            return data[varName] !== undefined && data[varName] !== null ? String(data[varName]) : match;
        });

        return processedMessage;
    }

    /**
     * Validate phone number format
     */
    validatePhoneNumber(phone: string): { isValid: boolean; error?: string } {
        if (!phone || phone.trim().length === 0) {
            return { isValid: false, error: 'Phone number is empty' };
        }

        // Remove all non-digit characters except +
        const cleanPhone = phone.replace(/[^\d+]/g, '');

        if (cleanPhone.length < 8) {
            return { isValid: false, error: 'Phone number is too short' };
        }

        if (cleanPhone.length > 15) {
            return { isValid: false, error: 'Phone number is too long' };
        }

        return { isValid: true };
    }

    /**
     * Calculate SMS message parts (for multi-part messages)
     */
    calculateMessageParts(message: string): { parts: number; length: number; encoding: string } {
        const length = message.length;
        
        // Check if message contains unicode characters
        const hasUnicode = /[^\x00-\x7F]/.test(message);
        
        if (hasUnicode) {
            // Unicode messages: 70 chars per part, 67 for multi-part
            const charsPerPart = length <= 70 ? 70 : 67;
            return {
                parts: Math.ceil(length / charsPerPart),
                length,
                encoding: 'unicode'
            };
        } else {
            // GSM-7 encoding: 160 chars per part, 153 for multi-part
            const charsPerPart = length <= 160 ? 160 : 153;
            return {
                parts: Math.ceil(length / charsPerPart),
                length,
                encoding: 'gsm7'
            };
        }
    }
}

/**
 * Multi-Channel Notification Service
 */
class NotificationService {
    private emailService: EmailService;
    private smsService: SmsService;
    private config: NotificationConfig;

    constructor(config: NotificationConfig) {
        this.config = config;
        this.emailService = new EmailService(config);
        this.smsService = new SmsService(config);
    }

    /**
     * Process notification message across multiple channels
     */
    async processMessage(body: MessageBody): Promise<any> {
        const { notificationType, channels, content, priority = 'medium' } = body;
        console.log(`Processing ${notificationType} notification via channels: ${channels.join(', ')}`);

        const results: any[] = [];
        const errors: any[] = [];

        for (const channel of channels) {
            try {
                let result: any;

                switch (channel) {
                    case 'email':
                        if (content.email) {
                            if (!this.emailService.validateContent(content.email)) {
                                throw new Error('Invalid email content structure');
                            }
                            result = await this.emailService.sendNotification(
                                content.email
                            );
                        } else {
                            throw new Error('Email content not provided for email channel');
                        }
                        break;

                    case 'sms':
                        if (content.sms) {
                            if (!this.smsService.validateContent(content.sms)) {
                                throw new Error('Invalid SMS content structure');
                            }
                            
                            // Validate phone number before sending
                            const recipientPhone = this.smsService.extractRecipient(content.sms);
                            const phoneValidation = this.smsService.validatePhoneNumber(recipientPhone);
                            
                            if (!phoneValidation.isValid) {
                                throw new Error(`Invalid phone number: ${phoneValidation.error}`);
                            }
                            
                            // Calculate message parts
                            const messageParts = this.smsService.calculateMessageParts(content.sms.message);
                            console.log('SMS message analysis:', messageParts);
                            
                            result = await this.smsService.sendNotification(
                                content.sms,
                                content.sms.data,
                                content.sms.metadata || {}
                            );
                        } else {
                            throw new Error('SMS content not provided for SMS channel');
                        }
                        break;
                    case 'push':
                        // Future implementation
                        result = {
                            channel: 'push',
                            status: 'not_implemented',
                            message: 'Push notifications are not implemented yet'
                        };
                        break;

                    case 'webhook':
                        // Future implementation
                        result = {
                            channel: 'webhook',
                            status: 'not_implemented',
                            message: 'Webhook notifications are not implemented yet'
                        };
                        break;

                    default:
                        throw new Error(`Unsupported notification channel: ${channel}`);
                }

                results.push(result);
                console.log(`${channel} notification processed:`, result);

            } catch (error) {
                const errorResult = {
                    channel,
                    status: 'error',
                    error: error instanceof Error ? error.message : 'Unknown error'
                };

                errors.push(errorResult);
                console.error(`Error processing ${channel} notification:`, error);
            }
        }

        return {
            notificationType,
            channels: channels,
            priority,
            results,
            errors,
            summary: {
                total: channels.length,
                successful: results.filter(r => r.status === 'sent').length,
                failed: errors.length,
                notSupported: results.filter(r => ['not_supported', 'not_implemented'].includes(r.status)).length
            },
            processedAt: new Date().toISOString()
        };
    }

    /**
     * Validate notification request
     */
    private validateNotificationRequest(body: MessageBody): void {
        if (!body.notificationType) {
            throw new Error('notificationType is required');
        }

        if (!body.channels || !Array.isArray(body.channels) || body.channels.length === 0) {
            throw new Error('channels array is required and must not be empty');
        }

        if (!body.content) {
            throw new Error('content is required');
        }

        // Validate that content exists for requested channels
        for (const channel of body.channels) {
            switch (channel) {
                case 'email':
                    if (!body.content.email) {
                        throw new Error(`Email content is required when email channel is specified`);
                    }
                    break;
                case 'sms':
                    if (!body.content.sms) {
                        throw new Error(`SMS content is required when SMS channel is specified`);
                    }
                    break;
                // Add validation for other channels as they're implemented
            }
        }
    }

    /**
     * Get service status
     */
    getServiceStatus(): Record<string, any> {
        return {
            email: {
                status: this.config.EMAIL_API_KEY ? 'active' : 'inactive',
                provider: 'Brevo',
                features: ['html_templates', 'attachments', 'handlebars_templating']
            },
            sms: {
                status: 'not_supported',
                provider: 'none',
                message: 'SMS service is not implemented yet'
            },
            push: {
                status: 'not_implemented',
                provider: 'none',
                message: 'Push notifications are not implemented yet'
            },
            webhook: {
                status: 'not_implemented',
                provider: 'none',
                message: 'Webhook notifications are not implemented yet'
            }
        };
    }
}

/**
 * Message Processor Class - Handles Lambda event processing
 */
class MessageProcessor {
    private notificationService: NotificationService;

    constructor(notificationService: NotificationService) {
        this.notificationService = notificationService;
    }

    /**
     * Process Lambda event
     */
    async processEvent(event: any): Promise<any> {
        console.log("Event received:", JSON.stringify(event, null, 2));

        try {
            if (event.Records) {
                // SQS event - process multiple messages
                const results = await Promise.all(
                    event.Records.map(async (record: any) => {
                        const body = JSON.parse(record.body);
                        return await this.notificationService.processMessage(body);
                    })
                );

                return SuccessResponse({
                    message: "Notifications processed successfully",
                    data: results
                });
            } else if (event.body) {
                // API Gateway event - process single message
                const body = JSON.parse(event.body);
                const result = await this.notificationService.processMessage(body);

                return SuccessResponse({
                    message: "Notification processed successfully",
                    data: result
                });
            } else if (event.notificationType) {
                // Direct invocation with notification data
                const result = await this.notificationService.processMessage(event);

                return SuccessResponse({
                    message: "Notification processed successfully",
                    data: result
                });
            } else {
                throw new Error("Unsupported event format. Expected SQS records, API Gateway body, or direct notification data.");
            }
        } catch (error) {
            console.error("Error processing notification:", error);
            throw error;
        }
    }

    /**
     * Get service health status
     */
    getHealthStatus(): any {
        return {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            services: this.notificationService.getServiceStatus()
        };
    }
}

/**
 * Lambda handler function
 */
const NotificationHandler = async (event: any): Promise<any> => {
    const notificationService = new NotificationService(CONFIG);
    const messageProcessor = new MessageProcessor(notificationService);

    // Handle health check requests
    if (event.httpMethod === 'GET' && event.path === '/health') {
        return SuccessResponse(messageProcessor.getHealthStatus());
    }

    return await messageProcessor.processEvent(event);
};

// Export the handler wrapped with middleware
export const handler = lambdaMiddleware(NotificationHandler);