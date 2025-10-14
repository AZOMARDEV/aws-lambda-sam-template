import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, ErrorResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Types } from 'mongoose';
import ProjectSettingsModel, { IAuthSettings } from '../../models/project.schema';

// ==================== INTERFACES ====================

interface UpdateAuthSettingsRequest {
    id: string; // document _id
    settings: Partial<IAuthSettings>; // Partial AUTH settings to update
}

interface UpdateAuthSettingsResponse {
    id: string;
    status: string;
    message: string;
    data: any;
}

// ==================== BUSINESS HANDLER ====================

class UpdateAuthSettingsHandler {
    private requestData: UpdateAuthSettingsRequest;
    private logger: ReturnType<typeof createLogger>;
    private settingsDoc: any;

    constructor(event: APIGatewayProxyEvent, body: UpdateAuthSettingsRequest) {
        const requestId = event.requestContext?.requestId || 'unknown';
        this.requestData = body;
        this.logger = createLogger('project-service', requestId);
        this.logger.appendPersistentKeys({ functionName: 'update-auth-settings' });
    }

    async processRequest(): Promise<UpdateAuthSettingsResponse> {
        this.logger.info('Starting update AUTH settings process');

        this.validateRequestData();
        await this.loadSettings();
        this.mergeAndValidateSettings();
        this.validateAuthFlowLogic();
        await this.updateSettingsInDB();

        const responseData = this.prepareResponseData();
        this.logger.info('Update AUTH settings completed successfully', { id: this.settingsDoc._id });
        return responseData;
    }

    private validateRequestData(): void {
        const requiredFields = ['id', 'settings'];
        validateRequiredFields(this.requestData, requiredFields, {
            id: 'Document ID is required',
            settings: 'Settings object is required'
        });

        if (!Types.ObjectId.isValid(this.requestData.id)) {
            throw new HttpError('Invalid ID format', 400);
        }

        const { settings } = this.requestData;

        // Validate email settings structure if provided
        if (settings.emailSettings) {
            this.validateEmailSettings(settings.emailSettings);
        }

        // Validate SMS settings structure if provided
        if (settings.smsSettings) {
            this.validateSMSSettings(settings.smsSettings);
        }
    }

    private async loadSettings(): Promise<void> {
        this.logger.debug('Loading AUTH settings', { id: this.requestData.id });
        this.settingsDoc = await ProjectSettingsModel.findById(this.requestData.id);
        if (!this.settingsDoc) {
            throw new HttpError('AUTH settings not found', 404);
        }
        if (this.settingsDoc.category !== 'AUTH') {
            throw new HttpError('Document category mismatch', 400);
        }
    }

    private mergeAndValidateSettings(): void {
        // Deep merge the existing settings with the new partial settings
        const existingSettings = this.settingsDoc.settings.toObject();
        const updatedSettings = this.deepMerge(existingSettings, this.requestData.settings);

        // Ensure all required objects exist with proper defaults
        this.ensureRequiredAuthObjects(updatedSettings);

        // Update the document with merged settings
        this.settingsDoc.settings = updatedSettings;

        this.logger.info('Settings merged successfully');
    }

    private deepMerge(target: any, source: any): any {
        const result = { ...target };

        for (const key in source) {
            if (source.hasOwnProperty(key)) {
                if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                    result[key] = this.deepMerge(target[key] || {}, source[key]);
                } else {
                    result[key] = source[key];
                }
            }
        }

        return result;
    }

    private ensureRequiredAuthObjects(settings: any): void {
        // Auto-create traditionalFlow if missing
        if (!settings.traditionalFlow) {
            settings.traditionalFlow = {
                enabled: false,
                registration: {
                    requiredFields: ["email", "password", "firstName", "lastName"],
                    optionalFields: ["phone", "dateOfBirth"],
                    verificationRequired: true,
                    termsAcceptanceRequired: true
                },
                loginMethods: ["EMAIL"],
                allowGuestMode: false,
                accountActivationFlow: "EMAIL"
            };
            this.logger.info('Auto-created traditionalFlow with enabled: false');
        }

        // Auto-create ssoFlow if missing
        if (!settings.ssoFlow) {
            settings.ssoFlow = {
                enabled: false,
                providers: [],
                requireProfileCompletion: false,
                profileCompletionFields: []
            };
            this.logger.info('Auto-created ssoFlow with enabled: false');
        }

        // Auto-create mfa if missing
        if (!settings.mfa) {
            settings.mfa = {
                enabled: false,
                mandatory: false,
                methods: ["SMS"],
                requireProfileCompletion: false,
                profileCompletionFields: [],
                trustedDevices: {
                    enabled: true,
                    defaultExpirationDays: 30,
                    maxTrustedDevices: 5,
                    requireReauth: false
                }
            };
            this.logger.info('Auto-created mfa with enabled: false');
        }

        // Auto-create passwordPolicy if missing
        if (!settings.passwordPolicy) {
            settings.passwordPolicy = {
                minLength: 8,
                requireUppercase: true,
                requireLowercase: true,
                requireNumbers: true,
                requireSymbols: false,
                forbiddenPasswords: [],
                preventReuse: 5,
                passwordExpiryDays: 0,
                strengthMeter: true
            };
            this.logger.info('Auto-created passwordPolicy with defaults');
        }

        // Auto-create sessionManagement if missing
        if (!settings.sessionManagement) {
            settings.sessionManagement = {
                maxSessionDurationHours: 24,
                idleTimeoutMinutes: 30,
                revocationOnPasswordChange: true,
                deviceRecognition: true,
                concurrentSessionLimit: 5,
                rememberMe: {
                    enabled: true,
                    durationDays: 30
                },
                securitySettings: {
                    httpOnly: true,
                    secure: true,
                    sameSite: "lax"
                }
            };
            this.logger.info('Auto-created sessionManagement with defaults');
        }

        // Auto-create emailSettings if missing
        if (!settings.emailSettings) {
            settings.emailSettings = {
                provider: "smtp",
                fromAddress: "noreply@example.com",
                templates: {}
            };
            this.logger.info('Auto-created emailSettings with defaults');
        }

        // Auto-create smsSettings if missing
        if (!settings.smsSettings) {
            settings.smsSettings = {
                provider: "twilio",
                templates: {}
            };
            this.logger.info('Auto-created smsSettings with defaults');
        }
    }

    private validateAuthFlowLogic(): void {
        const { traditionalFlow, ssoFlow, mfa } = this.settingsDoc.settings;

        // Rule: Cannot have both traditional flow AND MFA both enabled as true
        if (traditionalFlow.enabled === true && mfa.enabled === true) {
            throw new HttpError('Traditional flow and MFA cannot both be enabled. Choose either Traditional + SSO, or SSO + MFA.', 400);
        }

        // Ensure at least one authentication method is enabled
        if (!traditionalFlow.enabled && !ssoFlow.enabled) {
            throw new HttpError('At least one authentication flow (traditional or SSO) must be enabled', 400);
        }

        // Valid combinations:
        // 1. Traditional + SSO (MFA disabled)
        // 2. SSO + MFA (Traditional disabled)
        // 3. Traditional only (SSO and MFA disabled)
        // 4. SSO only (Traditional and MFA disabled)

        this.logger.info('Auth flow validation passed', {
            traditional: traditionalFlow.enabled,
            sso: ssoFlow.enabled,
            mfa: mfa.enabled
        });
    }

    private validateEmailSettings(emailSettings: any): void {
        if (emailSettings.provider && !emailSettings.provider.trim()) {
            throw new HttpError('Email provider cannot be empty', 400);
        }

        if (emailSettings.fromAddress) {
            // Validate email address format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(emailSettings.fromAddress)) {
                throw new HttpError('Invalid email address format for fromAddress', 400);
            }
        }

        // Validate templates structure - should contain template names as keys
        if (emailSettings.templates && typeof emailSettings.templates !== 'object') {
            throw new HttpError('Email templates must be an object with template names as keys', 400);
        }

        // Log template structure for debugging
        if (emailSettings.templates && Object.keys(emailSettings.templates).length > 0) {
            this.logger.info('Email templates configured', {
                templateNames: Object.keys(emailSettings.templates)
            });
        }
    }

    private validateSMSSettings(smsSettings: any): void {
        if (smsSettings.provider && !smsSettings.provider.trim()) {
            throw new HttpError('SMS provider cannot be empty', 400);
        }

        // Validate templates structure - should contain message text as values
        if (smsSettings.templates && typeof smsSettings.templates !== 'object') {
            throw new HttpError('SMS templates must be an object with template keys and message text as values', 400);
        }

        // Validate that SMS templates contain actual message text
        if (smsSettings.templates) {
            for (const [templateName, messageText] of Object.entries(smsSettings.templates)) {
                if (typeof messageText !== 'string' || !messageText.trim()) {
                    throw new HttpError(`SMS template '${templateName}' must contain valid message text`, 400);
                }
            }
        }

        // Log template structure for debugging
        if (smsSettings.templates && Object.keys(smsSettings.templates).length > 0) {
            this.logger.info('SMS templates configured', {
                templateNames: Object.keys(smsSettings.templates)
            });
        }
    }

    private async updateSettingsInDB(): Promise<void> {
        this.logger.debug('Updating AUTH settings in DB', { id: this.requestData.id });
        await this.settingsDoc.save();
    }

    private prepareResponseData(): UpdateAuthSettingsResponse {
        return {
            id: this.settingsDoc._id.toString(),
            status: 'success',
            message: 'AUTH settings updated successfully',
            data: this.settingsDoc.toObject()
        };
    }
}

// ==================== LAMBDA HANDLER ====================

const UpdateAuthSettingsLambda = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const logger = createLogger('project-service', event.requestContext?.requestId || 'unknown');
    logger.info('Handler started');

    await connectDB();
    const parsedBody = parseRequestBody<UpdateAuthSettingsRequest>(event, logger);

    const handler = new UpdateAuthSettingsHandler(event, parsedBody);
    const result = await handler.processRequest();

    logger.info('Handler finished successfully');
    return SuccessResponse({ message: 'AUTH settings updated', data: result });

};

export const handler = lambdaMiddleware(UpdateAuthSettingsLambda, {
    serviceName: 'project-service',
    enableRequestLogging: true,
    enableResponseLogging: true,
    enablePerformanceLogging: true,
    logLevel: 'info'
});