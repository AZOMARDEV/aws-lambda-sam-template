import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, ErrorResponse } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import ProjectSettingsModel, { IAuthSettings } from '../../models/project.schema';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import HttpError from '../../exception/httpError';

// ==================== INTERFACES ====================

interface CreateAuthSettingsRequest {
  category: "AUTH";
  settings: IAuthSettings; // must match the schema
}

interface CreateAuthSettingsResponse {
  _id: any;
  status: string;
  message: string;
  data: any;
}

// ==================== BUSINESS HANDLER ====================

class CreateAuthSettingsHandler {
  private requestData: CreateAuthSettingsRequest;
  private logger: ReturnType<typeof createLogger>;

  constructor(event: APIGatewayProxyEvent, body: CreateAuthSettingsRequest) {
    const requestId = event.requestContext?.requestId || 'unknown';
    this.requestData = body;
    this.logger = createLogger('project-service', requestId);
    this.logger.appendPersistentKeys({ functionName: 'create-auth-settings' });
  }

  async processRequest(): Promise<CreateAuthSettingsResponse> {
    this.logger.info('Creating AUTH settings');

    this.validateRequestData();
    this.validateAuthFlowLogic();
    await this.checkIfAuthSettingsExist();

    try {
      const authSettingsDoc = new ProjectSettingsModel({
        category: this.requestData.category,
        settings: this.requestData.settings
      });

      await authSettingsDoc.save();

      this.logger.info(`AUTH settings created successfully with ID: ${authSettingsDoc._id}`);

      return {
        _id: authSettingsDoc._id,
        status: 'success',
        message: 'Project AUTH settings created successfully',
        data: authSettingsDoc.toObject()
      };

    } catch (error: any) {
      // Handle MongoDB duplicate key error (E11000) as a fallback
      if (error.code === 11000 && error.message.includes('category')) {
        this.logger.error('Duplicate category error caught during save operation');
        throw new HttpError(`Project settings for category '${this.requestData.category}' already exists. Use update operation instead.`, 409);
      }

      // Re-throw other errors
      this.logger.error(`Error creating AUTH settings: ${error.message}`);
      throw error;
    }
  }

  private validateRequestData(): void {
    if (!this.requestData.settings) {
      throw new HttpError('settings field is required', 400);
    }

    if (!this.requestData.category || this.requestData.category !== 'AUTH') {
      throw new HttpError('category must be "AUTH"', 400);
    }

    // Auto-create missing auth flow objects with enabled: false
    this.ensureRequiredAuthObjects();

    const { settings } = this.requestData;

    // Validate email settings structure
    if (settings.emailSettings) {
      this.validateEmailSettings(settings.emailSettings);
    }

    // Validate SMS settings structure
    if (settings.smsSettings) {
      this.validateSMSSettings(settings.smsSettings);
    }
  }

  private ensureRequiredAuthObjects(): void {
    const { settings } = this.requestData;

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
    const { traditionalFlow, ssoFlow, mfa } = this.requestData.settings;

    // Rule: Cannot have both traditional flow AND MFA both enabled as true
    if (traditionalFlow.enabled === true && mfa.enabled === true) {
      throw new HttpError('Traditional flow and MFA cannot both be enabled. Choose either Traditional + SSO, or SSO + MFA.', 400);
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
    if (!emailSettings.provider) {
      throw new HttpError('Email provider is required', 400);
    }

    if (!emailSettings.fromAddress) {
      throw new HttpError('Email fromAddress is required', 400);
    }

    // Validate email address format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailSettings.fromAddress)) {
      throw new HttpError('Invalid email address format for fromAddress', 400);
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
    if (!smsSettings.provider) {
      throw new HttpError('SMS provider is required', 400);
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

  private async checkIfAuthSettingsExist(): Promise<void> {
    const existingAuthSettings = await ProjectSettingsModel.findOne({
      category: this.requestData.category
    });

    if (existingAuthSettings) {
      this.logger.warn(`AUTH settings already exist with ID: ${existingAuthSettings._id}`);
      throw new HttpError(`Project settings for category '${this.requestData.category}' already exists. Use update operation instead.`, 409);
    }
  }
}

// ==================== LAMBDA HANDLER ====================

const CreateAuthSettingsLambda = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const logger = createLogger('project-service', event.requestContext?.requestId || 'unknown');
  logger.info('Handler started');

  await connectDB();
  const parsedBody = parseRequestBody<CreateAuthSettingsRequest>(event, logger);

  const handler = new CreateAuthSettingsHandler(event, parsedBody);
  const result = await handler.processRequest();

  logger.info('Handler finished successfully');
  return SuccessResponse({ message: 'Project AUTH settings created', data: result });
};

export const handler = lambdaMiddleware(CreateAuthSettingsLambda, {
  serviceName: 'project-service',
  enableRequestLogging: true,
  enableResponseLogging: true,
  enablePerformanceLogging: true,
  logLevel: 'info'
});