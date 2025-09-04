import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, ErrorResponse } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import ProjectSettingsModel, { IAuthSettings } from '../../models/project.schema';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';

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

    if (!this.requestData.settings) {
      throw new Error('settings field is required');
    }

    // Check if AUTH category already exists
    const existingAuthSettings = await ProjectSettingsModel.findOne({
      category: this.requestData.category
    });

    if (existingAuthSettings) {
      this.logger.warn(`AUTH settings already exist with ID: ${existingAuthSettings._id}`);
      throw new Error(`Project settings for category '${this.requestData.category}' already exists. Use update operation instead.`);
    }

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
        throw new Error(`Project settings for category '${this.requestData.category}' already exists. Use update operation instead.`);
      }

      // Re-throw other errors
      this.logger.error(`Error creating AUTH settings: ${error.message}`);
      throw error;
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