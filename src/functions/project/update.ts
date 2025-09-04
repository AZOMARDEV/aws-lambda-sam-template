import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { connectDB } from '../../utils/dbconnect';
import { SuccessResponse, validateRequiredFields } from '../../utils/helper';
import { createLogger } from '../../utils/logger';
import { parseRequestBody } from '../../utils/requestParser';
import HttpError from '../../exception/httpError';
import { lambdaMiddleware } from '../../middleware/lambdaMiddleware';
import { Types } from 'mongoose';
import ProjectSettingsModel, { IAuthSettings } from '../../models/project.schema';

// ==================== INTERFACES ====================

interface UpdateAuthSettingsRequest {
    id: string; // document _id
    settings: IAuthSettings; // AUTH settings to update
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

    private async updateSettingsInDB(): Promise<void> {
        this.logger.debug('Updating AUTH settings in DB', { id: this.requestData.id });
        this.settingsDoc.settings = this.requestData.settings;
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
