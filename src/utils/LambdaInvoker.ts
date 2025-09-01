import { Lambda } from 'aws-sdk';

export class LambdaInvoker {
    private lambdaClient: Lambda;

    constructor() {
        this.lambdaClient = new Lambda({
            region: process.env.AWS_REGION || 'us-east-1'
        });
    }

    async invoke(functionName: string, payload: any): Promise<any> {
        try {
            const result = await this.lambdaClient.invoke({
                FunctionName: functionName,
                InvocationType: "RequestResponse",
                Payload: JSON.stringify(payload),
            }).promise();

            if (!result.Payload) {
                throw new Error('Lambda invocation failed - no response');
            }

            const response = JSON.parse(result.Payload as string);

            if (response.statusCode !== 200) {
                const errorData = JSON.parse(response.body || '{}');
                throw new Error(errorData.message || 'Lambda function returned error');
            }

            return JSON.parse(response.body);
        } catch (error) {
            console.error('Lambda invocation failed:', error);
            throw error;
        }
    }
}