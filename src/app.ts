import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { SuccessResponse } from './utils/helper';
import { lambdaMiddleware } from './middleware/lambdaMiddleware';

const FunctionNameLambdaHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    //const { metadata, authorization } = extractAuthData(event.headers);
    const parsedBody = event.body ? JSON.parse(event.body) : {};

    // Validate required fields
    /* Example
    validateRequiredFields(
        {
            firstName: parsedBody.firstName,
            'location.coordinates': parsedBody.location?.coordinates
        },
        ['firstName', 'location.coordinates'],
        {
            firstName: 'firstName is required',
            'location.coordinates': 'coordinates is required'
        }
    );*/

    // connection & logic 

    return SuccessResponse({ message: 'Account created successfully', data: { /* return  */ } });

};

// Export the handler wrapped with the middleware
export const handler = lambdaMiddleware(FunctionNameLambdaHandler);