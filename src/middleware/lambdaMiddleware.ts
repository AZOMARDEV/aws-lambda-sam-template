import HttpError from "../exception/httpError";
import { ErrorResponse } from "../utils/helper";

// Error handling middleware for Lambda functions
export const lambdaMiddleware = (handler: Function) => {
    return async (event: any, context: any) => {
        try {
            // Call the actual Lambda function (handler)
            return await handler(event, context);
        } catch (err) {
            // Handle HttpError with additional error data
            if (err instanceof HttpError) {
                return ErrorResponse({
                    status: err?.status,
                    message: err?.message,
                    data: err
                });
            }

            // Log the error and return a generic response for unexpected errors
            console.error("Unexpected error:", err);
            return ErrorResponse({
                status: 500,
                message: 'Internal Server Error',
                data: err
            });
        }
    };
};
