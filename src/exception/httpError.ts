// Define a custom error class
class HttpError extends Error {
    [x: string]: any;
    status: number;
    data?: any;
    code?: any;

    constructor(message: string, status: number , code?: any) {
        super(message); // Pass the message to the base Error class
        this.status = status;
        this.name = "HttpError"; // Set the error name to HttpError
        this.code = code;
    }
}

export default HttpError;
