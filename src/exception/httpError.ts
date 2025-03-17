// Define a custom error class
class HttpError extends Error {
    status: number;
    data?: any;

    constructor(message: string, status: number) {
        super(message); // Pass the message to the base Error class
        this.status = status;
        this.name = "HttpError"; // Set the error name to HttpError
    }
}

export default HttpError;
