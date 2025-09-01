import mongoose from "mongoose";
import HttpError from "../exception/httpError";

let cachedDb: mongoose.mongo.Db | null | undefined = null;
const MONGODB_URI: string = process.env.MONGODB_URI ?? "";

export const connectDB = async () => {
    try {
        if (cachedDb) return cachedDb;
        const client = await mongoose.connect(MONGODB_URI, {
            serverSelectionTimeoutMS: 5000 * 60,
        });
        cachedDb = client.connection.db;
        return cachedDb;

    } catch (error) {
        console.error('MongoDB connection error:', error);
        throw new HttpError(`MongoDB connection error: ${error} `, 400);

    }
};