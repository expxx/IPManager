import mongoose from "mongoose";
import dotenv from 'dotenv';
dotenv.config();

export default async function connect() {
    mongoose.connect(process.env.MONGO_URL || "mongodb://localhost:27017/ipmanager")
        .then(m => m.connection.getClient())
        .catch(console.error);
}