import mongoose from "mongoose";

export default async function connect() {
    mongoose.connect("mongodb://localhost:27017/ipmanager")
        .then(m => m.connection.getClient())
        .catch(console.error);
}