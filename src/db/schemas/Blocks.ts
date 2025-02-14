import { model, Schema } from "mongoose";

const blocksSchema = new Schema({
    IPHash: { type: String, required: true },
})

export default model('Blocks', blocksSchema);