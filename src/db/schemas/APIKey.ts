import { model, Schema } from "mongoose";

const schema = new Schema({
    assignee_email: String,
    key: String,
    usage: {
        requests: Number,
    },
    created: Date,
    updated: Date,
})

schema.on('pre', function(next) {
    this.updated = new Date();
    next()
});

export default model('APIKey', schema);