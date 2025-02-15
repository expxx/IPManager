import { model, Schema } from "mongoose";

const schema = new Schema({
    IP: String,
    country: String,
    region: String,
    city: String,
    asn: String,
    
    crawler: Boolean,
    proxy: Boolean,
    vpn: Boolean,
    tor: Boolean,

    created: Date,
    updated: Date,
})

schema.on('pre', function(next) {
    this.updated = new Date();
    next()
});

export default model('Quality', schema);