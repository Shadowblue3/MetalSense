const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const postSchema = new Schema({
    title: String,
    region: String,
    body: String,
    symptoms: [String],
    type: String,
    waterSource: String,
    affectedCount: String,
    imageUrl: String,
    resolved: { type: Boolean, default: false },
    latitude: Number,
    longitude: Number,
    assignedOfficerId: { type: String, default: null },
});

const postModel = mongoose.model('posts', postSchema)
module.exports = postModel;