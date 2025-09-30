const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const commentSchema = new Schema({
  text: String,
  authorId: String,
  authorRole: { type: String, enum: ['master', 'official'] },
  authorName: String,
}, { timestamps: { createdAt: true, updatedAt: false } });

const communicationSchema = new Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  category: { type: String, enum: ['water', 'disease', 'general'], default: 'general' },
  state: String,
  district: String,
  authorId: String,
  authorRole: { type: String, enum: ['master', 'official'], required: true },
  authorName: String,
  comments: [commentSchema]
}, { timestamps: true });

module.exports = mongoose.model('communications', communicationSchema);
