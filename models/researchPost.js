const mongoose = require('mongoose');

const ResearchPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  abstract: { type: String },
  content: { type: String },
  tags: { type: [String], default: [] },
  authorId: { type: String },
  authorEmail: { type: String },
  authorName: { type: String },
}, {
  timestamps: true,
  collection: 'research_posts'
});

module.exports = mongoose.model('research_post', ResearchPostSchema);
