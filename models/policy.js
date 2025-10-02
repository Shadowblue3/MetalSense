const mongoose = require('mongoose');

const PolicySchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  description: { type: String, required: true, trim: true, maxlength: 10000 },
  createdBy: { type: String, default: null }, // GOV ID or email of creator
  resolved: { type: Boolean, default: false }
}, {
  timestamps: true // adds createdAt and updatedAt
});

module.exports = mongoose.model('Policy', PolicySchema);
