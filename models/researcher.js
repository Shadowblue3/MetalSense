const mongoose = require('mongoose');

const ResearcherSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  id: { type: String, index: true, unique: true },
  affiliation: { type: String },
  state: { type: String },
  district: { type: String },
  password: { type: String, required: true },
}, {
  timestamps: true,
  collection: 'researchers'
});

module.exports = mongoose.model('researcher', ResearcherSchema);
