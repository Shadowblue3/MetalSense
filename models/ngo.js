const mongoose = require('mongoose');

const NgoSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  id: { type: String, index: true, unique: true },
  registrationNo: { type: String, unique: true },
  focusAreas: { type: [String], default: [] },
  state: { type: String },
  district: { type: String },
  password: { type: String, required: true },
}, {
  timestamps: true,
  collection: 'ngos'
});

module.exports = mongoose.model('ngo', NgoSchema);
