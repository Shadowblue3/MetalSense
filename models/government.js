const mongoose = require('mongoose');

const GovernmentSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String, required: true, index: true, unique: true },
  id: { type: String, index: true, unique: true },
  department: { type: String },
  state: { type: String },
  district: { type: String },
  phone: { type: Number },
  password: { type: String, required: true },
}, {
  timestamps: true,
  collection: 'government_users'
});

module.exports = mongoose.model('government_user', GovernmentSchema);
