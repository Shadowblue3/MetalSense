const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const officialSchema = new Schema({
  name: String,
  userEmail: String,
  designation: String,
  state: String,
  district: String,
  department: String,
  id: String,
  phone: Number,
  password: String,
  confirmPassword: String,
});

const officialModel = mongoose.model('official', officialSchema)
module.exports = officialModel;