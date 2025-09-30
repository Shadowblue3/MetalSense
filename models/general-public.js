const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const generalSchema = new Schema({
  name: String,
  phoneNo: Number,
  userEmail: String,
  state: String,
  district: String,
  Area: String,
  password: String,
  confirmPassword: String,
});

const generalModel = mongoose.model('general', generalSchema)
module.exports = generalModel;