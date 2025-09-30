const mongoose = require('mongoose');

// Schema for Disease_Data collection
const DiseaseDataSchema = new mongoose.Schema(
  {
    Column1: { type: Number },
    week_of_outbreak: { type: String },
    state_ut: { type: String, index: true },
    district: { type: String, index: true },
    Disease: { type: String, index: true },
    Cases: { type: Number, default: 0 },
    Deaths: { type: Number, default: 0 },
    day: { type: Number },
    mon: { type: Number, min: 1, max: 12, index: true },
    year: { type: Number, index: true },
    Latitude: { type: Number },
    Longitude: { type: Number },
    preci: { type: Number },
    LAI: { type: Number },
    Temp: { type: Number },
  },
  {
    collection: 'Disease_Data',
    timestamps: true,
  }
);

// Export model as dataModel
const dataModel = mongoose.model('Disease_Data', DiseaseDataSchema);
module.exports = dataModel;
