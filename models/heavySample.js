const mongoose = require('mongoose');

// Flexible schema for heavy metal sampling data in the same 'Disease_Data' collection
// This schema is permissive (strict: false) to accommodate any additional fields present.
const HeavySampleSchema = new mongoose.Schema(
  {
    sample_id: { type: Number },
    location: { type: String },
    latitude: { type: Number },
    longitude: { type: Number },
    year: { type: Number },
    month: { type: Number, min: 1, max: 12 },
    pH: { type: Number },
    EC: { type: Number },

    As: { type: Number },
    Cd: { type: Number },
    Cr: { type: Number },
    Cu: { type: Number },
    Pb: { type: Number },
    Zn: { type: Number },
    Ni: { type: Number },

    Background_As: { type: Number },
    Background_Cd: { type: Number },
    Background_Cr: { type: Number },
    Background_Cu: { type: Number },
    Background_Pb: { type: Number },
    Background_Zn: { type: Number },
    Background_Ni: { type: Number },
  },
  {
    collection: 'Disease_Data',
    strict: false, // allow any additional fields to pass through
    timestamps: true,
  }
);

module.exports = mongoose.model('HeavySample', HeavySampleSchema);
