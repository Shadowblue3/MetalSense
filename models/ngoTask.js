const mongoose = require('mongoose');

const NgoTaskSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  description: { type: String, required: true, trim: true, maxlength: 10000 },
  ngoId: { type: String, required: true, index: true }, // Target NGO unique code (e.g., NGOXXXXXX)
  assignedBy: { type: String, required: true, index: true }, // Official/admin ID assigning the task
  status: { type: String, enum: ['assigned', 'in-progress', 'completed', 'cancelled'], default: 'assigned', index: true },
  dueDate: { type: Date },
}, {
  timestamps: true,
  collection: 'ngo_tasks'
});

module.exports = mongoose.model('ngo_task', NgoTaskSchema);
