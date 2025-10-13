import mongoose from 'mongoose';

const historySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  file: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
  action: { type: String, enum: ['open'], required: true },
}, { timestamps: true });

const History = mongoose.model('History', historySchema);

export default History;

