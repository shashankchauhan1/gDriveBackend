import mongoose from 'mongoose';

const fileVersionSchema = new mongoose.Schema({
  file: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
  versionNumber: { type: Number, required: true },
  cloudinaryUrl: { type: String, required: true },
  cloudinaryPublicId: { type: String, required: true },
  fileType: { type: String },
  size: { type: Number },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

const FileVersion = mongoose.model('FileVersion', fileVersionSchema);

export default FileVersion;


