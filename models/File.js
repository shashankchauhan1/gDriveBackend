// server/models/File.js
import mongoose from 'mongoose';

// File schema for storing file and folder metadata
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true }, // Name of file or folder
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // User who owns the file
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'File', default: null }, // Parent folder (if any)

  // Type: 'file' or 'folder'
  type: { type: String, enum: ['file', 'folder'], required: true },

  // File-specific fields (not required for folders)
  cloudinaryUrl: { type: String }, // URL from Cloudinary
  cloudinaryPublicId: { type: String }, // Cloudinary public ID
  fileType: { type: String }, // MIME type
  size: { type: Number }, // File size in bytes
  currentVersion: { type: mongoose.Schema.Types.ObjectId, ref: 'FileVersion' },
  versionCount: { type: Number, default: 0 },

  // Permissions for sharing
  permissions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: { type: String, enum: ['viewer', 'editor'], default: 'viewer' }
  }],

  // Trash support
  isTrashed: { type: Boolean, default: false },
  trashedAt: { type: Date }

}, { timestamps: true }); // Adds createdAt and updatedAt

const File = mongoose.model('File', fileSchema);

export default File;