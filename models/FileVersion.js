/**
 * FileVersion Model
 * 
 * Tracks version history for files
 * Every time a file is uploaded or updated, a new version entry is created
 * Allows users to view and revert to previous file versions
 * 
 * Collection: fileversions
 * 
 * Purpose:
 * - Store metadata about each version of a file
 * - Link to Cloudinary storage location for each version
 * - Track who uploaded each version and when
 * - Display version history in UI for user to select/revert
 * 
 * Relationship:
 * - file: References the File document this version belongs to
 * - uploadedBy: References the User who uploaded this version
 * - Created automatically when file is uploaded via /api/files/upload
 */

import mongoose from 'mongoose';

const fileVersionSchema = new mongoose.Schema({
  /**
   * @property {ObjectId} file
   * Reference to the File document this version belongs to
   * When file has 3 versions, 3 separate FileVersion docs exist with same file reference
   * Required: Yes - every version must be tied to a file
   */
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true
  },

  /**
   * @property {Number} versionNumber
   * Sequential version number within this file
   * Version 1 = original upload, Version 2 = first re-upload, etc.
   * Helps identify which version is newest
   * Required: Yes
   */
  versionNumber: {
    type: Number,
    required: true
  },

  /**
   * @property {String} cloudinaryUrl
   * Public URL for this specific version in Cloudinary storage
   * Used to display, download, or view specific version
   * Example: https://res.cloudinary.com/account/image/upload/v1234567890/mern-drive/file_id.pdf
   * Required: Yes - must have valid URL for retrieval
   */
  cloudinaryUrl: {
    type: String,
    required: true
  },

  /**
   * @property {String} cloudinaryPublicId
   * Cloudinary's internal asset identifier
   * Used to delete version from Cloudinary storage
   * Format: folder/asset_name (e.g., 'mern-drive/507f1f77bcf86cd799439011')
   * Required: Yes - must be stored for deletion ops
   */
  cloudinaryPublicId: {
    type: String,
    required: true
  },

  /**
   * @property {String} fileType
   * Type of file (image, pdf, video, etc.)
   * Populated from Cloudinary's resource_type field
   * Used for determining how to display/preview in UI
   * Examples: 'image', 'pdf', 'video'
   * Optional: Some legacy versions may not have this
   */
  fileType: {
    type: String
  },

  /**
   * @property {Number} size
   * File size in bytes
   * Useful for displaying file size in version history
   * Shows user how much space different versions use
   * Optional: Some versions may not have this recorded
   */
  size: {
    type: Number
  },

  /**
   * @property {ObjectId} uploadedBy
   * Reference to User who uploaded this version
   * Allows attribution in version history (shows who uploaded each version)
   * Used for audit logging
   * Required: Yes - must know who made each version
   */
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

}, {
  timestamps: true // Auto-adds createdAt and updatedAt
});

/**
 * Indexes for Performance
 * (Can be added if collection grows large)
 * 
 * Would want:
 * - { file: 1, versionNumber: -1 } for quick version list queries
 * - { createdAt: -1 } for recent versions queries
 * - { uploadedBy: 1 } for tracking versions uploaded by specific user
 */

const FileVersion = mongoose.model('FileVersion', fileVersionSchema);

export default FileVersion;


