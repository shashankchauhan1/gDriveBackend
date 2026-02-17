/**
 * File Model
 * 
 * Represents both files and folders in the Cloud-Box drive
 * Handles metadata, permissions, versioning, and trash management
 * 
 * This is a unified model where:
 * - type: 'file' = uploaded file with Cloudinary storage
 * - type: 'folder' = directory for organizing files
 * 
 * Features:
 * - Hierarchical folder structure via parentId
 * - Permission-based sharing (viewer/editor roles)
 * - File versioning support
 * - Soft delete with trash functionality
 */

import mongoose from 'mongoose';

/**
 * File/Folder Schema Definition
 * 
 * @typedef {Object} File
 * @property {String} filename - Name of file or folder
 * @property {ObjectId} owner - User who owns this file
 * @property {ObjectId} parentId - Parent folder ID (hierarchical structure)
 * @property {String} type - 'file' or 'folder'
 * @property {String} cloudinaryUrl - Public URL of file (files only)
 * @property {String} cloudinaryPublicId - Cloudinary identifier (files only)
 * @property {String} fileType - MIME type (files only)
 * @property {Number} size - File size in bytes (files only)
 * @property {Array} permissions - Share settings with other users
 * @property {Boolean} isTrashed - Soft delete flag
 * @property {Date} createdAt - Auto-generated creation timestamp
 * @property {Date} updatedAt - Auto-generated update timestamp
 */
const fileSchema = new mongoose.Schema({
  /**
   * Filename
   * Name of the file or folder displayed to users
   */
  filename: { 
    type: String, 
    required: [true, 'Filename is required'],
    trim: true,
    maxlength: [255, 'Filename cannot exceed 255 characters']
  },

  /**
   * Owner
   * Reference to User who owns this file
   * Only owner can delete or permanently share
   */
  owner: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'Owner is required']
  },

  /**
   * Parent ID
   * References parent folder for hierarchical structure
   * null = file is at root level
   */
  parentId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'File', 
    default: null 
  },

  /**
   * Type
   * Determines if this is a file or folder
   * Folders don't have Cloudinary metadata
   */
  type: { 
    type: String, 
    enum: ['file', 'folder'], 
    required: [true, 'Type must be either "file" or "folder"'],
    default: 'file'
  },

  /**
   * Cloudinary URL
   * Public URL to access the file
   * Only populated for files (type: 'file')
   */
  cloudinaryUrl: { 
    type: String 
  },

  /**
   * Cloudinary Public ID
   * Unique identifier from Cloudinary service
   * Used for updating or deleting files
   */
  cloudinaryPublicId: { 
    type: String 
  },

  /**
   * File Type (MIME)
   * Example: 'image/png', 'application/pdf'
   * Only populated for files
   */
  fileType: { 
    type: String 
  },

  /**
   * File Size
   * Size in bytes
   * Only populated for files
   */
  size: { 
    type: Number,
    min: [0, 'File size cannot be negative']
  },

  /**
   * Current Version
   * Reference to latest FileVersion document
   * Used for version history tracking
   */
  currentVersion: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'FileVersion'
  },

  /**
   * Version Count
   * Tracks total number of versions
   * Incremented when file is updated
   */
  versionCount: { 
    type: Number, 
    default: 0,
    min: [0, 'Version count cannot be negative']
  },

  /**
   * Permissions
   * Array of objects representing users with access to this file
   * Each permission has user reference and access role
   * Inherited by children via role resolution
   */
  permissions: [{
    /**
     * User granted access
     */
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User' 
    },
    /**
     * Access role:
     * - 'viewer': Can only view/download
     * - 'editor': Can modify and re-share
     */
    role: { 
      type: String, 
      enum: ['viewer', 'editor'], 
      default: 'viewer' 
    }
  }],

  /**
   * Is Trashed
   * Soft delete flag - file not deleted, just hidden
   * Allows recovery from trash before permanent deletion
   */
  isTrashed: { 
    type: Boolean, 
    default: false,
    index: true // Index for faster trash lookup
  },

  /**
   * Trashed At
   * Timestamp when file was moved to trash
   * Used for trash retention policy
   */
  trashedAt: { 
    type: Date 
  }

}, { 
  timestamps: true // Automatically adds createdAt and updatedAt
});

/**
 * Index for efficient queries
 * Speed up common lookups by owner, parent, and type
 */
fileSchema.index({ owner: 1, parentId: 1, type: 1 });
fileSchema.index({ owner: 1, isTrashed: 1 });

/**
 * Create Model
 * Compiles schema into a model
 */
const File = mongoose.model('File', fileSchema);

export default File;