/**
 * History Model (Activity Log)
 * 
 * Records user interactions with files for audit logging and activity tracking
 * Currently tracks file open events, can be extended for other actions
 * 
 * Collection: histories
 * 
 * Purpose:
 * - Track user activities (when users open files)
 * - Provide activity feed/timeline for users
 * - Enable audit logging for compliance
 * - Analytics on file access patterns
 * - Recently accessed files tracking
 * 
 * Current Tracked Actions:
 * - 'open': User opened/viewed a file
 * 
 * Future Actions (can be added):
 * - 'download': User downloaded a file
 * - 'share': User shared a file with another user
 * - 'rename': User renamed a file
 * - 'delete': User deleted a file
 * - 'create': User created a file/folder
 * 
 * Relationship:
 * - user: References the User who performed the action
 * - file: References the File that was accessed/modified
 * - Created automatically when certain actions occur
 */

import mongoose from 'mongoose';

const historySchema = new mongoose.Schema({
  /**
   * @property {ObjectId} user
   * Reference to the User who performed this action
   * Identifies which user did what in the system
   * Used to filter history by user
   * Required: Yes - every action must have an actor
   */
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  /**
   * @property {ObjectId} file
   * Reference to the File/Folder on which action was performed
   * Which file was accessed/opened/modified
   * Used with popup to show file details in activity log
   * Required: Yes - every action targets a file
   */
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true
  },

  /**
   * @property {String} action
   * Type of action performed on the file
   * Current enum values: ['open']
   * Can be extended to include other actions (download, share, delete, etc.)
   * 
   * Enum validation ensures only valid actions are recorded
   * New actions require updating this schema
   * Required: Yes - every record must describe an action
   */
  action: {
    type: String,
    enum: ['open'],
    required: true
  },

}, {
  timestamps: true // Auto-adds createdAt and updatedAt
});

/**
 * Indexes for Performance
 * 
 * Current indexes (implicit):
 * - _id (MongoDB default)
 * 
 * Would want for optimization:
 * - { user: 1, createdAt: -1 } for fetching user's recent activity (primary use)
 * - { file: 1, createdAt: -1 } for file access history/analytics
 * - { createdAt: -1 } for recent activity across all users
 * - { user: 1, action: 1 } for filtering specific actions by user
 */

const History = mongoose.model('History', historySchema);

export default History;

