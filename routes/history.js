/**
 * Activity History Routes
 * 
 * Tracks user interactions with files for audit logging
 * Records when users open files, helping with activity tracking and analytics
 * 
 * Model: History
 * - Stores user ID, file ID, action type, and timestamp
 * - Primarily used for activity audit trail
 * 
 * Note: Currently only tracks 'open' actions
 * Future: Could be extended to track other actions (delete, share, rename, etc.)
 */

import express from 'express';
import auth from '../middleware/auth.js';
import History from '../models/History.js';

const router = express.Router();

/**
 * GET /api/history
 * 
 * Retrieve recent activity/events for the authenticated user
 * Shows file open events with file details
 * Limited to 50 most recent events
 * Useful for activity log, recently accessed files, audit trail
 * 
 * Authentication: Required
 * Query Parameters: None (currently)
 * 
 * Response (200 OK):
 * - Array of history events (max 50), sorted newest first:
 *   - _id: Event ID
 *   - user: User ID who performed action (from token)
 *   - file: Populated file document with:
 *     - filename: File name
 *     - cloudinaryUrl: File URL (for displaying thumbnail/preview)
 *     - type: 'file' or 'folder'
 *   - action: Event type (currently 'open')
 *   - createdAt: Timestamp when event occurred
 * 
 * Sorting:
 * - By createdAt descending (newest events first)
 * - Limited to 50 most recent
 * 
 * Error Responses:
 * - 500: Server error
 * 
 * @example
 * GET /api/history
 * Headers: x-auth-token: <token>
 * 
 * Response (200): Array of recent activity events
 * [
 *   {
 *     "_id": "60d6ec49c1234567890ab000",
 *     "user": "60d5ec49c1234567890ab000",
 *     "file": {
 *       "_id": "60d5ec49c1234567890abcde",
 *       "filename": "report.pdf",
 *       "cloudinaryUrl": "https://...",
 *       "type": "file"
 *     },
 *     "action": "open",
 *     "createdAt": "2024-01-20T15:30:00.000Z"
 *   }
 * ]
 * 
 * Use Cases:
 * - Display recently accessed files in dashboard
 * - Show activity timeline on user profile
 * - Audit trail for compliance/security
 * - Analytics on file access patterns
 */
router.get('/', auth, async (req, res) => {
  try {
    /**
     * Fetch User's Recent Activity Events
     * Query for all events belonging to current user
     * Populate file details for showing in activity list
     * Sort newest first, limit results to avoid huge responses
     */
    const events = await History.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('file', 'filename cloudinaryUrl type');
    
    /**
     * Return Activity Events
     * Frontend can display in timeline or activity feed format
     */
    res.json(events);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * EXPORT MODULE
 * 
 * Export router for use in main application
 */
export default router;

