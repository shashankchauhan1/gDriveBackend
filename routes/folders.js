/**
 * Folder Management Routes
 * 
 * Handles folder creation and hierarchy traversal
 * 
 * Key Features:
 * - Create folders with hierarchical parent-child relationships
 * - Breadcrumb path generation for UI navigation
 * - Duplicate name detection (folders with same name in different locations allowed)
 * - Access control through permission inheritance from parent folders
 * 
 * Model: Uses File model with type: 'folder' to distinguish from files
 * 
 * Concepts:
 * - Hierarchical Structure: Each folder has a parentId (or null for root)
 * - Breadcrumb Generation: Build path from current folder up to root
 * - Access Verification: Check ancestor chain to verify folder access
 */

import express from 'express';
import auth from '../middleware/auth.js';
import File from '../models/File.js';

const router = express.Router();

/**
 * POST /api/folders
 * 
 * Create a new folder in the file hierarchy
 * Can be created in root (no parentId) or within a parent folder
 * 
 * Authentication: Required
 * 
 * Request Body:
 * - name (required): Folder name (max 255 characters per schema)
 * - parentId (optional): Parent folder ID (null or omitted for root)
 * 
 * Validation:
 * - Name cannot be empty
 * - Duplicate names allowed in different parent folders
 * - Duplicate names NOT allowed in same parent (prevents confusion)
 * 
 * Access Control:
 * - Folders are always created by current user (via req.user.id)
 * - User must authenticate but no parent permission check (user owns new folder)
 * 
 * Response (201 Created):
 * - Complete folder document:
 *   - _id: Generated MongoDB ID
 *   - filename: Folder name
 *   - owner: User who created it
 *   - type: 'folder' (distinguishes from files)
 *   - parentId: Parent folder ID (or null for root)
 *   - createdAt: Timestamp
 *   - updatedAt: Timestamp
 *   - permissions: Empty array initially (no shared access yet)
 *   - isTrashed: false (not in trash)
 * 
 * Error Responses:
 * - 400: Folder with same name already exists in this location
 * - 500: Server error
 * 
 * @example
 * POST /api/folders
 * Headers: x-auth-token: <token>
 * Body: {
 *   "name": "Project2024",
 *   "parentId": "60d5ec49c1234567890abcde"
 * }
 * 
 * Response (201):
 * {
 *   "_id": "60d6ec49c1234567890abcdf",
 *   "filename": "Project2024",
 *   "owner": "60d5ec49c1234567890ab000",
 *   "type": "folder",
 *   "parentId": "60d5ec49c1234567890abcde",
 *   "permissions": [],
 *   "isTrashed": false,
 *   "createdAt": "2024-01-20T10:00:00.000Z"
 * }
 */
router.post('/', auth, async (req, res) => {
  try {
    const { name, parentId = null } = req.body;

    /**
     * Validate Folder Name
     * Check that name is provided and not empty
     */
    if (!name || !name.trim()) {
      return res.status(400).json({ msg: 'Folder name is required' });
    }

    /**
     * Check for Duplicate Names in Same Location
     * Same name allowed in different parent folders, but not in same parent
     * Example: "Photos" in root AND "Photos" in "Projects" are OK
     *          But two "Photos" folders in same parent are NOT OK
     */
    const existing = await File.findOne({
      owner: req.user.id,
      parentId,
      filename: name,
      type: 'folder'
    });
    if (existing) {
      return res.status(400).json({ msg: 'A folder with this name already exists here.' });
    }

    /**
     * Create New Folder Document
     * Folder is always created by authenticated user
     * Type: 'folder' distinguishes from type: 'file'
     */
    const newFolder = new File({
      filename: name.trim(),
      owner: req.user.id,
      parentId,
      type: 'folder',
      // Other fields initialized with defaults:
      // - permissions: [] (empty, no sharing yet)
      // - isTrashed: false
      // - createdAt/updatedAt: auto-generated
    });

    /**
     * Save & Return Folder
     * Return complete document with all fields
     */
    await newFolder.save();
    res.status(201).json(newFolder);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * GET /api/folders/:id/path
 * 
 * Get the breadcrumb path from a folder up to root
 * Used to display folder hierarchy in UI for navigation
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): Folder ID to get path for
 * 
 * Access Control:
 * - User must have access to folder (own it or have permission on ancestor)
 * - Traverses entire ancestor chain to verify access
 * - Returns 404 if user cannot verify access at any point
 * 
 * Response (200 OK):
 * - Array of folder objects from root to target, in order:
 *   - _id: Folder ID
 *   - filename: Display name
 *   - Empty array for root (no path)
 * 
 * Example Response:
 * [
 *   { "_id": "root1", "filename": "Project2024" },
 *   { "_id": "sub1", "filename": "2024-Q1" },
 *   { "_id": "sub2", "filename": "Reports" }
 * ]
 * 
 * Error Responses:
 * - 404: Folder not found or user not authorized to access
 * - 500: Server error
 * 
 * @example
 * GET /api/folders/60d6ec49c1234567890abcdf/path
 * Headers: x-auth-token: <token>
 * 
 * Response (200): Array of path segments from root to folder
 */
router.get('/:id/path', auth, async (req, res) => {
  try {
    const path = [];
    let currentFolderId = req.params.id;

    /**
     * Traverse Up the Folder Hierarchy
     * Start from requested folder and move up to root
     */
    while (currentFolderId) {
      /**
       * Load Current Folder Document
       */
      const folder = await File.findById(currentFolderId);
      if (!folder) return res.status(404).json({ msg: 'Path not found' });

      /**
       * SECURITY: Verify User Has Access
       * Check if user owns folder OR has permission on this folder or any ancestor
       * This prevents users from discovering paths they don't have access to
       */
      let hasAccess = false;
      let node = folder;
      while (node) {
        if (
          node.owner.toString() === req.user.id ||
          node.permissions.some(p => p.user.toString() === req.user.id)
        ) {
          hasAccess = true;
          break;
        }
        if (!node.parentId) break;
        node = await File.findById(node.parentId);
      }
      if (!hasAccess) return res.status(404).json({ msg: 'Path not found' });

      /**
       * Add Folder to Path (at beginning for chronological order)
       * Prepend so path builds from root → target
       */
      path.unshift({
        _id: folder._id,
        filename: folder.filename
      });

      /**
       * Move Up to Parent Folder
       * Loop continues if parentId exists, stops at root (parentId = null)
       */
      currentFolderId = folder.parentId;
    }

    /**
     * Return Complete Breadcrumb Path
     */
    res.json(path);
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