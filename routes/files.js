/**
 * File Management Routes
 * 
 * Comprehensive file and folder management system with:
 * - File upload to Cloudinary cloud storage
 * - Hierarchical folder structure (one level parent via parentId)
 * - Permission-based access control (viewer/editor roles)
 * - Soft delete with trash recovery
 * - File versioning with version history
 * - Permission and sharing management
 * - File search and metadata tracking
 * 
 * Key Concepts:
 * - Files are stored in Cloudinary (cloud-based storage)
 * - Metadata stored in MongoDB (File, FileVersion, History models)
 * - Permissions cascade: files inherit access from parent folders
 * - Soft delete: items moved to trash (isTrashed flag) before permanent deletion
 * - Versions: track all file uploads/updates through FileVersion model
 * 
 * Access Control:
 * - Owner: Full control, can share, delete, rename
 * - Editor: Can upload new versions, rename, create subfolders
 * - Viewer: Read-only access
 * - Cascading: If parent folder shared as editor, all children are editor
 * 
 * API Endpoints (see methods below):
 * Files: upload, list, rename, delete, restore, search, open (history)
 * Permissions: share, revoke, view, update user roles
 * Versions: list, delete specific, clear all but latest
 * Trash: list, permanently delete
 */

import express from 'express';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import auth from '../middleware/auth.js';
import File from '../models/File.js';
import User from '../models/User.js';
import History from '../models/History.js';
import FileVersion from '../models/FileVersion.js';
import dotenv from 'dotenv'; 

dotenv.config();

const router = express.Router();

/**
 * CLOUDINARY CONFIGURATION
 * 
 * Configures cloud storage connection for file uploads
 * Required environment variables:
 * - CLOUDINARY_CLOUD_NAME: Cloudinary account identifier
 * - CLOUDINARY_API_KEY: API authentication key
 * - CLOUDINARY_API_SECRET: API secret for secure operations
 */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/**
 * MULTER CONFIGURATION
 * 
 * Handles file upload validation before streaming to Cloudinary
 * Settings:
 * - Storage: Memory (not disk) - file streamed directly to cloud
 * - Size limit: 10MB per file
 * - Allowed types: Images (all types) and PDFs (by MIME type and extension)
 * - Validation: File type checked via both MIME type and extension
 * 
 * Flow: Client sends file → Multer validates → Streams to Cloudinary → DB record created
 */
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const mime = file.mimetype || '';
    const name = (file.originalname || '').toLowerCase();
    const isImage = mime.startsWith('image/');
    const isPdfMime = mime === 'application/pdf' || mime === 'application/x-pdf';
    const isPdfExt = name.endsWith('.pdf');

    if (isImage || isPdfMime || isPdfExt) {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'));
    }
  }
});

/**
 * UTILITY FUNCTIONS - Permission & Access Control
 */

/**
 * Load file document from MongoDB with caching
 * @param {string} id - MongoDB file document ID
 * @param {Map} cache - Cache map for avoiding repeated DB queries
 * @returns {Promise<Object|null>} File document or null if not found
 */
const loadFromCache = async (id, cache) => {
  if (!id) return null;
  const key = id.toString();
  if (cache.has(key)) return cache.get(key);
  const doc = await File.findById(id);
  if (doc) cache.set(key, doc);
  return doc;
};

/**
 * Resolve user's effective role on a file/folder
 * 
 * Permission Resolution Algorithm:
 * 1. Check if user is owner of current item → return 'owner'
 * 2. Check if user has direct permission on current item → return that role
 * 3. If not found and item has parent, traverse up to parent
 * 4. Repeat until root folder reached
 * 5. Return null if no permission found anywhere in hierarchy
 * 
 * This allows files to inherit permissions from parent folders
 * Example: If folder shared as 'editor', all files inside are 'editor'
 * 
 * @param {Object} item - File document to check permissions for
 * @param {string} userId - User ID to check permissions for
 * @param {Map} cache - Cache map to avoid repeated DB queries
 * @returns {Promise<string|null>} Role ('owner', 'viewer', 'editor') or null if no access
 */
const resolveUserRole = async (item, userId, cache = new Map()) => {
  if (!item) return null;
  let node = item;
  while (node) {
    const ownerId = node.owner?._id ? node.owner._id.toString() : node.owner?.toString?.();
    if (ownerId === userId) return 'owner';
    const permission = node.permissions?.find?.((p) => {
      const permUserId = p.user?._id ? p.user._id.toString() : p.user?.toString?.();
      return permUserId === userId;
    });
    if (permission) return permission.role;
    if (!node.parentId) break;
    node = await loadFromCache(node.parentId, cache);
  }
  return null;
};

/**
 * Attach effective role to multiple file documents
 * 
 * This function enriches file documents with their effective role for the user
 * Uses caching to avoid redundant database queries when checking parent folders
 * 
 * @param {Array<Object>} items - Array of file documents
 * @param {string} userId - User ID to resolve roles for
 * @returns {Promise<Array<Object>>} Array of documents with effectiveRole attached
 */
const attachEffectiveRole = async (items, userId) => {
  const cache = new Map();
  return Promise.all(items.map(async (doc) => {
    const role = await resolveUserRole(doc, userId, cache);
    const plain = doc.toObject();
    const ownerId = doc.owner?._id ? doc.owner._id.toString() : doc.owner?.toString?.();
    plain.effectiveRole = role || (ownerId === userId ? 'owner' : null);
    return plain;
  }));
};

/**
 * UTILITY FUNCTIONS - File Versioning
 */

/**
 * Ensure file version history seed exists
 * 
 * When a file is first created or needs version tracking, this creates an initial
 * FileVersion entry if one doesn't exist. This ensures version history is available.
 * 
 * @param {Object} fileDoc - File document from MongoDB
 * @param {string|Object} fallbackUploader - User ID of uploader (for initial version)
 * @returns {Promise<void>}
 */
const ensureFileVersionSeed = async (fileDoc, fallbackUploader) => {
  if (!fileDoc || fileDoc.type !== 'file') return;
  const count = await FileVersion.countDocuments({ file: fileDoc._id });
  if (count > 0) {
    if (fileDoc.versionCount !== count) {
      fileDoc.versionCount = count;
      await fileDoc.save();
    }
    return;
  }
  if (!fileDoc.cloudinaryUrl || !fileDoc.cloudinaryPublicId) return;
  const ownerId = fallbackUploader?._id ? fallbackUploader._id : fallbackUploader;
  const fallbackOwner = fileDoc.owner?._id ? fileDoc.owner._id : fileDoc.owner;
  const version = await FileVersion.create({
    file: fileDoc._id,
    versionNumber: 1,
    cloudinaryUrl: fileDoc.cloudinaryUrl,
    cloudinaryPublicId: fileDoc.cloudinaryPublicId,
    fileType: fileDoc.fileType,
    size: fileDoc.size,
    uploadedBy: ownerId || fallbackOwner,
  });
  fileDoc.currentVersion = version._id;
  fileDoc.versionCount = 1;
  await fileDoc.save();
};

/**
 * FILE UPLOAD ENDPOINTS
 */

/**
 * POST /api/files/upload
 * 
 * Upload a new file to Cloudinary and create metadata in database
 * 
 * Authentication: Required (x-auth-token header)
 * Content-Type: multipart/form-data
 * 
 * Request Body:
 * - file (required): File to upload (images or PDFs, max 10MB)
 * - parentId (optional): Folder ID to place file in (defaults to root)
 * 
 * Validation:
 * - File size: Max 10MB
 * - File type: Images (all types) or PDFs
 * - Parent access: User must own or have access to specified parent folder
 * 
 * Response (201 Created):
 * - File metadata including:
 *   - _id: Database document ID
 *   - filename: Original file name
 *   - owner: User ID of uploader
 *   - cloudinaryUrl: Public URL for viewing/downloading
 *   - cloudinaryPublicId: Cloudinary asset identifier
 *   - size: File size in bytes
 *   - type: 'file' (as opposed to 'folder')
 *   - effectiveRole: 'owner' (for uploader)
 * 
 * Error Responses:
 * - 400: No file uploaded, invalid type, or file too large
 * - 404: Parent folder not found
 * - 401: User not authorized to upload to specified parent
 * - 500: Server error or Cloudinary upload failure
 * 
 * @example
 * POST /api/files/upload
 * Headers: x-auth-token: <token>, Content-Type: multipart/form-data
 * Body: 
 *   file: [binary image data]
 *   parentId: "60d5ec49c1234567890abcde"
 * 
 * Response (201):
 * {
 *   "_id": "60d5ec49c1234567890abcde",
 *   "filename": "document.pdf",
 *   "owner": "60d5ec49c1234567890ab000",
 *   "cloudinaryUrl": "https://res.cloudinary.com/...",
 *   "size": 204800,
 *   "type": "file",
 *   "effectiveRole": "owner"
 * }
 */
router.post('/upload', auth, (req, res, next) => {
  upload.single('file')(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ msg: 'File too large. Max size is 10MB.' });
      }
      return res.status(400).json({ msg: `Upload error: ${err.message}` });
    } else if (err) {
      return res.status(400).json({ msg: err.message });
    }
    next();
  });
}, async (req, res) => {
  try {
    /**
     * Step 1: Validate File Provided
     * Check that client sent an actual file
     */
    if (!req.file) {
      return res.status(400).json({ msg: 'No file uploaded or invalid file type.' });
    }

    /**
     * Step 2: Validate Parent Folder Access
     * If user specifies a parent folder, verify they have access to it
     */
    const { parentId } = req.body;
    let parent = null;
    if (parentId) {
      parent = await File.findById(parentId);
      if (!parent) return res.status(404).json({ msg: 'Parent folder not found' });
      // Access check: user must own parent or have permission on any ancestor
      let node = parent;
      let hasAccess = false;
      while (node) {
        if (node.owner.toString() === req.user.id || node.permissions.some(p => p.user.toString() === req.user.id)) {
          hasAccess = true;
          break;
        }
        if (!node.parentId) break;
        node = await File.findById(node.parentId);
      }
      if (!hasAccess) return res.status(401).json({ msg: 'Not authorized to upload to this folder' });
    }

    /**
     * Step 3: Upload to Cloudinary
     * Stream file buffer to Cloudinary cloud storage
     * folder: 'mern-drive' organizes files within Cloudinary account
     */
    const uploadStream = cloudinary.uploader.upload_stream(
      { resource_type: 'auto', folder: 'mern-drive' },
      async (error, result) => {
        if (error) {
          console.error('Cloudinary Error:', error);
          return res.status(500).json({ msg: 'Error uploading to cloud storage: ' + error.message });
        }

        /**
         * Step 4: Save File Metadata to Database
         * Create File document with Cloudinary reference
         */
        const newFile = new File({
          filename: req.file.originalname,
          owner: req.user.id,
          cloudinaryUrl: result.secure_url,
          cloudinaryPublicId: result.public_id,
          fileType: result.resource_type,
          size: result.bytes,
          type: 'file',
          parentId: parent ? parent._id : null,
        });

        await newFile.save();

        /**
         * Step 5: Initialize Version History
         * Create first version entry for tracking uploads
         */
        await ensureFileVersionSeed(newFile, req.user.id);
        const payload = newFile.toObject();
        payload.effectiveRole = 'owner';
        res.status(201).json(payload);
      }
    );

    /**
     * Step 6: Stream File to Upload
     * Send file buffer to Cloudinary stream
     */
    uploadStream.end(req.file.buffer);

  } catch (err) {
    console.error('Server Error:', err);
    res.status(500).json({ msg: 'Server Error: ' + err.message });
  }
});

/**
 * FILE RETRIEVAL AND LISTING ENDPOINTS
 */

/**
 * GET /api/files
 * 
 * List files and folders accessible to the user
 * Supports hierarchical browsing via parentId parameter
 * 
 * Authentication: Required (x-auth-token header)
 * Query Parameters:
 * - parentId (optional): Folder ID to list contents of
 *   - If omitted: Lists items in root folder
 *   - If provided: Lists items within that folder
 * 
 * Access Control:
 * - Root listing: Shows user's own items + items explicitly shared with them
 * - Subfolder listing: Shows all items in folder if user has access to folder
 *   - User must own folder OR have permission on folder/ancestor
 * 
 * Response (200 OK):
 * - Array of file/folder documents with properties:
 *   - _id: Document ID
 *   - filename: File or folder name
 *   - type: 'file' or 'folder'
 *   - owner: Folder/file owner
 *   - parentId: Parent folder ID (null for root)
 *   - size: File size in bytes (only for files)
 *   - effectiveRole: User's access level (owner/editor/viewer/null if no access)
 *   - createdAt: Creation timestamp
 * 
 * Error Responses:
 * - 401: User not authorized to access folder
 * - 404: Parent folder not found
 * - 500: Server error
 * 
 * @example
 * GET /api/files
 * Headers: x-auth-token: <token>
 * Response (200): Array of 5-10 items
 * 
 * @example
 * GET /api/files?parentId=60d5ec49c1234567890abcde
 * Headers: x-auth-token: <token>
 * Response (200): Array of items in specified folder
 */
router.get('/', auth, async (req, res) => {
  try {
    const parentId = req.query.parentId || null;

    /**
     * ROOT FOLDER LISTING
     * When no parentId specified, show user's root items
     */
    if (!parentId) {
      const items = await File.find({
        $and: [
          { parentId: null },
          { isTrashed: { $ne: true } },
          {
            $or: [
              { owner: req.user.id },
              { 'permissions.user': req.user.id }
            ]
          }
        ]
      });
      const enriched = await attachEffectiveRole(items, req.user.id);
      return res.json(enriched);
    }

    /**
     * SUBFOLDER LISTING
     * When parentId specified, verify access and list folder contents
     */
    let current = await File.findById(parentId);
    if (!current) return res.status(404).json({ msg: 'Parent folder not found' });

    /**
     * ACCESS VERIFICATION
     * Traverse up folder tree to check if user owns or has permission on any ancestor
     */
    let hasAccess = false;
    while (current) {
      if (
        current.owner.toString() === req.user.id ||
        current.permissions.some(p => p.user.toString() === req.user.id)
      ) {
        hasAccess = true;
        break;
      }
      if (!current.parentId) break;
      current = await File.findById(current.parentId);
    }
    if (!hasAccess) return res.status(401).json({ msg: 'Not authorized to view this folder' });

    /**
     * LIST FOLDER CONTENTS
     * Show all items in folder (not in trash)
     */
    const items = await File.find({ parentId: parentId, isTrashed: { $ne: true } });
    const enriched = await attachEffectiveRole(items, req.user.id);
    return res.json(enriched);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * POST /api/files/:id/open
 * 
 * Record a file "open" event for activity history
 * Used to track when users view files (for history/audit logging)
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * 
 * Access Control:
 * - User must own file OR have viewer/editor permission (via roles)
 * 
 * Response (201 Created):
 * - { ok: true }
 * 
 * Error Responses:
 * - 401: User not authorized to view this file
 * - 404: File not found
 * - 500: Server error
 * 
 * @example
 * POST /api/files/60d5ec49c1234567890abcde/open
 * Headers: x-auth-token: <token>
 * Response (201): { ok: true }
 */
router.post('/:id/open', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });

    /**
     * Permission Check
     * Does user own file or have permission on it?
     */
    const role = await resolveUserRole(file, req.user.id);
    if (!role && file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Not authorized' });
    }

    /**
     * Create History Entry
     * Track this open event for audit logging
     */
    const entry = new History({ user: req.user.id, file: file._id, action: 'open' });
    await entry.save();
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * TRASH AND DELETION ENDPOINTS
 * 
 * Files are soft-deleted (moved to trash) before permanent deletion
 * This allows users to recover accidentally deleted files
 */

/**
 * DELETE /api/files/:id
 * 
 * Soft delete a file or folder (move to trash)
 * File is not permanently deleted, can be restored within trash
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * 
 * Access Control:
 * - User must be owner or have editor role (viewers cannot delete)
 * 
 * Response (200 OK):
 * - { msg: 'Moved to trash' }
 * 
 * Error Responses:
 * - 401: User not authorized to delete
 * - 404: File not found
 * - 500: Server error
 */
router.delete('/:id', auth, async (req, res) => {
  try {
    /**
     * Load File & Check Permissions
     * Only owner or editor can delete
     */
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    const role = await resolveUserRole(file, req.user.id);
    if (!role || role === 'viewer') return res.status(401).json({ msg: 'User not authorized' });

    /**
     * Soft Delete
     * Set isTrashed flag with timestamp
     */
    file.isTrashed = true;
    file.trashedAt = new Date();
    await file.save();
    res.json({ msg: 'Moved to trash' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * GET /api/files/trash
 * 
 * List all trashed items belonging to the current user
 * Sorted by most recently trashed first
 * 
 * Authentication: Required
 * 
 * Response (200 OK):
 * - Array of trashed file/folder documents with:
 *   - All file properties
 *   - trashedAt: Timestamp when moved to trash
 *   - isTrashed: true
 * 
 * Error Responses:
 * - 500: Server error
 * 
 * @example
 * GET /api/files/trash
 * Headers: x-auth-token: <token>
 * Response (200): Array of 0+ trashed items
 */
router.get('/trash', auth, async (req, res) => {
  try {
    const items = await File.find({ owner: req.user.id, isTrashed: true }).sort({ trashedAt: -1 });
    res.json(items);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * PUT /api/files/:id/restore
 * 
 * Restore a trashed file or folder from trash
 * Restores to original parent folder (if it still exists)
 * If parent was also deleted, moves to root folder instead
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * 
 * Access Control:
 * - Only owner can restore their own files
 * 
 * Response (200 OK):
 * - Restored file document with isTrashed: false
 * 
 * Error Responses:
 * - 401: User not owner
 * - 404: File not found
 * - 500: Server error
 */
router.put('/:id/restore', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.owner.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });

    /**
     * Verify Parent Folder Still Exists
     * If parent was also deleted, restore to root instead
     */
    let parentValid = true;
    if (file.parentId) {
      const parent = await File.findById(file.parentId);
      if (!parent || parent.isTrashed) {
        parentValid = false;
      }
    }

    /**
     * Restore from Trash
     * Clear isTrashed flag and clear trashedAt timestamp
     */
    file.isTrashed = false;
    file.trashedAt = undefined;
    if (!parentValid) {
      file.parentId = null; // Move to root if parent deleted
    }
    await file.save();
    res.json(file);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * DELETE /api/files/trash/:id
 * 
 * Permanently delete a trashed file or folder
 * CANNOT BE UNDONE - file is completely removed
 * For files: Deletes from Cloudinary storage AND database
 * For folders: Deletes folder and all contained files/versions
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID in trash
 * 
 * Access Control:
 * - Only owner can permanently delete
 * - Item must be in trash (isTrashed: true)
 * 
 * Response (200 OK):
 * - { msg: 'Deleted permanently' }
 * 
 * Error Responses:
 * - 400: Item is not in trash
 * - 401: User not owner
 * - 404: File not found
 * - 500: Server error or Cloudinary deletion failure
 */
router.delete('/trash/:id', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.owner.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });
    if (!file.isTrashed) return res.status(400).json({ msg: 'File is not in trash' });

    /**
     * Delete File Versions
     * If item is a file (not folder), delete all versions from Cloudinary
     */
    if (file.type === 'file') {
      const versions = await FileVersion.find({ file: file._id });
      await Promise.all(versions.map(async (v) => {
        if (v.cloudinaryPublicId) {
          try {
            await cloudinary.uploader.destroy(v.cloudinaryPublicId);
          } catch {}
        }
      }));
      await FileVersion.deleteMany({ file: file._id });
    }

    /**
     * Delete File Record from Database
     * Permanently removes all trace of file/folder
     */
    await File.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Deleted permanently' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


/**
 * FILE MODIFICATION & SEARCH ENDPOINTS
 */

/**
 * PUT /api/files/:id/rename
 * 
 * Rename a file or folder
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * 
 * Request Body:
 * - name (required): New filename (cannot be empty)
 * 
 * Access Control:
 * - User must be owner or have editor role (viewers cannot rename)
 * 
 * Response (200 OK):
 * - Updated file document with new filename
 * 
 * Error Responses:
 * - 400: New name is required or empty
 * - 401: User not authorized to rename
 * - 404: File not found
 * - 500: Server error
 * 
 * @example
 * PUT /api/files/60d5ec49c1234567890abcde/rename
 * Headers: x-auth-token: <token>
 * Body: { "name": "new_filename.pdf" }
 * Response (200): Updated file document
 */
router.put('/:id/rename', auth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ msg: 'New name is required' });

    /**
     * Load File & Check Permissions
     * Only owner or editor can rename
     */
    const item = await File.findById(req.params.id);
    if (!item) return res.status(404).json({ msg: 'Item not found' });

    const role = await resolveUserRole(item, req.user.id);
    if (!role || (role !== 'owner' && role !== 'editor')) {
      return res.status(401).json({ msg: 'Not authorized to rename' });
    }

    /**
     * Update Filename & Save
     */
    item.filename = name.trim();
    await item.save();
    return res.json(item);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * GET /api/files/search
 * 
 * Search for files and folders by name
 * Only returns items accessible to the user
 * Results limited to 100 items (for performance)
 * 
 * Authentication: Required
 * Query Parameters:
 * - q (required): Search query string (case-insensitive substring match)
 * 
 * Access Control:
 * - Only returns files the user owns or has access to (via permissions)
 * - Does not search across all users' files
 * - Excludes trashed items
 * 
 * Response (200 OK):
 * - Array of matching file/folder documents (max 100)
 * - Each item includes effectiveRole for permission display
 * - Empty array if no matches or empty query
 * 
 * Error Responses:
 * - 500: Server error
 * 
 * @example
 * GET /api/files/search?q=budget
 * Headers: x-auth-token: <token>
 * Response (200): Array of matched files (max 100 items)
 */
router.get('/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || !q.trim()) return res.json([]);

    /**
     * Build Search Pattern
     * Escape regex special characters for literal matching
     * Case-insensitive search via 'i' flag
     */
    const regex = new RegExp(q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');

    /**
     * Find Accessible Items
     * Search files the user owns or has been shared with
     * Only search non-trashed items for cleaner results
     */
    const ownedOrShared = await File.find({
      $or: [
        { owner: req.user.id },
        { 'permissions.user': req.user.id }
      ],
      isTrashed: { $ne: true },
      filename: regex,
    }).limit(100);

    /**
     * Attach Permission Roles
     * Add effectiveRole to search results for display
     */
    const enriched = await attachEffectiveRole(ownedOrShared, req.user.id);
    return res.json(enriched);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * POST /api/files/:id/revoke
 * 
 * Revoke a user's access to a file by email address
 * DEPRECATED: Use DELETE /api/files/:id/permissions/:userId instead
 * 
 * @deprecated Use DELETE /api/files/:id/permissions/:userId for better error handling
 */
router.post('/:id/revoke', auth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ msg: 'Email is required' });

    const item = await File.findById(req.params.id);
    if (!item) return res.status(404).json({ msg: 'Item not found' });
    if (item.owner.toString() !== req.user.id) return res.status(401).json({ msg: 'Only owner can revoke' });

    const userToRevoke = await User.findOne({ email });
    if (!userToRevoke) return res.status(404).json({ msg: 'User not found' });

    item.permissions = item.permissions.filter(p => p.user.toString() !== userToRevoke.id);
    await item.save();
    return res.json(item.permissions);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * PERMISSION & SHARING ENDPOINTS
 * 
 * Manage who can access files and what level of access they have
 * Two roles: 'viewer' (read-only) and 'editor' (can upload new versions, rename)
 */

/**
 * POST /api/files/:id/share
 * 
 * Share a file or folder with another user
 * Creates or updates a permission entry for the specified user
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID to share
 * 
 * Request Body:
 * - email (required): Email address of user to share with
 * - role (required): 'viewer' or 'editor'
 * 
 * Access Control:
 * - Only file owner can share (editor/viewer cannot grant access)
 * 
 * Response (200 OK):
 * - permissions: Array of permission objects with populated user details
 * - mode: 'created' (new permission) or 'updated' (replaced existing)
 * 
 * Error Responses:
 * - 400: Invalid role or attempting to share with self
 * - 401: User is not file owner
 * - 404: File not found or user with email not found
 * - 500: Server error
 * 
 * @example
 * POST /api/files/60d5ec49c1234567890abcde/share
 * Headers: x-auth-token: <token>
 * Body: {
 *   "email": "colleague@example.com",
 *   "role": "editor"
 * }
 * Response (200): {
 *   "permissions": [
 *     { "user": { "_id": "...", "username": "colleague", "email": "colleague@example.com" }, "role": "editor" }
 *   ],
 *   "mode": "created"
 * }
 */
router.post('/:id/share', auth, async (req, res) => {
  try {
    const { email, role } = req.body;

    /**
     * Validate Role Parameter
     * Only 'viewer' and 'editor' are valid roles
     */
    if (!['viewer', 'editor'].includes(role)) {
      return res.status(400).json({ msg: 'Invalid role' });
    }

    /**
     * Load File & Verify Ownership
     * Only owner can add permissions
     */
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ msg: 'File not found' });
    }

    if (file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'User not authorized to share this file' });
    }

    /**
     * Find User to Share With
     * Must be registered user with matching email
     */
    const userToShareWith = await User.findOne({ email });
    if (!userToShareWith) {
      return res.status(404).json({ msg: 'User to share with not found' });
    }

    /**
     * Prevent Self-Sharing
     * User cannot grant permission to themselves (already owner)
     */
    if (userToShareWith.id === req.user.id) {
      return res.status(400).json({ msg: 'You cannot share a file with yourself' });
    }

    /**
     * Update or Create Permission
     * If user already has permission, update role
     * Otherwise, add new permission entry
     */
    const existing = file.permissions.find(p => p.user.toString() === userToShareWith.id);
    let mode = 'created';
    if (existing) {
      existing.role = role;
      mode = 'updated';
    } else {
      file.permissions.push({ user: userToShareWith.id, role });
    }
    await file.save();

    /**
     * Populate User Details
     * Return permissions with full user information
     */
    await file.populate('permissions.user', 'username email');

    res.json({ permissions: file.permissions, mode });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

/**
 * GET /api/files/:id/permissions
 * 
 * View all permissions for a file or folder
 * Shows owner and all users with access
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * 
 * Access Control:
 * - Only owner can view permissions (security: don't reveal sharing to non-owners)
 * 
 * Response (200 OK):
 * - owner: Owner user object with username and email
 * - permissions: Array of permission objects:
 *   - user: User object (username, email)
 *   - role: 'viewer' or 'editor'
 * 
 * Error Responses:
 * - 401: User is not owner
 * - 404: File not found
 * - 500: Server error
 * 
 * @example
 * GET /api/files/60d5ec49c1234567890abcde/permissions
 * Headers: x-auth-token: <token>
 * Response (200): {
 *   "owner": { "_id": "...", "username": "john", "email": "john@example.com" },
 *   "permissions": [
 *     { "user": { "username": "jane", "email": "jane@example.com" }, "role": "viewer" }
 *   ]
 * }
 */
router.get('/:id/permissions', auth, async (req, res) => {
  try {
    const item = await File.findById(req.params.id)
      .populate('owner', 'username email')
      .populate('permissions.user', 'username email');
    if (!item) return res.status(404).json({ msg: 'Item not found' });

    /**
     * Security Check: Only Owner Can View
     */
    const ownerId = item.owner?._id ? item.owner._id.toString() : item.owner?.toString?.();
    if (ownerId !== req.user.id) {
      return res.status(401).json({ msg: 'Only owner can view permissions' });
    }

    return res.json({
      owner: item.owner,
      permissions: item.permissions,
    });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * PATCH /api/files/:id/permissions
 * 
 * Update a user's role on a file or folder
 * Changes existing permission's role setting
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * 
 * Request Body:
 * - userId (required): User ID to update permission for
 * - role (required): New role ('viewer' or 'editor')
 * 
 * Access Control:
 * - Only owner can change permissions
 * 
 * Response (200 OK):
 * - permissions: Updated permissions array with user details
 * 
 * Error Responses:
 * - 400: userId or valid role required
 * - 401: User is not owner
 * - 404: File or permission not found
 * - 500: Server error
 * 
 * @example
 * PATCH /api/files/60d5ec49c1234567890abcde/permissions
 * Headers: x-auth-token: <token>
 * Body: { "userId": "60d5ec49c1234567890ab111", "role": "editor" }
 * Response (200): Array of updated permissions
 */
router.patch('/:id/permissions', auth, async (req, res) => {
  try {
    const { userId, role } = req.body;
    if (!userId || !['viewer', 'editor'].includes(role)) {
      return res.status(400).json({ msg: 'User and valid role are required' });
    }

    /**
     * Load File & Verify Ownership
     */
    const item = await File.findById(req.params.id).populate('permissions.user', 'username email');
    if (!item) return res.status(404).json({ msg: 'Item not found' });
    const ownerId = item.owner?._id ? item.owner._id.toString() : item.owner?.toString?.();
    if (ownerId !== req.user.id) {
      return res.status(401).json({ msg: 'Only owner can modify permissions' });
    }

    /**
     * Find & Update Permission
     */
    const perm = item.permissions.find((p) => {
      const permUserId = p.user?._id ? p.user._id.toString() : p.user?.toString?.();
      return permUserId === userId;
    });
    if (!perm) return res.status(404).json({ msg: 'Permission not found' });
    perm.role = role;
    await item.save();
    await item.populate('permissions.user', 'username email');
    return res.json(item.permissions);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * DELETE /api/files/:id/permissions/:userId
 * 
 * Revoke a user's access to a file or folder
 * Permanently removes permission entry for specified user
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File or folder ID
 * - userId (path): User ID to revoke access from
 * 
 * Access Control:
 * - Only owner can revoke permissions
 * 
 * Response (200 OK):
 * - permissions: Updated permissions array (user removed)
 * 
 * Error Responses:
 * - 401: User is not owner
 * - 404: File not found or permission not found
 * - 500: Server error
 * 
 * @example
 * DELETE /api/files/60d5ec49c1234567890abcde/permissions/60d5ec49c1234567890ab111
 * Headers: x-auth-token: <token>
 * Response (200): Array of remaining permissions (with user removed)
 */
router.delete('/:id/permissions/:userId', auth, async (req, res) => {
  try {
    const item = await File.findById(req.params.id).populate('permissions.user', 'username email');
    if (!item) return res.status(404).json({ msg: 'Item not found' });

    /**
     * Security Check: Only Owner Can Revoke
     */
    const ownerId = item.owner?._id ? item.owner._id.toString() : item.owner?.toString?.();
    if (ownerId !== req.user.id) {
      return res.status(401).json({ msg: 'Only owner can revoke access' });
    }

    /**
     * Find & Remove Permission
     * Filter out the specified user from permissions array
     */
    const before = item.permissions.length;
    item.permissions = item.permissions.filter((p) => {
      const permUserId = p.user?._id ? p.user._id.toString() : p.user?.toString?.();
      return permUserId !== req.params.userId;
    });

    /**
     * Verify Permission Was Found
     */
    if (before === item.permissions.length) {
      return res.status(404).json({ msg: 'Permission not found' });
    }

    await item.save();
    await item.populate('permissions.user', 'username email');
    return res.json(item.permissions);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * FILE VERSIONING ENDPOINTS
 * 
 * Manage file versions and version history
 * Each file upload creates a new version entry
 * User can view all versions and delete specific older versions
 */

/**
 * GET /api/files/:id/versions
 * 
 * List all versions of a file with metadata
 * Includes upload timestamps and uploader information
 * Sorted newest to oldest
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File ID (must be type 'file', not 'folder')
 * 
 * Access Control:
 * - User must own file or have access via permissions
 * 
 * Response (200 OK):
 * - versions: Array of version objects:
 *   - versionNumber: Sequential version number (1 = oldest)
 *   - createdAt: Timestamp when version was created
 *   - cloudinaryUrl: Public URL for viewing/downloading
 *   - size: File size in bytes
 *   - fileType: File type (image, pdf, etc)
 *   - uploadedBy: User object who uploaded this version
 * - versionCount: Total number of versions
 * 
 * Error Responses:
 * - 400: Item is not a file (versions only for files)
 * - 401: User not authorized
 * - 404: File not found
 * - 500: Server error
 * 
 * @example
 * GET /api/files/60d5ec49c1234567890abcde/versions
 * Headers: x-auth-token: <token>
 * Response (200): {
 *   "versions": [
 *     {
 *       "versionNumber": 3,
 *       "createdAt": "2024-01-20T15:30:00.000Z",
 *       "cloudinaryUrl": "https://...",
 *       "size": 512000,
 *       "fileType": "pdf",
 *       "uploadedBy": { "username": "john", "email": "john@example.com" }
 *     }
 *   ],
 *   "versionCount": 3
 * }
 */
router.get('/:id/versions', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.type !== 'file') return res.status(400).json({ msg: 'Versions only available for files' });

    /**
     * Permission Check
     * User must own or have access to file
     */
    const role = await resolveUserRole(file, req.user.id);
    if (!role && file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Not authorized' });
    }

    /**
     * Ensure Version History Initialized
     * Creates initial version entry if needed
     */
    await ensureFileVersionSeed(file, file.owner);

    /**
     * Fetch & Return Versions
     * Sorted newest to oldest (for browsing latest first)
     */
    const versions = await FileVersion.find({ file: file._id })
      .sort({ versionNumber: -1 })
      .select('versionNumber createdAt cloudinaryUrl size fileType uploadedBy')
      .populate('uploadedBy', 'username email');
    return res.json({
      versions,
      versionCount: versions.length,
    });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * DELETE /api/files/:id/versions/:versionId
 * 
 * Delete a specific old version of a file
 * Cannot delete the only remaining version (safety)
 * Deletes from Cloudinary storage and database
 * If deleted version was current, promotes latest to current
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File ID
 * - versionId (path): Specific version ID to delete
 * 
 * Access Control:
 * - Only file owner can delete versions
 * 
 * Response (200 OK):
 * - msg: 'Version deleted'
 * - versionCount: Updated count of remaining versions
 * 
 * Error Responses:
 * - 400: Cannot delete only version or item not a file
 * - 401: User not owner
 * - 404: File or version not found
 * - 500: Server error
 */
router.delete('/:id/versions/:versionId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.type !== 'file') return res.status(400).json({ msg: 'Versions only available for files' });
    if (file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Only owner can delete versions' });
    }

    /**
     * Initialize Version History
     * Ensure versions are seeded before deletion
     */
    await ensureFileVersionSeed(file, file.owner);

    /**
     * Find Version to Delete
     */
    const version = await FileVersion.findOne({ _id: req.params.versionId, file: file._id });
    if (!version) return res.status(404).json({ msg: 'Version not found' });

    /**
     * Safety Check: Cannot Delete Only Version
     * Files must always have at least one version
     */
    const total = await FileVersion.countDocuments({ file: file._id });
    if (total <= 1) return res.status(400).json({ msg: 'Cannot delete the only version' });

    /**
     * Delete from Cloudinary
     * Remove actual file from cloud storage
     */
    try {
      await cloudinary.uploader.destroy(version.cloudinaryPublicId);
    } catch (destroyErr) {
      console.warn('Failed to delete Cloudinary asset for version', destroyErr.message);
    }

    /**
     * Delete Version Record from Database
     */
    await version.deleteOne();

    /**
     * Update Current Version if Needed
     * If the deleted version was the current one, promote latest
     */
    if (file.currentVersion?.toString() === version._id.toString()) {
      const latest = await FileVersion.findOne({ file: file._id }).sort({ versionNumber: -1 });
      if (latest) {
        file.cloudinaryUrl = latest.cloudinaryUrl;
        file.cloudinaryPublicId = latest.cloudinaryPublicId;
        file.fileType = latest.fileType;
        file.size = latest.size;
        file.currentVersion = latest._id;
      }
    }

    /**
     * Update Version Count & Save
     */
    file.versionCount = Math.max(1, total - 1);
    await file.save();
    return res.json({ msg: 'Version deleted', versionCount: file.versionCount });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * DELETE /api/files/:id/versions
 * 
 * Clear all old versions of a file, keeping only the latest
 * Useful for freeing up storage space when file has many versions
 * Permanently deletes all old versions from Cloudinary
 * 
 * Authentication: Required
 * Parameters:
 * - id (path): File ID
 * 
 * Access Control:
 * - Only file owner can clear version history
 * 
 * Request Body: None
 * 
 * Response (200 OK):
 * - msg: 'Version history cleared'
 * - versionCount: 1 (only latest remains)
 * 
 * Error Responses:
 * - 400: No additional versions to remove or not a file
 * - 401: User not owner
 * - 404: File not found
 * - 500: Server error
 * 
 * @example
 * DELETE /api/files/60d5ec49c1234567890abcde/versions
 * Headers: x-auth-token: <token>
 * Response (200): {
 *   "msg": "Version history cleared",
 *   "versionCount": 1
 * }
 */
router.delete('/:id/versions', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.type !== 'file') return res.status(400).json({ msg: 'Versions only available for files' });
    if (file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Only owner can clear history' });
    }

    /**
     * Initialize Version History
     */
    await ensureFileVersionSeed(file, file.owner);

    /**
     * Check if History Exists
     * Must have more than one version to clear
     */
    const versions = await FileVersion.find({ file: file._id }).sort({ versionNumber: -1 });
    if (versions.length <= 1) {
      return res.status(400).json({ msg: 'No additional versions to remove' });
    }

    /**
     * Separate Latest from Older Versions
     * Keep [0] (latest/newest), delete [...rest] (older)
     */
    const [latest, ...older] = versions;

    /**
     * Delete All Old Versions
     * Remove from Cloudinary and database
     */
    await Promise.all(older.map(async (v) => {
      try {
        await cloudinary.uploader.destroy(v.cloudinaryPublicId);
      } catch (destroyErr) {
        console.warn('Failed to delete Cloudinary asset for version', destroyErr.message);
      }
      await v.deleteOne();
    }));

    /**
     * Update File Metadata
     * Point to latest version only
     */
    file.versionCount = 1;
    file.currentVersion = latest._id;
    file.cloudinaryUrl = latest.cloudinaryUrl;
    file.cloudinaryPublicId = latest.cloudinaryPublicId;
    file.fileType = latest.fileType;
    file.size = latest.size;
    await file.save();
    return res.json({ msg: 'Version history cleared', versionCount: 1 });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * SHARED FILES ENDPOINTS
 */

/**
 * GET /api/files/shared-with-me
 * 
 * List all files and folders shared with the current user
 * Shows items where user has viewer or editor permissions
 * Does not include user's own files
 * 
 * Authentication: Required
 * Query Parameters: None
 * 
 * Response (200 OK):
 * - Array of file/folder documents:
 *   - All file properties
 *   - owner: Populated with owner's username and email
 *   - effectiveRole: User's permission level (viewer or editor)
 * 
 * Error Responses:
 * - 500: Server error
 * 
 * @example
 * GET /api/files/shared-with-me
 * Headers: x-auth-token: <token>
 * Response (200): Array of shared items
 */
router.get('/shared-with-me', auth, async (req, res) => {
  try {
    /**
     * Find All Files Shared with User
     * Searches permissions array for current user
     */
    const sharedFiles = await File.find({
      'permissions.user': req.user.id
    }).populate('owner', 'username email');

    /**
     * Attach Effective Role
     * Add permission level information to each item
     */
    const enriched = await attachEffectiveRole(sharedFiles, req.user.id);
    res.json(enriched);
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