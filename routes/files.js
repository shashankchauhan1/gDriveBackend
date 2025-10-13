// server/routes/files.js
import express from 'express';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import auth from '../middleware/auth.js';
import File from '../models/File.js';
import User from '../models/User.js'; // <-- Import the User model
import History from '../models/History.js';
import dotenv from 'dotenv'; 

dotenv.config();

const router = express.Router();

// Debug print to verify Cloudinary API key is loaded
console.log('Cloudinary API Key:', process.env.CLOUDINARY_API_KEY);
console.log('Cloudinary Cloud Name:', process.env.CLOUDINARY_CLOUD_NAME);
console.log('Cloudinary API Secret:', process.env.CLOUDINARY_API_SECRET ? '***' : 'MISSING');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer for memory storage with file size/type validation
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Accept only images and PDFs
    if (
      file.mimetype.startsWith('image/') ||
      file.mimetype === 'application/pdf'
    ) {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'));
    }
  }
});

// @route   POST /api/files/upload
// @desc    Upload a file
// Improved upload route with error handling and validation
router.post('/upload', auth, (req, res, next) => {
  upload.single('file')(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      // Multer-specific errors (file too large, etc.)
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ msg: 'File too large. Max size is 10MB.' });
      }
      return res.status(400).json({ msg: `Upload error: ${err.message}` });
    } else if (err) {
      // Other errors (file type, etc.)
      return res.status(400).json({ msg: err.message });
    }
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ msg: 'No file uploaded or invalid file type.' });
    }

    // Optional parent folder to place the file in
    const { parentId } = req.body;
    let parent = null;
    if (parentId) {
      parent = await File.findById(parentId);
      if (!parent) return res.status(404).json({ msg: 'Parent folder not found' });
      // Allow if user owns the parent or has been granted permission on any ancestor
      let node = parent; let hasAccess = false;
      while (node) {
        if (node.owner.toString() === req.user.id || node.permissions.some(p => p.user.toString() === req.user.id)) { hasAccess = true; break; }
        if (!node.parentId) break;
        node = await File.findById(node.parentId);
      }
      if (!hasAccess) return res.status(401).json({ msg: 'Not authorized to upload to this folder' });
    }

    // Upload file to Cloudinary
    const uploadStream = cloudinary.uploader.upload_stream(
      { resource_type: 'auto', folder: 'mern-drive' },
      async (error, result) => {
        if (error) {
          console.error('Cloudinary Error:', error);
          return res.status(500).json({ msg: 'Error uploading to cloud storage: ' + error.message });
        }

        // Create a new file document in our database
        const newFile = new File({
          filename: req.file.originalname,
          owner: req.user.id,
          cloudinaryUrl: result.secure_url,
          cloudinaryPublicId: result.public_id,
          fileType: result.resource_type,
          size: result.bytes,
          type: 'file', // Required by schema
          parentId: parent ? parent._id : null,
        });

        await newFile.save();
        res.status(201).json(newFile);
      }
    );

    // End the stream and send the file buffer
    uploadStream.end(req.file.buffer);

  } catch (err) {
    console.error('Server Error:', err);
    res.status(500).json({ msg: 'Server Error: ' + err.message });
  }
});

// @route   GET /api/files
// @desc    Get all files AND folders for a user in a specific parent folder
router.get('/', auth, async (req, res) => {
  try {
    // Parent folder to list
    const parentId = req.query.parentId || null;

    // Root listing: show user's own items in root + any items (files or folders) explicitly shared at root
    if (!parentId) {
      const items = await File.find({
        $and: [ { parentId: null }, { isTrashed: { $ne: true } }, { $or: [
          { owner: req.user.id },
          { 'permissions.user': req.user.id }
        ] } ]
      });
      return res.json(items);
    }

    // Non-root: verify access via ancestor chain (owner or permissions on any ancestor)
    let current = await File.findById(parentId);
    if (!current) return res.status(404).json({ msg: 'Parent folder not found' });
    let hasAccess = false;
    while (current) {
      if (
        current.owner.toString() === req.user.id ||
        current.permissions.some(p => p.user.toString() === req.user.id)
      ) {
        hasAccess = true; break;
      }
      if (!current.parentId) break;
      current = await File.findById(current.parentId);
    }
    if (!hasAccess) return res.status(401).json({ msg: 'Not authorized to view this folder' });

    // If user has access to parent folder, list all its children (regardless of who owns them)
    const items = await File.find({ parentId: parentId, isTrashed: { $ne: true } });
    return res.json(items);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

// @route   POST /api/files/:id/open
// @desc    Record an "open" event for history
router.post('/:id/open', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });

    // Access check: owner or permission on any ancestor
    let node = file.type === 'folder' ? file : (file.parentId ? await File.findById(file.parentId) : file);
    let hasAccess = false;
    while (node) {
      if (node.owner.toString() === req.user.id || node.permissions.some(p => p.user.toString() === req.user.id)) { hasAccess = true; break; }
      if (!node.parentId) break;
      node = await File.findById(node.parentId);
    }
    if (!hasAccess) return res.status(401).json({ msg: 'Not authorized' });

    const entry = new History({ user: req.user.id, file: file._id, action: 'open' });
    await entry.save();
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   DELETE /api/files/:id
// @desc    Delete a file
router.delete('/:id', auth, async (req, res) => {
  try {
    // Soft delete: move to trash (owner only)
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.owner.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });

    file.isTrashed = true;
    file.trashedAt = new Date();
    await file.save();
    res.json({ msg: 'Moved to trash' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   PUT /api/files/:id/restore
// @desc    Restore a trashed item (owner only)
router.put('/:id/restore', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.owner.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });
    file.isTrashed = false;
    file.trashedAt = undefined;
    await file.save();
    res.json(file);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   GET /api/files/trash
// @desc    List trashed items for current user
router.get('/trash', auth, async (req, res) => {
  try {
    const items = await File.find({ owner: req.user.id, isTrashed: true }).sort({ trashedAt: -1 });
    res.json(items);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   DELETE /api/files/trash/:id
// @desc    Permanently delete an item in trash (owner only)
router.delete('/trash/:id', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ msg: 'File not found' });
    if (file.owner.toString() !== req.user.id) return res.status(401).json({ msg: 'User not authorized' });
    if (!file.isTrashed) return res.status(400).json({ msg: 'File is not in trash' });

    if (file.type === 'file' && file.cloudinaryPublicId) {
      try { await cloudinary.uploader.destroy(file.cloudinaryPublicId); } catch {}
    }
    await File.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Deleted permanently' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


// @route   PUT /api/files/:id/rename
// @desc    Rename a file or folder (owner or users with editor role on any ancestor)
router.put('/:id/rename', auth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ msg: 'New name is required' });

    const item = await File.findById(req.params.id);
    if (!item) return res.status(404).json({ msg: 'Item not found' });

    // Access: owner OR editor in this item or any ancestor
    let node = item;
    let canEdit = false;
    while (node) {
      if (node.owner.toString() === req.user.id) { canEdit = true; break; }
      const editor = node.permissions.find(p => p.user.toString() === req.user.id && p.role === 'editor');
      if (editor) { canEdit = true; break; }
      if (!node.parentId) break;
      node = await File.findById(node.parentId);
    }
    if (!canEdit) return res.status(401).json({ msg: 'Not authorized to rename' });

    item.filename = name.trim();
    await item.save();
    return res.json(item);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

// @route   POST /api/files/:id/revoke
// @desc    Revoke a user's access by email (owner only)
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

// @route   GET /api/files/search
// @desc    Search files/folders by name accessible to the user
router.get('/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || !q.trim()) return res.json([]);
    const regex = new RegExp(q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');

    // Find accessible items: owned or shared directly
    const ownedOrShared = await File.find({
      $or: [
        { owner: req.user.id },
        { 'permissions.user': req.user.id }
      ],
      isTrashed: { $ne: true },
      filename: regex,
    }).limit(100);

    return res.json(ownedOrShared);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

// @route   POST /api/files/:id/share
// @desc    Share a file with another user
router.post('/:id/share', auth, async (req, res) => {
  try {
    const { email, role } = req.body;

    // 1. Find the file to be shared
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ msg: 'File not found' });
    }

    // 2. Security Check: Only the owner can share the file
    if (file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'User not authorized to share this file' });
    }

    // 3. Find the user to share with by their email
    const userToShareWith = await User.findOne({ email });
    if (!userToShareWith) {
      return res.status(404).json({ msg: 'User to share with not found' });
    }

    // 4. Prevent owner from sharing with themselves
    if (userToShareWith.id === req.user.id) {
        return res.status(400).json({ msg: 'You cannot share a file with yourself' });
    }

    // 5. Check if already shared with this user
    const isAlreadyShared = file.permissions.some(p => p.user.toString() === userToShareWith.id);
    if (isAlreadyShared) {
      return res.status(400).json({ msg: 'File is already shared with this user' });
    }

    // 6. Add the permission and save
    file.permissions.push({ user: userToShareWith.id, role });
    await file.save();

    res.json(file.permissions);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   GET /api/files/shared-with-me
// @desc    Get all files shared with the current user
router.get('/shared-with-me', auth, async (req, res) => {
  try {
    // Find all files where the permissions array contains the current user's ID
    const sharedFiles = await File.find({
      'permissions.user': req.user.id
    }).populate('owner', 'username email'); // Use populate to get owner's details

    res.json(sharedFiles);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

export default router;