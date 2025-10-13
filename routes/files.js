// server/routes/files.js
import express from 'express';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import auth from '../middleware/auth.js';
import File from '../models/File.js';
import User from '../models/User.js'; // <-- Import the User model
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
    // Find items where the parentId matches the query, or is null for the root
    const parentId = req.query.parentId || null;

    const items = await File.find({ owner: req.user.id, parentId: parentId });
    res.json(items);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   DELETE /api/files/:id
// @desc    Delete a file
router.delete('/:id', auth, async (req, res) => {
  try {
    // 1. Find the file in the database
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ msg: 'File not found' });
    }

    // 2. **Crucial Security Check:** Ensure the user owns the file
    if (file.owner.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'User not authorized' });
    }

    // 3. Delete the file from Cloudinary
    await cloudinary.uploader.destroy(file.cloudinaryPublicId);

    // 4. Delete the file record from MongoDB
    await File.findByIdAndDelete(req.params.id);

    res.json({ msg: 'File deleted successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
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