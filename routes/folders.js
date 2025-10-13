// server/routes/folders.js
import express from 'express';
import auth from '../middleware/auth.js';
import File from '../models/File.js'; // We use the same 'File' model

const router = express.Router();

// @route   POST /api/folders
// @desc    Create a new folder
router.post('/', auth, async (req, res) => {
  try {
    const { name, parentId = null } = req.body;

    // Check if a folder with the same name already exists in the same location
    const existing = await File.findOne({ owner: req.user.id, parentId, filename: name, type: 'folder' });
    if (existing) {
      return res.status(400).json({ msg: 'A folder with this name already exists here.' });
    }

    const newFolder = new File({
      filename: name,
      owner: req.user.id,
      parentId,
      type: 'folder',
    });

    await newFolder.save();
    res.status(201).json(newFolder);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   GET /api/folders/:id/path
// @desc    Get the breadcrumb path for a folder
router.get('/:id/path', auth, async (req, res) => {
  try {
    const path = [];
    let currentFolderId = req.params.id;

    while (currentFolderId) {
      const folder = await File.findById(currentFolderId);

      // Security: ensure the folder exists and user has access via ownership or permissions on any ancestor
      if (!folder) return res.status(404).json({ msg: 'Path not found' });
      let hasAccess = false;
      let node = folder;
      while (node) {
        if (
          node.owner.toString() === req.user.id ||
          node.permissions.some(p => p.user.toString() === req.user.id)
        ) { hasAccess = true; break; }
        if (!node.parentId) break;
        node = await File.findById(node.parentId);
      }
      if (!hasAccess) return res.status(404).json({ msg: 'Path not found' });

      // Add the folder to the beginning of the path array
      path.unshift({ _id: folder._id, filename: folder.filename });
      currentFolderId = folder.parentId;
    }

    res.json(path);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


export default router;