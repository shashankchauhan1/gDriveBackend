import express from 'express';
import auth from '../middleware/auth.js';
import History from '../models/History.js';

const router = express.Router();

// @route   GET /api/history
// @desc    Get recent file open events for the current user
router.get('/', auth, async (req, res) => {
  try {
    const events = await History.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('file', 'filename cloudinaryUrl type');
    res.json(events);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

export default router;

