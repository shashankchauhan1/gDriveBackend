import express from 'express';
import auth from '../middleware/auth.js';
import User from '../models/User.js';

const router = express.Router();

// @route   PUT /api/users/me
// @desc    Update current user's profile (username, email)
router.put('/me', auth, async (req, res) => {
  try {
    const { username, email } = req.body;
    const updates = {};
    if (username) updates.username = username;
    if (email) updates.email = email;

    const updated = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updated) return res.status(404).json({ message: 'User not found' });
    return res.json(updated);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

export default router;

