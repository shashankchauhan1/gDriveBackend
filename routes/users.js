import express from 'express';
import bcrypt from 'bcryptjs';
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

// @route   PUT /api/users/me/password
// @desc    Update current user's password
router.put('/me/password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: 'All password fields are required' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'New password and confirmation do not match' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'New password must be at least 8 characters' });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    return res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

export default router;

