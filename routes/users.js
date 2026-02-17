/**
 * User Profile Routes
 * 
 * Handles user account management operations
 * - Update profile information (username, email)
 * - Change password with verification
 * 
 * All operations require authentication (x-auth-token header)
 * Operations only allowed on authenticated user's own account (security)
 */

import express from 'express';
import bcrypt from 'bcryptjs';
import auth from '../middleware/auth.js';
import User from '../models/User.js';

const router = express.Router();

/**
 * PUT /api/users/me
 * 
 * Update current authenticated user's profile information
 * Allows updating username and/or email
 * 
 * Authentication: Required
 * 
 * Request Body:
 * - username (optional): New display name (2-50 chars per schema)
 * - email (optional): New email address (must be unique, will be lowercased)
 * 
 * Validation:
 * - Username: 2-50 characters
 * - Email: Must be valid email format and unique across all users
 * - At least one field required to update
 * 
 * Response (200 OK):
 * - Updated user document:
 *   - _id: User ID
 *   - username: Updated username
 *   - email: Updated email
 *   - createdAt: Original account creation date
 *   - updatedAt: Last update timestamp
 *   - Note: password field excluded for security
 * 
 * Error Responses:
 * - 404: User not found (shouldn't happen with valid token)
 * - 500: Server error or validation failure
 * 
 * @example
 * PUT /api/users/me
 * Headers: x-auth-token: <token>
 * Body: {
 *   "username": "john_doe_updated",
 *   "email": "newemail@example.com"
 * }
 * 
 * Response (200): User object with updates applied
 * {
 *   "_id": "60d5ec49c1234567890ab000",
 *   "username": "john_doe_updated",
 *   "email": "newemail@example.com",
 *   "createdAt": "2024-01-15T10:30:00.000Z",
 *   "updatedAt": "2024-01-20T15:45:00.000Z"
 * }
 */
router.put('/me', auth, async (req, res) => {
  try {
    const { username, email } = req.body;

    /**
     * Build Updates Object
     * Only include fields that were provided
     * Undefined fields are not saved
     */
    const updates = {};
    if (username) updates.username = username;
    if (email) updates.email = email;

    /**
     * Update User Document
     * runValidators: true enables schema validation
     * new: true returns updated document
     * select('-password'): Excludes password from response for security
     */
    const updated = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updated) return res.status(404).json({ message: 'User not found' });

    /**
     * Return Updated Profile
     * Client can use this to update UI with new information
     */
    return res.json(updated);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * PUT /api/users/me/password
 * 
 * Change the authenticated user's password
 * Requires verification with current password before allowing change
 * 
 * Authentication: Required
 * 
 * Request Body:
 * - currentPassword (required): User's current password for verification
 * - newPassword (required): New password (min 8 characters)
 * - confirmPassword (required): Confirmation - must match newPassword
 * 
 * Validation:
 * - Current password must be correct (verified against stored hash)
 * - New password must be at least 8 characters
 * - New password and confirmation must match
 * - All three fields required
 * 
 * Security Features:
 * - Requires current password (prevents unauthorized changes if account compromised)
 * - New password is hashed with bcrypt before storage
 * - Password field excluded from responses
 * - Uses secure comparison for password verification
 * 
 * Response (200 OK):
 * - { message: 'Password updated successfully' }
 * 
 * Error Responses:
 * - 400: Validation errors:
 *   - Missing required fields
 *   - Passwords don't match
 *   - Password too short
 *   - Current password incorrect
 * - 404: User not found
 * - 500: Server error
 * 
 * @example
 * PUT /api/users/me/password
 * Headers: x-auth-token: <token>
 * Body: {
 *   "currentPassword": "oldPassword123",
 *   "newPassword": "newSecurePassword456",
 *   "confirmPassword": "newSecurePassword456"
 * }
 * 
 * Response (200): { message: 'Password updated successfully' }
 */
router.put('/me/password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    /**
     * Validate Input Fields
     * All three fields required for password change
     */
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: 'All password fields are required' });
    }

    /**
     * Validate Password Match
     * New password and confirmation must be identical
     */
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'New password and confirmation do not match' });
    }

    /**
     * Validate Password Length
     * New password must meet security minimum
     */
    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'New password must be at least 8 characters' });
    }

    /**
     * Load User & Verify Current Password
     * Ensure user exists and they know current password
     */
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    /**
     * Verify Current Password
     * Compare provided password against stored hash
     * This prevents unauthorized password changes
     */
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect' });

    /**
     * Hash New Password
     * Use bcrypt with salt for secure storage
     */
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    /**
     * Success Confirmation
     * Return message to user for feedback
     */
    return res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server Error');
  }
});

/**
 * EXPORT MODULE
 * 
 * Export router for use in main application
 */
export default router;

