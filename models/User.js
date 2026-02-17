/**
 * User Model
 * 
 * Represents a Cloud-Box user account
 * Stores user authentication credentials and profile information
 * 
 * Fields:
 * - username: Display name for the user
 * - email: Unique email address for login
 * - password: Hashed password (never stored as plaintext)
 * - createdAt/updatedAt: Automatic timestamps
 */

import mongoose from 'mongoose';

/**
 * User Schema Definition
 * 
 * @typedef {Object} User
 * @property {String} username - User's display name (required, trimmed)
 * @property {String} email - User's email for authentication (required, unique, lowercase)
 * @property {String} password - Bcrypt hashed password (required, never plaintext)
 * @property {Date} createdAt - Auto-generated creation timestamp
 * @property {Date} updatedAt - Auto-generated update timestamp
 */
const userSchema = new mongoose.Schema({
  /**
   * Username
   * Used for display purposes and identified by the user
   */
  username: {
    type: String,
    required: [true, 'Username is required'],
    trim: true,
    minlength: [2, 'Username must be at least 2 characters'],
    maxlength: [50, 'Username cannot exceed 50 characters']
  },

  /**
   * Email Address
   * Unique identifier for user login
   * Used for authentication and communication
   */
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
  },

  /**
   * Password
   * Stored as bcrypt hash for security
   * NEVER stored or transmitted as plaintext
   */
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false // Don't include password in queries by default
  }

}, { 
  timestamps: true // Automatically adds createdAt and updatedAt fields
});

/**
 * Create Model
 * Compiles schema into a model
 */
const User = mongoose.model('User', userSchema);

export default User;