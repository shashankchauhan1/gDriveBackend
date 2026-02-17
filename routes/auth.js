/**
 * Authentication Routes
 * 
 * Handles user registration, login, and profile retrieval
 * Implements JWT-based token authentication
 * 
 * Endpoints:
 * - POST /api/auth/register - Create new user account
 * - POST /api/auth/login - Authenticate and get JWT token
 * - GET /api/auth/me - Get current authenticated user profile
 */

import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import auth from '../middleware/auth.js';

const router = express.Router();

/**
 * POST /api/auth/register
 * 
 * Register a new user account
 * 
 * Required Fields:
 * - username (string): Display name for the user
 * - email (string): Unique email for authentication
 * - password (string): Min 6 characters
 * 
 * Returns:
 * - 201: User created successfully
 * - 400: Validation error or user already exists
 * - 500: Server error
 * 
 * @example
 * POST /api/auth/register
 * {
 *   "username": "john_doe",
 *   "email": "john@example.com",
 *   "password": "securePassword123"
 * }
 * 
 * Response:
 * {
 *   "message": "User registered successfully!"
 * }
 */
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    /**
     * Validate Input
     * Check that all required fields are provided
     */
    if (!username || !email || !password) {
      return res.status(400).json({
        message: 'Username, email, and password are required'
      });
    }

    /**
     * Validate Password Length
     * Ensure password meets security requirements
     */
    if (password.length < 6) {
      return res.status(400).json({
        message: 'Password must be at least 6 characters long'
      });
    }

    /**
     * Check Existing User
     * Prevent duplicate email registrations
     */
    let existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({
        message: 'Email already registered. Please log in or use a different email.'
      });
    }

    /**
     * Hash Password
     * Use bcrypt with salt for secure password storage
     */
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    /**
     * Create New User
     * Store user with hashed password
     */
    const newUser = new User({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
    });

    await newUser.save();

    /**
     * Registration Success
     * Return success message (user should now log in)
     */
    res.status(201).json({
      message: 'Registration successful! Please log in with your credentials.'
    });

  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({
      message: 'Registration failed. Please try again later.'
    });
  }
});

/**
 * POST /api/auth/login
 * 
 * Authenticate user and return JWT token
 * 
 * Required Fields:
 * - email (string): User email
 * - password (string): User password
 * 
 * Returns:
 * - 200: Login successful with JWT token
 * - 400: Invalid credentials
 * - 500: Server error
 * 
 * Token Details:
 * - Expires in 5 hours
 * - Send in x-auth-token header for protected routes
 * - Contains user ID in payload
 * 
 * @example
 * POST /api/auth/login
 * {
 *   "email": "john@example.com",
 *   "password": "securePassword123"
 * }
 * 
 * Response:
 * {
 *   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI..."
 * }
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    /**
     * Validate Input
     * Check that credentials are provided
     */
    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password are required'
      });
    }

    /**
     * Find User by Email
     * Check if email exists in database
     */
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) {
      return res.status(400).json({
        message: 'Invalid email or password'
      });
    }

    /**
     * Verify Password
     * Compare provided password with stored hash
     */
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({
        message: 'Invalid email or password'
      });
    }

    /**
     * Create JWT Token
     * Include user ID in token payload
     */
    const payload = {
      user: {
        id: user._id.toString()
      }
    };

    /**
     * Sign Token
     * Generate JWT with secret key and expiration
     */
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '5h' }, // Token valid for 5 hours
      (err, token) => {
        if (err) {
          console.error('Token generation error:', err);
          return res.status(500).json({
            message: 'Failed to generate authentication token'
          });
        }

        /**
         * Login Success
         * Return token to client for future authenticated requests
         */
        res.json({
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email
          }
        });
      }
    );

  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({
      message: 'Login failed. Please try again later.'
    });
  }
});

/**
 * GET /api/auth/me
 * 
 * Get current authenticated user's profile
 * Requires valid JWT token in x-auth-token header
 * 
 * Returns:
 * - 200: User profile data (excluding password)
 * - 401: No valid token provided
 * - 404: User not found
 * - 500: Server error
 * 
 * @example
 * GET /api/auth/me
 * Headers: x-auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI...
 * 
 * Response:
 * {
 *   "_id": "60d5ec49c1234567890abcde",
 *   "username": "john_doe",
 *   "email": "john@example.com",
 *   "createdAt": "2024-01-15T10:30:00.000Z",
 *   "updatedAt": "2024-01-15T10:30:00.000Z"
 * }
 */
router.get('/me', auth, async (req, res) => {
  try {
    /**
     * Fetch User Profile
     * Get user by ID from token, exclude password
     */
    const user = await User.findById(req.user.id).select('-password');

    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    /**
     * Return User Profile
     */
    res.json(user);

  } catch (error) {
    console.error('Profile retrieval error:', error.message);
    res.status(500).json({
      message: 'Failed to retrieve user profile'
    });
  }
});

export default router;
