// server/routes/auth.js
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'; 
import User from '../models/User.js';
import auth from '../middleware/auth.js';

const router = express.Router();

// @route   POST /api/auth/register
// @desc    Register a new user
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // 1. Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    // 2. Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. Create and save the new user
    user = new User({
      username,
      email,
      password: hashedPassword,
    });

    await user.save();

    // For now, just send a success message. We'll send a JWT token later.
    res.status(201).json({ message: 'User registered successfully!' });

  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});


// @route   POST /api/auth/login
// @desc    Authenticate user & get token
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // 1. Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // 2. Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // 3. If credentials are correct, create a JWT payload
    const payload = {
      user: {
        id: user.id, // This is the user's MongoDB document ID
      },
    };

    // 4. Sign the token and send it back to the client
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '5h' }, // Token expires in 5 hours
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

export default router;
 
// @route   GET /api/auth/me
// @desc    Get current authenticated user's profile
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});