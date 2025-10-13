// server/index.js

// Main Express server setup
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose'; // ODM for MongoDB
import authRoutes from './routes/auth.js'; // User authentication routes
import fileRoutes from './routes/files.js'; // File upload and management routes
import folderRoutes from './routes/folders.js'; // Folder management routes

// Load environment variables from .env file
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware setup
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(express.json()); // Parse incoming JSON requests

// API Routes
app.use('/api/auth', authRoutes); // User authentication routes
app.use('/api/files', fileRoutes); // File upload and management routes
app.use('/api/folders', folderRoutes); // Folder management routes

// Connect to MongoDB database
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("🎉 MongoDB connected successfully!"))
  .catch(err => console.error("MongoDB connection error:", err));

// Simple route for testing server status
app.get('/api/test', (req, res) => {
  res.json({ message: 'Hello from the server!' });
});

// Start the Express server
app.listen(PORT, () => {
  console.log(` Server is running on port ${PORT}`);
});