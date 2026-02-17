/**
 * Cloud-Box Backend Server
 * 
 * Main entry point for the file management API
 * Handles routing, middleware, database connections, and CORS
 * 
 * Environment Variables Required:
 * - MONGO_URI: MongoDB connection string
 * - JWT_SECRET: Secret key for JWT token signing
 * - CLOUDINARY_CLOUD_NAME: Cloudinary public ID
 * - CLOUDINARY_API_KEY: Cloudinary API key
 * - CLOUDINARY_API_SECRET: Cloudinary API secret
 * - PORT: Server port (default: 7500)
 * - CORS_ORIGIN: Allowed CORS origin (default: http://localhost:5173)
 */

import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import fileRoutes from "./routes/files.js";
import folderRoutes from "./routes/folders.js";
import userRoutes from "./routes/users.js";
import historyRoutes from "./routes/history.js";

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 7500;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';

/**
 * CORS Middleware
 * Sets appropriate headers for cross-origin requests
 * Allows requests from frontend on different port
 */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', CORS_ORIGIN);
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-auth-token, Authorization');
  res.header('Access-Control-Max-Age', '86400');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  
  next();
});

/**
 * Body Parser Middleware
 * Parse incoming JSON requests
 */
app.use(express.json());

/**
 * Request Logging Middleware
 * Logs incoming requests for debugging
 */
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

/**
 * API Routes
 * Mount all route handlers for different API endpoints
 */
app.use("/api/auth", authRoutes);      // Authentication endpoints
app.use("/api/files", fileRoutes);     // File operations
app.use("/api/folders", folderRoutes); // Folder operations
app.use("/api/users", userRoutes);     // User profile
app.use("/api/history", historyRoutes);// Activity history

/**
 * Health Check Route
 * Simple endpoint to verify server is running
 */
app.get("/api/test", (req, res) => {
  res.json({ 
    message: "Cloud-Box backend is running!",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

/**
 * Error Handling Middleware
 * Catches unhandled errors and returns standardized response
 */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

/**
 * 404 Handler
 * Returns error for non-existent routes
 */
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

/**
 * Database Connection
 * Connects to MongoDB with error handling
 */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected successfully!");
    console.log("📦 Database:", process.env.MONGO_URI?.split('/').pop());
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

/**
 * Start Server
 * Listen on specified port for incoming requests
 */
app.listen(PORT, () => {
  console.log(`🚀 Cloud-Box Server running on http://localhost:${PORT}`);
  console.log(`📡 CORS Origin: ${CORS_ORIGIN}`);
  console.log(`🔐 Environment: ${process.env.NODE_ENV || 'development'}`);
});
