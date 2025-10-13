import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import fileRoutes from "./routes/files.js";
import folderRoutes from "./routes/folders.js";
import userRoutes from "./routes/users.js";
import historyRoutes from "./routes/history.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 7500;

// ✅ Step 1: Simplest: remove cors() complexity and set headers ourselves for all routes

// ✅ Step 2: Global preflight + CORS headers (explicit, fixed origin)
app.use((req, res, next) => {
  // For local dev, fix the allowed origin explicitly
  res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-auth-token, Authorization');
  // Do not send Allow-Credentials unless you use cookies; tokens are in headers
  // res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ✅ Step 3: Parse incoming JSON requests
app.use(express.json());

// Always set CORS headers for every response
app.use((req, res, next) => {
  const origin = req.header('Origin');
  res.header('Access-Control-Allow-Origin', origin || '*');
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-auth-token, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ✅ Step 4: Define your routes
app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/folders", folderRoutes);
app.use("/api/users", userRoutes);
app.use("/api/history", historyRoutes);

// ✅ Step 5: Test route
app.get("/api/test", (req, res) => {
  res.json({ message: "Hello from the server!" });
});

// ✅ Step 6: Connect MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("🎉 MongoDB connected successfully!"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
