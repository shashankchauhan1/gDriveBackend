/**
 * Authentication Middleware
 * 
 * Protects routes by verifying JWT tokens
 * Extracts user information from valid tokens and attaches to request object
 * 
 * Usage:
 * router.get('/protected-route', auth, (req, res) => {
 *   const userId = req.user.id;
 * });
 */

import jwt from 'jsonwebtoken';

/**
 * Authentication Middleware Function
 * 
 * Verifies JWT token from request headers and validates it
 * If valid, attaches decoded user info to req.user for use in route handlers
 * 
 * Token Location: x-auth-token header
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * 
 * @returns {void} Calls next() if token is valid, sends error response if not
 * 
 * @example
 * // Valid token in header: x-auth-token: eyJhbGc...
 * // Result: req.user = { id: "user_mongo_id" }
 */
const auth = (req, res, next) => {
  try {
    // Extract token from request header
    const token = req.header('x-auth-token');

    // Check if token exists
    if (!token) {
      return res.status(401).json({ 
        message: 'No authentication token provided. Access denied.' 
      });
    }

    // Verify token and extract payload
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Attach user info to request object for use in route handlers
    req.user = decoded.user;
    
    // Continue to next middleware/route handler
    next();
    
  } catch (error) {
    // Handle token verification errors
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token has expired. Please log in again.' 
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        message: 'Invalid token. Access denied.' 
      });
    }
    
    // Generic error response
    return res.status(401).json({ 
      message: 'Token verification failed. Please log in again.' 
    });
  }
};

export default auth;