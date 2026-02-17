# Cloud-Box Backend Developer Guide

## 📋 Overview

This guide provides comprehensive documentation for the Cloud-Box backend - a MERN stack file management system with cloud storage, permissions, and versioning.

**Stack**: Node.js + Express.js + MongoDB + Mongoose + Cloudinary

## 🏗️ Architecture

### Core Components

- **Entry Point**: `index.js` - Server initialization, middleware setup, routing
- **Authentication**: `middleware/auth.js` - JWT token verification and user injection
- **Models**: Mongoose schemas for users, files, versions, and activity history
- **Routes**: RESTful API endpoints organized by resource type

### Models Structure

```
User (accounts)
├── username: string (2-50 chars)
├── email: string (unique, lowercase)
└── password: string (hashed, hidden)

File (files AND folders - unified model)
├── filename: string
├── type: 'file' | 'folder'
├── owner: reference to User
├── parentId: reference to File (parent folder)
├── permissions: array of {user, role}
│   └── role: 'viewer' | 'editor'
├── cloudinaryUrl: string (for files only)
├── cloudinaryPublicId: string (for cloud deletion)
├── size: number (bytes)
├── isTrashed: boolean (soft delete flag)
├── versionCount: number (for files)
└── currentVersion: reference to FileVersion

FileVersion (tracks file uploads)
├── file: reference to File
├── versionNumber: sequential counter
├── cloudinaryUrl: specific version URL
├── cloudinaryPublicId: cloud asset ID
├── uploadedBy: reference to User
├── fileType: 'image' | 'pdf' | etc.
└── size: bytes

History (activity log)
├── user: reference to User
├── file: reference to File
├── action: 'open' (extensible)
└── createdAt/updatedAt: timestamps
```

## 🔐 Authentication & Security

### JWT Token Flow

1. **Login** (`POST /api/auth/login`)
   - User sends email + password
   - Server verifies password against bcrypt hash
   - Server returns JWT token (valid for 5 hours)

2. **Protected Requests**
   - Client sends token in `x-auth-token` header
   - `auth` middleware verifies token
   - Extracts user ID and injects into `req.user.id`

3. **Token Verification**
   - Happens in `middleware/auth.js`
   - Handles expired tokens (TokenExpiredError)
   - Handles invalid tokens (JsonWebTokenError)
   - Returns specific error messages for debugging

### Password Security

- **Storage**: bcrypt with salt (10 rounds)
- **Verification**: bcrypt.compare() for safe comparison
- **Hidden Fields**: password marked with `select: false` in User model
- **Update**: Requires current password verification (`PUT /api/users/me/password`)

### Permission Model

**Role-Based Access Control (RBAC)**

Cascading permissions from parent to children:

```
Folder hierarchy:    User permissions:
├── Root/
│   ├── Projects/   ← shared as 'editor' with User A
│   │   ├── 2024/   ← User A inherits 'editor' access
│   │   │   └── Q1/Resume.pdf  ← User A can rename, view, upload versions
│   │   └── file.txt
│   └── Photos/
│       └── Vacation.jpg
```

**Access Resolution Algorithm** (`resolveUserRole` in files.js):

1. Check if user is owner → return 'owner'
2. Check if direct permission exists → return that role
3. If item has parent, traverse up and repeat
4. Return null if no access found in chain

**Roles**:
- **owner**: Full control, can share, delete, rename
- **editor**: Can upload new versions, rename, create subfolders
- **viewer**: Read-only access

## 📡 API Endpoints

### Authentication Routes (`/api/auth`)

#### `POST /api/auth/register`
- Register new user account
- Body: `{username, email, password}`
- Returns: 201 with success message
- Validations: email unique, password min 6 chars

#### `POST /api/auth/login`
- Authenticate and get JWT token
- Body: `{email, password}`
- Returns: 200 with `{token, user}`
- Valid for 5 hours from issue time

#### `GET /api/auth/me`
- Get current user profile (authenticated)
- Returns: 200 with user object (no password)
- Requires: x-auth-token header

---

### Files Routes (`/api/files`)

#### Upload & Retrieve

**`POST /api/files/upload`**
- Upload file to Cloudinary
- Multipart form-data: `{file, parentId?}`
- Max size: 10MB
- Allowed: Images (all types), PDFs
- Returns: 201 with file metadata
- Creates FileVersion entry automatically

**`GET /api/files`**
- List accessible files/folders
- Query: `?parentId=folderId` (optional)
- Root listing: user's items + shared items
- Subfolder: all items in folder (if user has access)
- Returns: 200 with array of items + effectiveRole

**`POST /api/files/:id/open`**
- Record file open event (for activity logging)
- Returns: 201 with `{ok: true}`
- Creates History entry

#### Modification

**`PUT /api/files/:id/rename`**
- Rename file or folder
- Body: `{name}`
- Requires: owner or editor role
- Returns: 200 with updated file

**`DELETE /api/files/:id`**
- Soft delete (move to trash)
- Requires: owner or editor role
- Returns: 200 with `{msg: 'Moved to trash'}`

#### Trash Management

**`GET /api/files/trash`**
- List user's trashed items
- Returns: 200 with array of trashed items

**`PUT /api/files/:id/restore`**
- Restore from trash
- Requires: owner only
- Returns: 200 with restored file

**`DELETE /api/files/trash/:id`**
- Permanently delete from trash
- Deletes from Cloudinary + database
- Requires: owner only
- Cascade: Deletes all versions if file

#### Search

**`GET /api/files/search`**
- Full-text search on filenames
- Query: `?q=searchterm`
- Only returns accessible items
- Max 100 results
- Returns: 200 with search results

#### Sharing & Permissions

**`POST /api/files/:id/share`**
- Share file with another user
- Body: `{email, role}`
- Requires: owner only
- Returns: 200 with permissions array + mode ('created'|'updated')

**`GET /api/files/:id/permissions`**
- View all permissions on file
- Requires: owner only
- Returns: 200 with owner + permissions array

**`PATCH /api/files/:id/permissions`**
- Update user's role on file
- Body: `{userId, role}`
- Requires: owner only
- Returns: 200 with updated permissions

**`DELETE /api/files/:id/permissions/:userId`**
- Revoke user's access
- Requires: owner only
- Returns: 200 with updated permissions

**`POST /api/files/:id/revoke`** (Deprecated)
- Old endpoint, use DELETE permissions/:userId instead
- Body: `{email}`

#### File Versions

**`GET /api/files/:id/versions`**
- List all versions of file
- Returns: 200 with versions array + count
- Sorted newest first

**`DELETE /api/files/:id/versions/:versionId`**
- Delete specific old version
- Requires: owner only
- Safety: Cannot delete only version
- Returns: 200 with updated count

**`DELETE /api/files/:id/versions`**
- Clear history (keep only latest version)
- Requires: owner only
- Returns: 200 with count=1

#### Sharing Status

**`GET /api/files/shared-with-me`**
- List files shared with current user
- Returns: 200 with array of shared items

---

### Folders Routes (`/api/folders`)

#### `POST /api/folders`
- Create new folder
- Body: `{name, parentId?}`
- Duplicate names allowed in different parents
- Returns: 201 with folder metadata

#### `GET /api/folders/:id/path`
- Get breadcrumb path from folder to root
- Returns: 200 with path array
- Security: Verifies access at each level

---

### User Routes (`/api/users`)

#### `PUT /api/users/me`
- Update user profile
- Body: `{username?, email?}`
- Requires: authentication
- Returns: 200 with updated user (no password)
- Validation: email unique

#### `PUT /api/users/me/password`
- Change password
- Body: `{currentPassword, newPassword, confirmPassword}`
- Requires: current password verification
- Min length: 8 characters
- Returns: 200 with success message

---

### History Routes (`/api/history`)

#### `GET /api/history`
- Get recent activity events
- Returns: 200 with max 50 events (newest first)
- Populated with file details
- Sorted by createdAt descending

---

## 🛠️ Environment Variables

Create `.env` in backend root:

```env
# Server
PORT=5000
NODE_ENV=development

# Database
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname

# JWT
JWT_SECRET=your-secret-key-here

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# CORS
CORS_ORIGIN=http://localhost:5173
```

## 🚀 Running the Server

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Expected output:
# Server running on port 5000
# MongoDB connected
# CORS enabled for http://localhost:5173
```

## 💾 Database Models in Detail

### User Model

```javascript
{
  username: String (2-50 chars, required),
  email: String (email format, unique, lowercase),
  password: String (min 6 chars, hashed, hidden),
  createdAt: Date,
  updatedAt: Date
}
```

Validation: Regex on email, minlength on password

### File Model

```javascript
{
  filename: String (max 255),
  type: 'file' | 'folder',
  owner: ObjectId → User,
  parentId: ObjectId → File (null for root),
  cloudinaryUrl: String,
  cloudinaryPublicId: String,
  fileType: String,
  size: Number,
  permissions: [{
    user: ObjectId → User,
    role: 'viewer' | 'editor'
  }],
  currentVersion: ObjectId → FileVersion,
  versionCount: Number,
  isTrashed: Boolean (default false),
  trashedAt: Date,
  createdAt: Date,
  updatedAt: Date
}
```

Indexes:
- `{owner: 1, parentId: 1, type: 1}` - fast folder listing
- `{owner: 1, isTrashed: 1}` - fast trash queries

### FileVersion Model

```javascript
{
  file: ObjectId → File (required),
  versionNumber: Number,
  cloudinaryUrl: String,
  cloudinaryPublicId: String,
  fileType: String,
  size: Number,
  uploadedBy: ObjectId → User,
  createdAt: Date,
  updatedAt: Date
}
```

### History Model

```javascript
{
  user: ObjectId → User,
  file: ObjectId → File,
  action: 'open',
  createdAt: Date,
  updatedAt: Date
}
```

## 🔄 Request/Response Examples

### Login Flow

```bash
# 1. Register
POST http://localhost:5000/api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securePassword123"
}

Response: 201
{ "message": "Registration successful! Please log in with your credentials." }

# 2. Login
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securePassword123"
}

Response: 200
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "60d5ec49c1234567890ab000",
    "username": "john_doe",
    "email": "john@example.com"
  }
}

# 3. Authenticated Request (use token)
GET http://localhost:5000/api/auth/me
Headers: x-auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Response: 200
{
  "_id": "60d5ec49c1234567890ab000",
  "username": "john_doe",
  "email": "john@example.com",
  "createdAt": "2024-01-15T10:30:00.000Z"
}
```

### File Upload Flow

```bash
# 1. Create folder
POST http://localhost:5000/api/folders
Headers: x-auth-token: <token>
Content-Type: application/json

{
  "name": "Projects"
}

Response: 201
{
  "_id": "60d6ec49c1234567890abcdf",
  "filename": "Projects",
  "owner": "60d5ec49c1234567890ab000",
  "type": "folder",
  "parentId": null
}

# 2. Upload file to folder
POST http://localhost:5000/api/files/upload
Headers: x-auth-token: <token>
Content-Type: multipart/form-data

Body:
file: [binary image data]
parentId: 60d6ec49c1234567890abcdf

Response: 201
{
  "_id": "60d6ec49c1234567890abce0",
  "filename": "screenshot.png",
  "type": "file",
  "owner": "60d5ec49c1234567890ab000",
  "parentId": "60d6ec49c1234567890abcdf",
  "cloudinaryUrl": "https://res.cloudinary.com/...",
  "size": 204800,
  "effectiveRole": "owner"
}
```

## 🐛 Debugging Tips

### Check Server Logs

```bash
# Terminal shows:
- Incoming requests with paths
- Middleware execution
- Database operations
- Error details with stack traces
```

### Common Error Responses

| Status | Message | Cause |
|--------|---------|-------|
| 400 | "Invalid credentials" | Wrong email/password |
| 401 | "Token has expired" | JWT expired (5 hours) |
| 401 | "Invalid token" | Malformed or wrong token |
| 401 | "Not authorized" | User lacks permission |
| 404 | "File not found" | Invalid file ID |
| 500 | "Server Error" | Unhandled exception |

### Performance Optimization

**Already Implemented**:
- Request logging middleware
- Database indexes for common queries
- Caching in permission resolution (loadFromCache)

**Could Add**:
- Rate limiting middleware
- Response compression
- Query optimization for large file lists
- Pagination on history endpoint

## 🔗 Integration with Frontend

Frontend typically:

1. **Stores token** after login (localStorage or secure cookie)
2. **Sends token** in `x-auth-token` header for all requests
3. **Handles token expiry** by redirecting to login when 401 received
4. **Uses file metadata** to build UI (filename, owner, effectiveRole)
5. **Polls history** endpoint for recent activity
6. **Streams files** from cloudinaryUrl (no backend proxy needed)

See [Frontend Documentation](../gDriveFrontend/README.md) for integration details.

## 📝 Key Design Decisions

### Single File Model for Files AND Folders
- Simplifies query logic (same DB operations for both)
- `type: 'file'` vs `type: 'folder'` distinguishes them
- Easier permission inheritance (same permissions array)

### Soft Delete Pattern
- `isTrashed: true` instead of immediate deletion
- Allows recovery within reasonable timeframe
- Trash permanently deleted requires separate endpoint

### Cloudinary Storage
- Files stored externally, not on server
- Reduces server load and storage costs
- Reliable, scalable, CDN-backed file delivery
- Public URLs for direct streaming (no download endpoint needed)

### Cascading Permissions
- Permissions inherit from parent folders
- Prevents permission explosion (don't need to set permissions on every file)
- One share action grants access to entire folder tree

### Version Tracking via Separate Model
- Each upload creates FileVersion entry
- Main File document always points to current version
- Allows deleting old versions while keeping latest
- Maintains audit trail

## 🚨 Security Considerations

✅ **Implemented**:
- JWT token validation on all protected routes
- Password hashing with bcrypt
- Unique email constraint
- Permission checks before file access
- CORS restriction to frontend origin
- Password field hidden in responses
- Email lowercased for case-insensitive matching

⚠️ **Consider Adding**:
- Rate limiting (prevent brute force login attempts)
- Request size limits
- SQL injection protection (already via Mongoose)
- XSS protection headers
- HTTPS requirement in production
- API key rotation for Cloudinary

## 📚 Related Documentation

- [Frontend Guide](../gDriveFrontend/README.md) - React component structure
- [Responsiveness Guide](../gDriveFrontend/RESPONSIVENESS_GUIDE.md) - CSS breakpoints
- [Project README](../README.md) - High-level overview
