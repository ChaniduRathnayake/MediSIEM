# MediSIEM Backend API

REST API for the MediSIEM — Next-Generation SIEM/IDS for Smart Hospitals platform.

## Stack
- **Runtime**: Node.js (ESM)
- **Framework**: Express.js
- **Auth**: JWT (jsonwebtoken) + bcryptjs
- **Storage**: In-memory (swap with MongoDB / PostgreSQL for production)

## Quick Start

```bash
cd backend
cp .env.example .env          # edit JWT_SECRET
npm install
npm run dev                   # starts on http://localhost:5000
```

## API Endpoints

### Auth
| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | `/api/auth/register` | ❌ | Register a new user |
| POST | `/api/auth/login` | ❌ | Login and receive JWT |
| GET | `/api/auth/me` | ✅ Bearer | Get current user profile |
| POST | `/api/auth/logout` | ✅ Bearer | Logout (client deletes token) |

### Users
| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/api/users` | ✅ Admin | List all users |
| GET | `/api/users/:id` | ✅ Owner/Admin | Get user by ID |

### Health
| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/api/health` | ❌ | API health check |

## Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@medisiem.com | Admin@1234 |
| User | user@medisiem.com | User@1234 |

## Environment Variables

```env
PORT=5000
JWT_SECRET=your_super_secret_jwt_key_here
NODE_ENV=development
```
