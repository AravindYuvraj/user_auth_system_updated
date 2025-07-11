# User Authentication System

A secure user authentication system built with FastAPI, JWT tokens, and role-based access control.

## Features
- User registration with password hashing (bcrypt)
- Password strength validation (min 8 chars, special character)
- Prevents duplicate usernames and emails
- User login with JWT token generation (30 min expiry)
- **Token refresh**: Get a new JWT before the old one expires (`/auth/refresh`)
- **Logout**: Invalidate your token (`/auth/logout`)
- **Forgot password**: Request a password reset (`/auth/forgot-password`)
- Protected routes (requires valid JWT token)
- Role-based access control (admin-only endpoints)
- Admin endpoints:
  - Get all users
  - Change user role
  - Delete user
- Proper error messages for authentication failures
- Simple web UI for registration, login, and user info
- Interactive API docs at `/docs`
- **Health check endpoint**: `/health`

## Security Features
- **Rate Limiting**: Prevents abuse (e.g., brute-force attacks)
  - Login: 5 per minute per IP
  - Registration: 3 per minute per IP
  - Password reset: 1 per minute per IP
  - General API: 100 per minute per IP
- **CORS**: Only allows trusted origins (localhost by default)
- **Security Headers**: Protects against common web attacks
- **Input Sanitization**: Cleans user input to prevent malicious data
- **Custom Error Handling**: Consistent, clear error messages
- **Token Blacklisting**: Prevents reuse of tokens after logout

## Requirements
- Python 3.8+
- See `requirements.txt` for dependencies

## Installation
1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd user_auth_system
   ```
2. **(Optional) Create a virtual environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```
3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install email-validator jinja2
   ```

## Running the App
1. Start the server:
   ```bash
   uvicorn main:app --reload
   ```
2. Open your browser:
   - Simple UI: [http://127.0.0.1:8000/ui](http://127.0.0.1:8000/ui)
   - API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   - Health check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

## End-to-End Example (Layman Terms)

### 1. **Register a New User**
- Go to `/ui` or `/docs`.
- Enter a username, email, and strong password (at least 8 characters, with a special character).
- Click Register. If successful, you’re now in the system!

### 2. **Login**
- Enter your username and password.
- Click Login. You’ll get a JWT token (like a digital badge).
- Save this token (the UI does this for you).

### 3. **Get Your Info (Protected Route)**
- Click “Get My Info” in the UI, or use `/auth/me` in `/docs` with your token.
- You’ll see your username, email, and role.

### 4. **Refresh Your Token**
- If your token is about to expire, POST to `/auth/refresh` with your token to get a new one.

### 5. **Logout**
- POST to `/auth/logout` with your token. Your token is now invalid—no one can use it again.

### 6. **Forgot Password**
- POST your email to `/auth/forgot-password`. (In a real app, you’d get a reset link by email.)

### 7. **Admin Features**
- If you’re an admin, you can:
  - See all users (`/auth/users`)
  - Change user roles (`/auth/users/{user_id}/role`)
  - Delete users (`/auth/users/{user_id}`)
- These are protected—only admins can use them.

### 8. **Health Check**
- Visit `/health` to see if the API is running (should return `{ "status": "ok" }`).

## Testing Rate Limits
- Try logging in more than 5 times in a minute—you’ll get a “Too Many Requests” error.
- Try registering more than 3 times in a minute—same thing.
- Password reset: only 1 per minute per IP.

## Notes
- All passwords are securely hashed before storage
- JWT tokens expire after 30 minutes
- Only admins can access user management endpoints
- For production, set a strong `SECRET_KEY` and use HTTPS

## License
MIT 