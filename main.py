from fastapi import FastAPI
from database import Base, engine
from auth import router as auth_router
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware import Middleware
from rate_limit import limiter
from slowapi import _rate_limit_exceeded_handler
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import RequestValidationError
from fastapi import status
from slowapi.errors import RateLimitExceeded

# Create the FastAPI app
app = FastAPI()

# Create the database tables (if they don't exist)
Base.metadata.create_all(bind=engine)

# Mount static directory for serving UI files
if not os.path.exists("static"):
    os.makedirs("static")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up templates directory for HTML rendering
if not os.path.exists("templates"):
    os.makedirs("templates")
templates = Jinja2Templates(directory="templates")

# Set up CORS (allow only specific origins, e.g., localhost for dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# (Optional) Redirect HTTP to HTTPS in production
# app.add_middleware(HTTPSRedirectMiddleware)

# Set up SlowAPI rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add security headers (HSTS, X-Content-Type-Options, etc.)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# Root endpoint for testing
@app.get("/")
def read_root():
    return {"message": "Welcome to the User Authentication System!"}

@app.get("/ui", include_in_schema=False)
def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok"}

app.include_router(auth_router)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body},
    ) 