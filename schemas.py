from pydantic import BaseModel, EmailStr, constr

# Schema for user registration (what data we expect when someone signs up)
class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=50)  # Username must be 3-50 chars
    email: EmailStr  # Valid email address
    password: constr(min_length=8)  # Password must be at least 8 chars

# Schema for user login (what data we expect when someone logs in)
class UserLogin(BaseModel):
    username: str
    password: str

# Schema for user info we send back (response)
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str

    class Config:
        orm_mode = True  # Allows reading data from SQLAlchemy models 