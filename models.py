from sqlalchemy import Column, Integer, String
from database import Base

# User model/table for the database
class User(Base):
    __tablename__ = "users"  # Table name in the database

    id = Column(Integer, primary_key=True, index=True)  # Unique ID for each user
    username = Column(String, unique=True, index=True, nullable=False)  # Username
    email = Column(String, unique=True, index=True, nullable=False)  # Email
    hashed_password = Column(String, nullable=False)  # Hashed password (not plain text!)
    role = Column(String, default="user")  # Role: 'user' or 'admin' 