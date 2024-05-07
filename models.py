from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_email_verified = Column(Boolean, default=False,index=True)
    
class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)   
    roll_no = Column(Integer, index=True)
    gender = Column(String, index=True)
    is_active = Column(Boolean, index=True)
