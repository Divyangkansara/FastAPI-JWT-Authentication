from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_email_verified = Column(Boolean, default=False, index=True)
    roles = Column(String, ForeignKey('roles.name')) 
    role = relationship("Role", backref="users")

    
        
class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)   
    roll_no = Column(Integer, index=True)
    gender = Column(String, index=True)
    is_active = Column(Boolean, index=True)
