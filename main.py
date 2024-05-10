from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional
from models import Student as StudentDBModel
from models import Role as RoleModel
from database import SessionLocal, engine
from datetime import datetime, timedelta
import auth
from auth import get_current_user
from dotenv import load_dotenv

load_dotenv() 


app = FastAPI()
app.include_router(auth.router)
Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Student(BaseModel):
    first_name: str
    last_name: str
    roll_no: int
    gender: str
    is_active: bool

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_stud_info(db, student_id):
    stud = db.query(StudentDBModel).filter(student_id == StudentDBModel.id).first()
    return stud

@app.post("/students/")
def create_student(student: Student, user: Session = Depends(get_current_user), db: Session = Depends(get_db)):
    db_student = StudentDBModel(**student.dict())
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return db_student

@app.get("/students/{student_id}")
def get_students(user: Session = Depends(get_current_user), db: Session = Depends(get_db)):
    students = db.query(StudentDBModel).all()
    return students

@app.put("/students/{student_id}")
def update_student(student_id: int, student: Student, user: Session = Depends(get_current_user), db: Session = Depends(get_db)):
    db_student = get_stud_info(db, student_id)
    if db_student is None:
        raise HTTPException(status_code=404, detail="Student not found")
    for attr, value in student.dict().items():
        setattr(db_student, attr, value)
    db.commit()
    db.refresh(db_student)
    return db_student

@app.delete("/students/{student_id}")
def delete_student(student_id: int, user: Session = Depends(get_current_user), db: Session = Depends(get_db)):
    db_student = get_stud_info(db, student_id)
    if db_student is None:
        raise HTTPException(status_code=404, detail="Student not found")
    db.delete(db_student)
    db.commit()
    return {"message": "Student deleted successfully"}

