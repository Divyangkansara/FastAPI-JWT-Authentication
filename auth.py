import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import timedelta, datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users, Role
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm.exc import NoResultFound
from typing import List, Optional


router = APIRouter(
    prefix='/auth',
    tags=['auth']
)



SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

EMAIL_HOST='smtp.gmail.com'  
EMAIL_PORT=587 
EMAIL_USE_TLS=True  
EMAIL_HOST_USER = 'divyang.kansara@technostacks.com' 
EMAIL_HOST_PASSWORD= '#Kansara@4698$'

class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_email_verified: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
class CreateRoleRequest(BaseModel):
    name: str

@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(create_role_request: CreateRoleRequest, db: Session = Depends(get_db)):
    role = Role(name=create_role_request.name)
    db.add(role)
    db.commit()
    return role

def send_email(recipient_email: str, subject: str, message: str):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'html'))

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
        server.starttls()  # Start TLS encryption
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
        response = server.sendmail(EMAIL_HOST_USER, recipient_email, msg.as_string())
        print(response)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest, roles: List[str], db: Session = Depends(get_db)):
    default_role = db.query(Role).filter(Role.name == "user").first()

    if not default_role:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default role 'user' not found in the database."
        )
    
    new_user = Users(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_email_verified=create_user_request.is_email_verified,
        roles=default_role.name
    )

    if roles:
        for role_name in roles:
            try:
                roles = db.query(Role).filter(Role.name == role_name).one()
                new_user.roles = roles.name
            except NoResultFound:
                pass

    db.add(new_user)
    db.commit()

    token = create_access_token(create_user_request.username, new_user.id, timedelta(minutes=20))
    print('➡ auth.py:74 token:', token)

    base_url = f'http://127.0.0.1:8000/auth/verify-email?token={token}'

    recipient_email = new_user.username
    print('➡ auth.py:76 recipient_email:', recipient_email)
    subject = "Verify your email"
    message = f"Click the following link to verify your email: {base_url}"
    html_txt = f"""<!DOCTYPE html>
        <html lang="en">
            <head></head>
            <body>
            Click the following link to verify your email: <a href='{base_url}'>link</a>
            </body>
        </html>"""
    message = html_txt

    send_email(recipient_email, subject, message)

    return new_user




@router.get("/verify-email")
async def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print('➡ auth.py:86 payload:', payload)
        user_id = payload.get('id')
        print('➡ auth.py:87 user_id:', user_id)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid link"
            )
            
        user = db.query(Users).filter(Users.id == user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid link"
            )        
        user.is_email_verified = True
        db.commit()
        
        return {"message":"Email verified successfully"} 
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token."
        )

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
            )
     
    token = create_access_token(user.username, user.id, timedelta(minutes=20))

    return {"access_token": token, "token_type": "bearer"}
 
def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    print('➡ auth.py:128 user:', user)
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_bearer)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.")
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.")
    
