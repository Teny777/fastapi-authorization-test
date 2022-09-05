import base64
import hmac
import hashlib
import json
import os
import datetime

from typing import Optional
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from fastapi import FastAPI, Form, Cookie, Depends
from fastapi.responses import Response

from database import SessionLocal, engine
import crud, models


load_dotenv()

models.Base.metadata.create_all(bind=engine)

app = FastAPI()



SECRET_KEY = os.environ.get('SECRET_KEY')
PASSWORD_SALT = os.environ.get('PASSWORD_SALT')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def sign_data(data: str) -> str:
    """
    Возвращает подписанные данные data.
    """
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    """
    Получение username из подписанной строки.
    """
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(user: models.User, password: str) -> bool:
    """
    Проверка пароля у пользователя.
    """
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = user.password.lower()
    return password_hash == stored_password_hash


def user_to_html_string(user: models.User) -> str:
    return (
        f"Привет, {user.username}!<br />"
        f"Ваша дата рождения: {user.date_of_birth.strftime('%d.%m.%Y')}<br />"
    )


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None), db: Session = Depends(get_db)):
    with open("templates/login.html", 'r') as f:
        login_page = f.read()

    if not username:
        return Response(login_page, media_type="text/html")

    valid_usernmae = get_username_from_signed_string(username)

    if not valid_usernmae:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = crud.get_user(db, valid_usernmae)
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(user_to_html_string(user), media_type="text/html")
    


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = crud.get_user(db, username)

    if not user or not verify_password(user, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Неверный логин или пароль!"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": user_to_html_string(user)
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)

    response.set_cookie(key="username", value=username_signed)
    return response