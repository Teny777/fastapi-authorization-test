from sqlalchemy.orm import Session
import models

def get_user(db: Session, login: str):
    return db.query(models.User).filter(models.User.login == login).first()


