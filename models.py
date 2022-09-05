from sqlalchemy import Column, String, Date
from database import Base

class User(Base):
    __tablename__ = 'users'
    
    login = Column(String, primary_key = True)
    password = Column(String)
    username = Column(String)
    date_of_birth = Column(Date)