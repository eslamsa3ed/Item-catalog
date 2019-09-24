import os
import sys
import json
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
envPath = os.path.join(ROOT_DIR, 'env.json')
env = json.loads(open(envPath, 'r').read())

class User(Base):
    """Create user table"""

    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    """Create Category table"""

    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False,unique=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""

        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id
        }

class Item(Base):
    """Create Item table """

    __tablename__ = "item"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False,unique=True)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'user_id': self.user_id,
            'category_id': self.category_id
            }

engine = create_engine("postgresql://"+env["POSTGRES_USER"]+":"+env["POSTGRES_PW"]+"@"+env["POSTGRES_URL"]+"/"+env["POSTGRES_DB"],
                       client_encoding='utf8')
Base.metadata.create_all(engine)
