from flask_sqlalchemy import SQLAlchemy
from jose import jwt
from os import environ
import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(100), primary_key=True)
    email = db.Column(db.String(100))
    username = db.Column(db.String(100))
    access_token = db.Column(db.String)
    refresh_token = db.Column(db.String)
    credits = db.Column(db.Integer)

    def __init__(self, id, email, username, access_token, refresh_token, credits):
        self.id = id
        self.email = email
        self.username = username
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.credits = credits

class Order(db.Model):
    __tablename__ = "orders"
    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100))
    status = db.Column(db.Integer)
    customer = db.Column(db.String(100))
    quantity = db.Column(db.Integer)
    total_currency = db.Column(db.Float)
    purchase_time = db.Column(db.DateTime(timezone=True))

    def __init__(self, order_id, user_id, status, customer, quantity, total_currency, purchase_time):
        self.order_id = order_id
        self.user_id = user_id
        self.status = status
        self.customer = customer
        self.quantity = quantity
        self.total_currency = total_currency
        self.purchase_time = purchase_time

    def as_dict(self):
       return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}



if __name__ == '__main__':
    db.create_all()
    db.session.commit()