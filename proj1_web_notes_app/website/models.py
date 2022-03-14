from . import db
#from current package
from flask_login import UserMixin
from sqlalchemy.sql import func

#using flask to create a simple database
#Note aned User are 2 different tables

class Note(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone = True), default = func.now())
    #user can create many nodes
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    #create a "relationship" table that stores connection of notes amnd user
    notes = db.relationship('Note')