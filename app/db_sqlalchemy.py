from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////test.db'
db = SQLAlchemy(app)


class User(db.Model):
    username = db.Column(db.String(32), unique=True, primary_key=True)
    password = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

#if __name__ == '__main__':
#    if os.path
#    db.create_all()
#    app.run(debug=True, host='127.0.0.1', port="5002")        