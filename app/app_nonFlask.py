import os
import subprocess
from flask import Flask, abort, request, jsonify, g, url_for, redirect, escape, render_template, flash, session, make_response
from wtforms import Form, BooleanField, StringField, PasswordField, validators, IntegerField, widgets, FileField
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from flask_sqlite3 import SQLite3
from flask_sqlalchemy import SQLAlchemy
#from db_sqlalchemy import db

import sqlalchemy as db
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy import inspect
from sqlalchemy.sql import text

from itsdangerous import Signer
import hashlib
              
app = Flask(__name__)
csrf = CSRFProtect(app)
SECRET_KEY = b'?\x03?w*\xd2\x84\xea\xc3\xc1\x8c\xe7\x80\x83\x9d\x8c=\xb1\x17\xe3Z\xf4|C'
app.config['SECRET_KEY'] = SECRET_KEY
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://test.db'
#db = SQLAlchemy(app)
credential_dictionary = {}
current_session = None
session = {}
s = Signer(SECRET_KEY)
salt = "abc123"
CSP = "default-src 'self'; script-src 'self'; frame-ancestors 'self'"
admin_credential = {'username': 'admin', 'password': 'Administrator@1', 'phone': '12345678901'}
#db.create_all()


class RegistrationForm(FlaskForm):  
    uname = StringField('Username', [validators.Length(min=4, max=25)], id='uname')
    pword = PasswordField('New Password', [validators.DataRequired()], id='pword')
    #phone = StringField('Phone Number', [validators.Length(min=10, max=10), validators.DataRequired()], id='2fa')
    phone = StringField('Phone Number', [validators.DataRequired()], id='2fa')
    #phone = IntegerField('Phone', [validators.NumberRange(min=0, max=10), validators.DataRequired()], id='2fa', widget = widgets.Input(input_type="tel"))
    #confirm = PasswordField('Repeat Password')
    #accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])

class LoginForm(FlaskForm):
    uname = StringField('Username', [validators.Length(min=4, max=25)], id='uname')
    pword = PasswordField('New Password', [validators.DataRequired()], id='pword')
    phone = StringField('Phone Number', [validators.Length(min=10, max=10), validators.DataRequired()], id='2fa')
    
class UploadForm(FlaskForm):
    inputtext = StringField('Text', [validators.DataRequired()], id='inputtext')
    
def reformat_phone(form, field):
    field.data = field.data.replace('-', '')
    return True
    
def secure_response(response):
    response.headers['Content-Security-Policy'] = CSP
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    if 'ID' in session:
        response.set_cookie('session_ID', value = session['ID'], domain = '127.0.0.1', secure=True, httponly=True)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        #session['username'] = request.form['username']
        #return redirect(url_for('index'))
        #username = request.form.get('uname')
        #password = request.form.get('pword')
        #phone = request.form.get('2fa')
        username = form.uname.data
        password = form.pword.data
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        phone = form.phone.data
        print (username, password_hash, phone)
        if username in credential_dictionary:
            if password_hash == credential_dictionary[username][0]:
                if phone == credential_dictionary[username][1]:
                    print ("Login successful")
                    result = "success"
                    #return render_template('spell_check.html', form=form, result = result, credential=[username,password,phone]) 
                    session['username'] = s.sign(username)
                    current_session = s.sign(hashlib.sha256((username + salt).encode()).hexdigest())
                    session['ID'] = current_session
                    session['domain'] = request.headers['Host']
                    print ("session ID: ", session['ID'])
                    response = make_response(render_template('login.html', form=form, result = result))
                    secure_response(response)
                    return response  
                else :
                    print ("Login failed - two-factor")
                    result = "two-factor failed"
                    response = make_response(render_template('login.html', form=form, result = result))
                    secure_response(response)
                    return response
            else:
                print ("Login failed - incorrect password")
                result = "Incorrect"
                response = make_response(render_template('login.html', form=form, result = result))
                secure_response(response)
                return response 
        else:
            print ("Login failed - incorrect username")
            result = "Incorrect"
            response = make_response(render_template('login.html', form=form, result = result))
            secure_response(response)
            return response
    else:
        result = "Incorrect"
        response = make_response(render_template('login.html', form=form, result = result))
        secure_response(response)
        return response
        #return render_template('login.html', form=form, result = result) 

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        #user = User(form.uname.data, form.pword.data,
                    #form.phone.data)
        if form.uname.data not in credential_dictionary:
            #flash('Thanks for registering')
            username = form.uname.data.replace('<','').replace('>','')
            password = form.pword.data
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            credential_dictionary[username] = [password_hash, form.phone.data]
            #print (credential_dictionary[form.uname.data][0], credential_dictionary[form.uname.data][1])
            print ("username: ", username, "\npassword: ", credential_dictionary[form.uname.data][0], "\nphone: ", credential_dictionary[form.uname.data][1])
            success = 'success'
            response = make_response(render_template('register.html', form=form, success = success))
            secure_response(response)
            return response
        else:
            success = 'failure'
            response = make_response(render_template('register.html', form=form, success = success))
            secure_response(response)
            return response
        #return redirect(url_for('login'))
        success = 'failure'
        response = make_response(render_template('register.html', form=form, success = success))
        secure_response(response)
        return response
    response = make_response(render_template('register.html', form=form))
    secure_response(response)
    return response
 
#@app.route('/success')
#def success():
#    return '''
#    <p id="success">Registered successfully</p>
#    '''
 
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    session.pop('ID', None)
    current_session = None
    return redirect(url_for('login'))
 
@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    #upload file
    #POST check file
    #if result != 'success':
    #    return render_template('login.html', form=form, result=result)
    form = UploadForm(request.form)
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST' and form.validate():
        inputtext = form.inputtext.data   
        with open("test.txt","w+") as fo:
            fo.write("%s" % inputtext)
        proc = subprocess.run(["./a.out", "test.txt", "wordlist.txt"], capture_output = True, universal_newlines = True)
        misspelled = proc.stdout
        response = make_response(render_template('spell_check.html', form=form, misspelled=misspelled, textout=inputtext))
        secure_response(response)
        return response
    return render_template('spell_check.html', form=form)
    
#@app.route('/', methods = ['POST'])
#def index():
#    if 'username' in session:
        
 
#@app.route('/api/users', methods = ['POST'])
#def new_user():
#    username = request.json.get('username')
#    password = request.json.get('password')
#    if username is None or password is None:
#        abort(400) # missing arguments
#    if User.query.filter_by(username = username).first() is not None:
#        abort(400) # existing user
#    user = User(username = username)
#    user.hash_password(password)
#    db.session.add(user)
#    db.session.commit()
#    return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.errorhandler(404)
def not_found(e):
    response = make_response(redirect(url_for('register')))
    response.headers['Content-Security-Policy'] = CSP
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
    
def create_admin_account():
    cur = db.connection.cursor()
    
    cur.execute("CREATE TABLE users (username text, password text, phone text)")
    cur.execute("INSERT INTO users (username, password, phone) VALUES(?, ?, ?)", (admin_credential['username'], admin_credential['password'], admin_credential['phone']))
    db.connection.commit()
    cur.close()

def initialize_db():
    metadata = MetaData()
    users = Table('users', metadata,
      Column('id', Integer, primary_key=True),
      Column('username', String),
      Column('password', String),
      Column('phone', String)
    )
    engine = create_engine('sqlite:///app.db')
    metadata.create_all(engine)
    with engine.connect() as con:
        admin_password = hashlib.sha256(('Administrator@1' + salt).encode()).hexdigest()
        query = db.insert(users).values(id=0, username = 'admin', password = admin_password, phone = '12345678901')
        con.execute(query)
        #data = ( {"id": 0, "username": "admin", "password": admin_password, "phone": "12345678901"})
        #statement = "INSERT INTO users(id, username, password, phone) VALUES(0, 'admin', "+ admin_password +"12345678901
        #for line in data:
            #con.execute(statement, **line)
    
if __name__ == '__main__':
    app.secret_key = SECRET_KEY
    #create_admin_account()
    if not os.path.exists('app.db'):
        print ("app.db does not exist")
        initialize_db()
    app.run(debug=True, host='127.0.0.1', port="5001")