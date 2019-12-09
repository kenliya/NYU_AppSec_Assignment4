import os
import subprocess
from subprocess import PIPE
import datetime
from flask import Flask, abort, request, jsonify, g, url_for, redirect, escape, render_template, flash, session, make_response
from wtforms import Form, BooleanField, StringField, PasswordField, validators, IntegerField, widgets, FileField
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
#from flask_sqlite3 import SQLite3
from itsdangerous import Signer
import hashlib
from flask_sqlalchemy import SQLAlchemy
#from db_setup import init_db
#import models
import db_init
from tables import User_Table, Login_Table
 
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
SECRET_KEY = b'?\x03?w*\xd2\x84\xea\xc3\xc1\x8c\xe7\x80\x83\x9d\x8c=\xb1\x17\xe3Z\xf4|C'
app.config['SECRET_KEY'] = SECRET_KEY
credential_dictionary = {}
current_session = None
session = {}
s = Signer(SECRET_KEY)
salt = "abc123"
CSP = "default-src 'self'; script-src 'self'; frame-ancestors 'self'"
admin_credential = {'username': 'admin', 'password': 'Administrator@1', 'phone': '12345678901'}

db = SQLAlchemy(app)

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
    
class LoginHistoryForm(FlaskForm):
    userid = StringField('Username', [validators.Length(min=4, max=25)], id='userid')
    
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
        search_query = db_init.User.query.filter(db_init.User.username == username).first()
        if search_query:
            if password_hash == search_query.password:
                if phone == search_query.phone:
                    print ("Login successful")
                    result = "success"
                    response = make_response(render_template('login.html', form=form, result = result))
                    secure_response(response)
                    #session['login'] = True
                    login_timestamp = datetime.datetime.now()
                    session['username'] = username
                    current_session = s.sign(hashlib.sha256((username + login_timestamp.strftime("%m/%d/%Y, %H:%M:%S") + salt).encode()).hexdigest())
                    session['ID'] = current_session
                    login_history = db_init.Login_History(username = username, session_cookie = current_session, login_timestamp = login_timestamp, logout_timestamp = 'N/A')
                    db_init.db_session.add(login_history)
                    db_init.db_session.commit()
                    return response  
                else:
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

        #if username in credential_dictionary:
        #    if password_hash == credential_dictionary[username][0]:
        #        if phone == credential_dictionary[username][1]:
        #            print ("Login successful")
        #            result = "success"
        #            #return render_template('spell_check.html', form=form, result = result, credential=[username,password,phone]) 
        #            session['username'] = s.sign(username)
        #            current_session = s.sign(hashlib.sha256((username + salt).encode()).hexdigest())
        #            session['ID'] = current_session
        #            session['domain'] = request.headers['Host']
        #            print ("session ID: ", session['ID'])
        #            response = make_response(render_template('login.html', form=form, result = result))
        #            secure_response(response)
        #            return response  
        #        else :
        #            print ("Login failed - two-factor")
        #            result = "two-factor failed"
        #            response = make_response(render_template('login.html', form=form, result = result))
        #            secure_response(response)
        #            return response
        #    else:
        #        print ("Login failed - incorrect password")
        #        result = "Incorrect"
        #        response = make_response(render_template('login.html', form=form, result = result))
        #        secure_response(response)
        #        return response 
        #else:
        #    print ("Login failed - incorrect username")
        #    result = "Incorrect"
        #    response = make_response(render_template('login.html', form=form, result = result))
        #    secure_response(response)
        #    return response
#    else:
#        result = "Incorrect"
#        response = make_response(render_template('login.html', form=form, result = result))
#        secure_response(response)
#        return response
        #return render_template('login.html', form=form, result = result) 

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        #user = User(form.uname.data, form.pword.data,
                    #form.phone.data)
        #if form.uname.data not in credential_dictionary:
        if not check_user_exists(form.uname.data):
            #flash('Thanks for registering')
            username = form.uname.data.replace('<','').replace('>','')
            password = form.pword.data
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            #credential_dictionary[username] = [password_hash, form.phone.data]
            #print (credential_dictionary[form.uname.data][0], credential_dictionary[form.uname.data][1])
            print ("username: ", username, "\npassword: ", password_hash, "\nphone: ", form.phone.data)
            new_user = db_init.User(username=username, password = password_hash, phone = form.phone.data)
            db_init.db_session.add(new_user)
            db_init.db_session.commit()
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
    logout_timestamp = datetime.datetime.now()
    login_history = db_init.Login_History.query.filter(db_init.Login_History.session_cookie == session['ID']).first()
    login_history.logout_timestamp = logout_timestamp
    db_init.db_session.commit()
    #login_history = 
    #login_history = db_init.Login_History(username = username, session_cookie = current_session, login_timestamp = login_timestamp, logout_timestamp = 'N/A')
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
        #proc = subprocess.run(["./a.out", "test.txt", "wordlist.txt"], capture_output = True, universal_newlines = True)
        proc = subprocess.run(["./a.out", "test.txt", "wordlist.txt"], stdout=PIPE, stderr=PIPE, universal_newlines = True)
        misspelled = proc.stdout
        query_count = db_init.db_session.query(db_init.Query_History).count()
        query = db_init.Query_History(username=session['username'], query_num = query_count, query_text = inputtext, query_results = misspelled)
        query_count+=1
        db_init.db_session.add(query)
        db_init.db_session.commit()
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

#@app.errorhandler(404)
#def not_found(e):
#    response = make_response(redirect(url_for('register')))
#    response.headers['Content-Security-Policy'] = CSP
#    response.headers['X-XSS-Protection'] = '1; mode=block'
#    return response
    
@app.route('/get_users', methods=['GET', 'POST'])
def get_users():
    #query = db_init.User.query.all()
    query = db_init.db_session.query(db_init.User)
    results = query.all()
    #print (query)
    table = User_Table(results)
    table.border = True
    return render_template('get_users.html', table=table)
    
@app.route('/login_history', methods=['GET', 'POST'])
def login_history():
    form = LoginHistoryForm(request.form)
    if 'username' in session.keys():
        if session['username'] == 'admin':
            if request.method == 'POST' and form.validate():
                username = form.userid.data
                query = db_init.Login_History.query.filter(db_init.Login_History.username == username)
                results = query.all()
                #table = Login_Table(results)
                return render_template('login_history.html', form = form, results = results)
            else:
                return render_template('login_history.html', form = form)
    return render_template('login_history.html', form = form)
    
@app.route('/history', methods=['GET', 'POST'])
def history():
    if 'username' in session.keys():
        if session['username'] == 'admin':
            query = db_init.db_session.query(db_init.Query_History)
            query_count = query.count()
            print ("query count:", query_count)
            results = query.all()
            print ("results:", results)
            return render_template('history.html', results = results, query_count = query_count)
        else:
            query = db_init.Query_History.query.filter(db_init.Query_History.username == session['username'])
            query_count = query.count()
            print ("query count:", query_count)
            results = query.all()
            print ("results:", results)
            return render_template('history.html', results = results, query_count = query_count)
    else:
        return render_template('history.html')

@app.route('/history/query<int:query_num>', methods=['GET'])
def query_history(query_num):
    print ("requesting query number:", query_num)
    #query = db_init.Query_History.query.filter(db_init.Query_History.username == session['username'], db_init.Query_History.query_num == query_num)
    query = db_init.Query_History.query.filter(db_init.Query_History.query_num == query_num)
    #first = query.first()
    #print (first.username, first.query_num)
    results = query.all()
    if results[0].username == session['username']:
        for row in results:
            print (row.username, row.query_num, row.query_text, row.query_results)
    else:
        results = None
    return render_template('query_history.html', results = results)
    
def create_admin_account():
    admin_password_hash =hashlib.sha256((admin_credential['password'] + salt).encode()).hexdigest()
    admin = db_init.User(username=admin_credential['username'], password = admin_password_hash, phone = admin_credential['phone'])
    db_init.db_session.add(admin)
    db_init.db_session.commit()
    #db_init.User.query.all()
    
def check_user_exists(username):
    exists = False
    query = db_init.User.query.filter(db_init.User.username == username).first()
    if query:
        exists = True
    return exists
    
if __name__ == '__main__':
    app.secret_key = SECRET_KEY
    #if not os.path.exists('app.db'):
        
    #db.create_all()
    
    #init_db()
    #db_init.db_init()
    if not check_user_exists('admin'):
        print ('admin does not exist')
        create_admin_account()
    app.run(debug=True, host='0.0.0.0', port="5001")