from flask_table import Table, Col
 
class User_Table(Table):
    username = Col('username')
    password = Col('password')
    phone = Col('phone')
    
class Login_Table(Table):
    username = Col('username')
    session_cookie = Col('session_cookie')
    login_timestamp = Col('login_timestamp')
    logout_timestamp = Col('logout_timestamp')