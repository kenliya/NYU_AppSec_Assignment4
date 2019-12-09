from app import db
 
 
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(32), unique=True, primary_key=True)
    password = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)

    def __repr__(self):
        return '<User {}>'.format(self.username)
 
 
#class History(db.Model):
#    """"""
#    __tablename__ = "history"
# 
#    id = db.Column(db.Integer, primary_key=True)
#    login_time = db.Column(db.TIMESTAMP)
#    release_date = db.Column(db.String)
#    publisher = db.Column(db.String)
#    media_type = db.Column(db.String)
# 
#    artist_id = db.Column(db.Integer, db.ForeignKey("artists.id"))
#    artist = db.relationship("Artist", backref=db.backref(
#        "albums", order_by=id), lazy=True)