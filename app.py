from flask import Flask, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO
from flask_socketio import emit
import eventlet
from eventlet import wsgi

app = Flask(__name__)
app.app_context().push()
app.secret_key = '10109238010'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet')

# Define the Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return '<Message %r>' % self.id

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

# Create the database tables
db.create_all()

# Store messages with user information
messages = []

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
# OAuth configuration
oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# OAuth login route
@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

# OAuth authorized route
@app.route('/auth')
def auth():
    token = oauth.google.authorize_access_token()
    session['user'] = token['userinfo']
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

# Fetching user information
@app.route('/')
def index():
    if 'oauth_token' in session:
        user = session['user']
        return render_template('index.html', username=user)
    return redirect(url_for('login'))

#@google.tokengetter
#def get_google_oauth_token():
#    return session.get('oauth_token')

@socketio.on('read-all')
def load_messages():
    if 'user' in session:
        all_messages = Message.query.all()
        messages_data = [{'id': message.id, 'username': message.username, 'message': message.message} for message in all_messages]
        emit('all-messages', messages_data, broadcast=True)

@socketio.on('message')
def handle_message(message):
    if 'user' in session:
        username = session['user']
        messages.append({'username': username, 'message': message})
        new_message = Message(username = username, message = message)
        db.session.add(new_message)
        db.session.commit()
        emit('message', {'username': username, 'message': message}, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, debug=True)

wsgi.server(eventlet.listen(("0.0.0.0", 5000)), app)