from flask import Flask, render_template, make_response
from flask import request, redirect, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import bcrypt
import os
import uuid


app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)

client = MongoClient('mongo')
db = client['cse312project']
users_collection = db['users']
tokens_collection = db['tokens']

@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    template = render_template('index.html')
    response = make_response(template)

    return response

@app.route('/recipe')
def recipe():
    template = render_template('recipe.html')
    response = make_response(template)

    return response


client = MongoClient('mongo')
db = client['cse312project']
users_collection = db['users']
tokens_collection = db['tokens']


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(username):
    user = users_collection.find_one({"username": username})
    if user:
        return User(username=user['username'])
    return None

@app.route('/register', methods=['POST'])
def register():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    if username and password:
        print(username)
        print(password)

    confirm_password = data.get('confirm_password')

    
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
   
    if not username or not password or not confirm_password:
        return jsonify({'error': 'All fields are required, please return to the auth page'}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "Username already taken, please return to the auth page and use a different username"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
 
    users_collection.insert_one({"username": username, "password": hashed_password})

    return make_response(redirect('/home'))


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        user_obj = User(username=username)
        login_user(user_obj)

        # Generate and store the token in plain text for matching
        token = str(uuid.uuid4())
        tokens_collection.insert_one({"username": username, "token": token})

        # Set the token as a cookie
        response = make_response(redirect(url_for('home')))
        response.set_cookie('auth_token', token, httponly=True, max_age=3600)
        return response

    return render_template('home_invalid_pass.html', username=None)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    token = request.cookies.get('auth_token')
    if token:
        tokens_collection.delete_one({"token": generate_password_hash(token)})

    logout_user()
    response = make_response(redirect('/'))
    response.delete_cookie('auth_token')
    return response


@app.route('/home', methods=['GET'])
def home():
    token = request.cookies.get('auth_token')
    if token:
        user_token = tokens_collection.find_one({"token": token})
        if user_token:
            username = user_token['username']
            return render_template('home.html', username=username)
    
    # If no valid token is found, redirect to the login page
    return render_template('home.html', username=None)



@app.route('/auth', methods=['GET'])
def auth():
    return render_template('auth.html')

if __name__ == "__main__":
    app.run(debug=True)