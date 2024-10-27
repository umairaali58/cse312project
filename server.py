from flask import Flask, render_template, make_response
from flask import request, redirect, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import bcrypt
import os
import uuid


app = Flask(__name__, template_folder='templates')

client = MongoClient('mongo')
db = client['cse312project']
users_collection = db['users']
tokens_collection = db['tokens']
# app.config['MONGO_URI'] = 'mongodb+srv://farhanmukit0:LnBsfo2rFTk0OSFF@cluster0.otbjk4d.mongodb.net/recipeapp?tls=true&tlsAllowInvalidCertificates=true'


# #PASS
# app.config['SECRET_KEY'] = 'LnBsfo2rFTk0OSFF'
# app.config['UPLOAD_FOLDER'] = 'static/media'

# app.config['MONGO_URI'] = 'mongodb+srv://farhanmukit0:Farhan10451!@cluster0.otbjk4d.mongodb.net/recipeapp?tls=true&tlsAllowInvalidCertificates=true'


# #PASS
# app.config['SECRET_KEY'] = 'LnBsfo2rFTk0OSFF'
# app.config['UPLOAD_FOLDER'] = 'static/media'



# "will add headers to any response.  Edit it to add more headers as needed "
@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    template = render_template('index.html')
    response = make_response(template)

    return response

# @app.route('/home')
# def home():
#     template = render_template('home.html')
#     response = make_response(template)

    return response
@app.route('/recipe')
def recipe():
    template = render_template('recipe.html')
    response = make_response(template)

    return response

# Setup MongoDB


# Setup Flask-Login
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
# mongodb+srv://farhanmukit0:<db_password>@cluster0.otbjk4d.mongodb.net/

@app.route('/register', methods=['POST'])
def register():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # hashpass_db = bcrypt.checkpw(password.encode('utf-8'), hashed_password)


   
    userinfo = users_collection.find_one({"username": username})
    if not username or not password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400
    if userinfo:
        return jsonify({"error": "Username already taken"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if not userinfo:
        # redirect = redirect(url_for('home'))
        users_collection.insert_one({"username": username, "password": hashed_password})
        
        return jsonify({"success": "User registered successfully"}), 200


    
    return jsonify({"error": "An error occurred"}), 400
    # Ensure data is being retrieved correctly
   

    # if users_collection.find_one({"username": username}):
    #     return jsonify({"error": "Username already taken"}), 400

    
    # users_collection.insert_one({"username": username, "password": hashed_password})



@app.route('/home', methods=['GET'])
def home():
    if current_user.is_authenticated:
        return render_template('home.html', username=current_user.username)
    return render_template('home.html', username=None)

@app.route('/auth', methods=['GET'])
def auth():
    return render_template('auth.html')

if __name__ == "__main__":
    app.run(debug=True)