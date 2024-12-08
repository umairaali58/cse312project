import time

from bson import ObjectId
from flask import Flask, render_template, make_response, request, url_for, jsonify, redirect
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_limiter import Limiter
import bcrypt
import os
import uuid
import hashlib
from pymongo import MongoClient
from PIL import Image
from functools import wraps




app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def get_client_ip():
    # Extract the first (original) IP in the X-Forwarded-For header
    forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)
    return forwarded_for.split(',')[0].strip()

# initialize limiter
limiter = Limiter(app=app, key_func=get_client_ip)

client = MongoClient('mongo')
db = client['cse312project']
users_collection = db['users']
tokens_collection = db['tokens']
recipeCollection = db["recipeCollection"]
penalty_collection = db['penalty']

allowed_image_extensions = {'png', 'jpg', 'jpeg'}


# Checks to see if the current ip is blocked for DOS reasons
def is_ip_blocked(ip):
    record = penalty_collection.find_one({"ip": ip})
    # if there is a record, it compares the time
    # if the current time is less than the exprire time, then they are still blocked
    if record:
        currentTime = time.time()
        if currentTime < record['expiry']:
            return True
        # otherwise, it removes them from the database
        else:
            penalty_collection.delete_one({"ip": ip})
    return False


# creates a decorator that checks if the user's ip is blocked before allowing request to go through
# use for
def check_ip_block(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if is_ip_blocked(ip):
            return jsonify(error="Too Many Requests", message="You have exceeded the allowed number of requests in a short duration. Please try again in 30 seconds."), 429
        return func(*args, **kwargs)

    return decorated_function



@app.errorhandler(429)
# creates a json response for users that exceed the rate
def rate_limit_handler(e):
    ip = get_remote_address()
    if not is_ip_blocked(ip):
        block_until = time.time() + 30  # add 30 seconds onto the current time
        # update the database to add them to the block list
        # use update one with upsert in case the ip is already in there for some reason

        penalty_collection.update_one(
            {"ip": ip},
            {"$set": {"expiry": block_until}},
            upsert=True)

    errorResponse = jsonify(error="Too Many Requests", message="You have exceeded the allowed number of requests in a short duration. Please try again in 30 seconds.")
    errorResponse.status_code = 429
    errorResponse.headers["Retry-After"] = 30
    return errorResponse



def allowed_file(file):
    """
    Checks to make sure the file is free of security violations and good to upload.
    Checks the file is an image using pillow, and checks the filename itself


    :param file: A file object that is being checked to see if it is a valid
                 and allowed image type.
    :type file: FileStorage
    :return: A boolean indicating whether the file is a valid and allowed
             image type.
    :rtype: bool
    """
    try:
        # try to open the image with pillow and verify
        image = Image.open(file)
        image.verify()
    except Exception as e:
        # if cant be opened, return false
        return False
    finally:
        # reset file pointer to start
        file.seek(0)
    # Also checks the file extension just in case
    filename = file.filename
    if filename:
        extension = filename.rsplit('.', 1)[-1].lower()
        if extension in allowed_image_extensions:
            return True
    return False


def resize_image_to_320x320(input_image):
    # create a temp image for resizing
    tempImage = input_image + "__temp_image"
    # resize and save the image
    with Image.open(input_image) as image:
        extension = image.format
        image.thumbnail((320, 320))
        image.save(tempImage, format=extension)
    # remove the original image, and rename the temp image to its original name
    os.remove(input_image)
    os.rename(tempImage, input_image)

def generate_file_name_for_storage():
    """
    Generates a unique file name for storage by counting existing files
    in the specified directory and appending the count to the prefix
    'media'. It helps in organizing and accessing files systematically.

    :return: A unique generated file name for storage.
    :rtype: str
    """
    fileCount = len(os.listdir(UPLOAD_FOLDER))
    return "media" + str(fileCount + 1)


# @app.after_request
# def add_header(response):
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     return response

@app.route('/')
@limiter.limit("10 per 10 seconds")
@check_ip_block
def index():
    template = render_template('index.html')
    response = make_response(template)

    return response



@app.route('/recipe')
@limiter.limit("10 per 10 seconds")
@check_ip_block
def recipe():
    global all_recipes
    template = render_template('recipe.html', recipes = recipeCollection.find({}))
    response = make_response(template)

    return response


# Setup MongoDB
# client = MongoClient('mongo')
# db = client['cse312project']
# users_collection = db['users']
# tokens_collection = db['tokens']
# recipeCollection = db["recipeCollection"]
# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username



@app.route("/testing")
def index():
    x_real_ip = request.headers.get('X-Real-IP')
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    print(f"X-Real-IP: {x_real_ip}")
    print(f"X-Forwarded-For: {x_forwarded_for}")
    return "Check logs for IP header information."

@app.route("/like", methods = ['POST'])
@limiter.limit("50 per 10 seconds")
@check_ip_block
def like_post():
    recipId = request.form.get('recipe_id')
    authToken = request.cookies.get('auth_token', None)
    recipe = recipeCollection.find_one({"_id": ObjectId(recipId)})

    if authToken and recipe:
        recipeLikes = recipe["likes"][0]
        recipeLikeList = recipe["likes"][1]
        authTokenHash = hashlib.sha256(authToken.encode()).hexdigest()
        username = tokens_collection.find_one({"token" : authTokenHash})["username"]

        if username not in recipeLikeList:
            recipeLikes += 1
            recipeLikeList.append(username)
            recipeCollection.update_one(
                {"_id": ObjectId(recipId)},
                {"$set": {"likes": (recipeLikes,recipeLikeList)}}
            )

    return redirect(url_for('recipe'))

all_recipes = recipeCollection.find({})



@app.route('/post_recipe', methods = ['POST'])
@limiter.limit("50 per 10 seconds")
@check_ip_block
def post_recipe():
    recipe_name = request.form.get("recipe_name")
    ingredients = request.form.get("ingredients")
    file = request.files.get('recipe_image')

    token =  request.cookies.get('auth_token', None)
    authTokenHash = ""
    username = None
    if token:
        authTokenHash = hashlib.sha256(token.encode()).hexdigest()
        username = tokens_collection.find_one({"token": authTokenHash})["username"]


    if file and allowed_file(file):

        # generate a filename via the helper function and concat it with the extension to get the full file path
        generated_filename =  generate_file_name_for_storage()
        extension = file.filename.rsplit('.', 1)[-1].lower()
        stored_file_name = generated_filename + "." + extension
        full_file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_file_name)
        # save the file
        file.save(full_file_path)
        # change the dimensions of the image for better display
        resize_image_to_320x320(full_file_path)

        if username:
            recipeCollection.insert_one({"recipe" : recipe_name, "ingredients": ingredients, "username": username, "likes": (0, []), "image": full_file_path})
            recipe_find = recipeCollection.find_one({"recipe": recipe_name, "ingredients": ingredients, "username": username})
        #If username doesnt exist
        else:
            recipeCollection.insert_one({"recipe" : recipe_name, "ingredients": ingredients, "username": "Guest", "likes": (0, []), "image": full_file_path})
            recipe_find = recipeCollection.find_one({"recipe": recipe_name, "ingredients": ingredients, "username": "Guest"})

    else:
        return jsonify({"recipe insertion error": "Please provide a properly formatted image: jpeg, jpg, or png"}), 200


    if not recipe_find:
        return jsonify({"recipe insertion error": "good job"}), 200
    
    
    return make_response(redirect(url_for('recipe')))
    #return render_template('recipe.html', username=user, recipes=all_recipes)

    
# Setup Flask-Login

# client = MongoClient('mongo')
# db = client['cse312project']
# users_collection = db['users']
# tokens_collection = db['tokens']


@login_manager.user_loader
def load_user(username):
    user = users_collection.find_one({"username": username})
    if user:
        return User(username=user['username'])
    return None

@app.route('/register', methods=['POST'])
@limiter.limit("12 per 10 seconds")
@check_ip_block
def register():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    confirm_password = data.get('confirm_password')

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
   
    if not username or not password or not confirm_password:
        return jsonify({'error': 'All fields are required, please return to the auth page'}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "Username already taken, please return to the auth page and use a different username"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({"username": username, "password": hashed_password, "friends": []})
    return make_response(redirect('/home'))

@app.route('/login', methods=['POST'])
@limiter.limit("12 per 10 seconds")
@check_ip_block
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        user_obj = User(username=username)
        login_user(user_obj)

        # Generate a plain token and store its hash in the database
        token = str(uuid.uuid4())
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        tokens_collection.replace_one({"username": username}, {"username": username, "token": token_hash}, upsert=True)

        # Set the plain token as a cookie
        response = make_response(redirect('home'))
        response.set_cookie('auth_token', token, httponly=True, max_age=3600)
        return response

    return render_template('home_invalid_pass.html', username=None)


@app.route('/logout', methods=['POST'])
@limiter.limit("12 per 10 seconds")
@check_ip_block
def logout():
    token = request.cookies.get('auth_token')
    if token:
        tokens_collection.delete_one({"token": hashlib.sha256(token.encode()).hexdigest()})

    logout_user()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('auth_token')
    return response



@app.route('/home', methods=['GET'])
@limiter.limit("16 per 10 seconds")
@check_ip_block
def home():
    token = request.cookies.get('auth_token')
    if token: 
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
    # if current_user.is_authenticated:
        # Retrieve the stored hashed token for the current user
        user_token = tokens_collection.find_one({"token": hashed_token})
        if user_token and user_token['token'] == hashlib.sha256(token.encode()).hexdigest():
            return render_template('home.html', username=user_token['username'])
        
    # If no valid token is found, redirect to the login page
    return render_template('home.html', username=None)

@app.route('/messages', methods=['GET'])
@limiter.limit("16 per 10 seconds")
@check_ip_block
def messages():
    token = request.cookies.get('auth_token')
    if token: 
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
    # if current_user.is_authenticated:
        # Retrieve the stored hashed token for the current user
        user_token = tokens_collection.find_one({"token": hashed_token})
        if user_token and user_token['token'] == hashlib.sha256(token.encode()).hexdigest():
            return render_template('messages.html', username=user_token['username'])
        
    # If no valid token is found, redirect to the login page
    return render_template('home.html', username=None)

@app.route('/add_friend', methods=['POST'])
@check_ip_block
@login_required
def add_friend():
    data = request.form
    user = data.get('username')

    if not user:
        return jsonify({"error": "Target username is required"}), 400

    if user == current_user.username:
        return jsonify({"error": "You cannot send a friend request to yourself"}), 400

    target_user = users_collection.find_one({"username": user})
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    if user in current_user.friends:
        return jsonify({"error": "You are already friends"}), 400

    users_collection.update_one(
        {"username": user},
        {"$addToSet": {"friend_requests": current_user.username}}
    )

    return jsonify({"success": f"added new friend"}), 200


@app.route('/auth', methods=['GET'])
@check_ip_block
def auth():
    return render_template('auth.html')

if __name__ == "__main__":
    app.run(debug=True)