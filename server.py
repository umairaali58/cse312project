import time

from bson import ObjectId
from flask import Flask, render_template, make_response, request, url_for, jsonify, redirect
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_limiter import Limiter
import bcrypt
import os
import uuid
import hashlib
from datetime import datetime
from pymongo import MongoClient
import random
from flask import Flask, request, jsonify, send_file
from bson.objectid import ObjectId
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from PIL import Image
from functools import wraps
import time
from threading import Lock
from datetime import datetime


import requests
import os
import textwrap

app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app)
app.config['SECRET_KEY'] = os.urandom(24)
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# extracts the ip from the headers that were forwarded by nginx
def get_client_ip():
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
competition_collection = db['competitions']

allowed_image_extensions = {'png', 'jpg', 'jpeg'}

competition_locks = {}
active_competitions = {}


@app.route('/turn')
@limiter.limit("10 per 10 seconds")
def turn_page():
    token = request.cookies.get('auth_token')
    if token:
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
        user_token = tokens_collection.find_one({"token": hashed_token})
        if user_token:
            username = user_token['username']
            # Get all users except current user
            all_users = list(users_collection.find(
                {"username": {"$ne": username}}, 
                {"username": 1, "_id": 0}
            ))
            
            # Get all recipes and convert ObjectId to string
            recipes = list(recipeCollection.find())
            for recipe in recipes:
                recipe['_id'] = str(recipe['_id'])  # Convert ObjectId to string
            
            # Get user's competitions and convert ObjectId to string
            competitions = list(competition_collection.find({
                '$or': [
                    {'player1': username},
                    {'player2': username}
                ]
            }))
            for comp in competitions:
                comp['_id'] = str(comp['_id'])
            
            return render_template('turn.html', 
                                username=username,
                                users=all_users,
                                recipes=recipes,
                                competitions=competitions)
    return redirect(url_for('home'))

def convert_mongodb_ids(document):
    """Convert all ObjectId instances in a document to strings."""
    if isinstance(document, dict):
        for key, value in document.items():
            if isinstance(value, ObjectId):
                document[key] = str(value)
            elif isinstance(value, (dict, list)):
                convert_mongodb_ids(value)
    elif isinstance(document, list):
        for item in document:
            convert_mongodb_ids(item)
    return document

# Then use it in your socket handlers
@socketio.on('join_competition')
def handle_join_competition(data):
    competition_id = data.get('competition_id')
    if not competition_id:
        return
    
    join_room(competition_id)
    competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
    if competition:
        competition = convert_mongodb_ids(competition)
        emit('competition_state', competition, room=competition_id)

# @socketio.on('join_competition')
# def handle_join_competition(data):
#     competition_id = data.get('competition_id')
#     if not competition_id:
#         return
    
#     join_room(competition_id)
#     competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
#     if competition:
#         emit('competition_state', competition, room=competition_id)

@socketio.on('start_turn')
def handle_start_turn(data):
    competition_id = data.get('competition_id')
    username = get_username_from_token(request.cookies.get('auth_token'))
    
    if not competition_id or not username:
        return
    
    competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
    if not competition or username not in [competition['player1'], competition['player2']]:
        return
    
    with competition_locks.get(competition_id, Lock()):
        if competition['current_player'] != username:
            return
            
        current_time = time.time()
        competition_collection.update_one(
            {'_id': ObjectId(competition_id)},
            {'$set': {
                'turn_start_time': current_time,
                'turn_active': True
            }}
        )
        
        emit('turn_started', {
            'player': username,
            'start_time': current_time
        }, room=competition_id)
        
        if competition_id not in active_competitions:
            active_competitions[competition_id] = True
            socketio.start_background_task(competition_timer, competition_id)

@socketio.on('end_turn')
def handle_end_turn(data):
    competition_id = data.get('competition_id')
    username = get_username_from_token(request.cookies.get('auth_token'))
    
    if not competition_id or not username:
        return
        
    with competition_locks.get(competition_id, Lock()):
        competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
        if not competition or competition['current_player'] != username:
            return
            
        current_time = time.time()
        elapsed_time = current_time - competition['turn_start_time']
        
        time_field = 'player1_time' if username == competition['player1'] else 'player2_time'
        next_player = competition['player2'] if username == competition['player1'] else competition['player1']
        
        competition_collection.update_one(
            {'_id': ObjectId(competition_id)},
            {'$inc': {time_field: elapsed_time},
             '$set': {
                'current_player': next_player,
                'turn_active': False,
                'last_turn_end': current_time
             }}
        )
        
        updated_competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
        # Convert ObjectId to string
        updated_competition['_id'] = str(updated_competition['_id'])
        if 'recipe_id' in updated_competition:
            updated_competition['recipe_id'] = str(updated_competition['recipe_id'])
            
        emit('turn_ended', {
            'player': username,
            'elapsed_time': elapsed_time,
            'next_player': next_player,
            'player1_total_time': updated_competition['player1_time'],
            'player2_total_time': updated_competition['player2_time']
        }, room=f"competition_{competition_id}")
# @socketio.on('end_turn')
# def handle_end_turn(data):
#     competition_id = data.get('competition_id')
#     username = get_username_from_token(request.cookies.get('auth_token'))
    
#     if not competition_id or not username:
#         return
        
#     with competition_locks.get(competition_id, Lock()):
#         competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
#         if not competition or competition['current_player'] != username:
#             return
            
#         current_time = time.time()
#         elapsed_time = current_time - competition['turn_start_time']
        
#         time_field = 'player1_time' if username == competition['player1'] else 'player2_time'
#         next_player = competition['player2'] if username == competition['player1'] else competition['player1']
        
#         competition_collection.update_one(
#             {'_id': ObjectId(competition_id)},
#             {'$inc': {time_field: elapsed_time},
#              '$set': {
#                 'current_player': next_player,
#                 'turn_active': False,
#                 'last_turn_end': current_time
#              }}
#         )
        
#         updated_competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
#         emit('turn_ended', {
#             'player': username,
#             'elapsed_time': elapsed_time,
#             'next_player': next_player,
#             'player1_total_time': updated_competition['player1_time'],
#             'player2_total_time': updated_competition['player2_time']
#         }, room=competition_id)

def competition_timer(competition_id):
    """Background task to send timer updates every second"""
    while active_competitions.get(competition_id):
        competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
        if not competition or not competition.get('turn_active'):
            continue
            
        current_time = time.time()
        elapsed_time = current_time - competition['turn_start_time']
        
        socketio.emit('timer_update', {
            'elapsed_time': elapsed_time,
            'current_player': competition['current_player']
        }, room=competition_id)
        
        # Check if turn time limit exceeded (5 minutes)
        if elapsed_time > 300:  # 5 minutes in seconds
            handle_end_turn({'competition_id': str(competition['_id'])})
            
        socketio.sleep(1)  # Update every second

# Add these new routes and socket handlers to server.py

@app.route('/competition/<competition_id>')
@limiter.limit("10 per 10 seconds")
def competition_room(competition_id):
    token = request.cookies.get('auth_token')
    print(token)

    if not token:
        return redirect(url_for('home'))
        
    username = get_username_from_token(token)
    if not username:
        return redirect(url_for('home'))
        
    try:
        competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
        if not competition:
            return "Competition not found", 404
            
        # Check if user is part of the competition
        if username not in [competition['player1'], competition['player2']]:
            # Check if they're allowed to spectate (you can add spectator logic here)
            return "Not authorized to view this competition", 403
            
        return render_template(
            'competition_room.html',
            competition=competition,
            username=username,
            is_current_player=username == competition['current_player']
        )
    except Exception as e:
        return str(e), 400

# Add these to your socket event handlers
@socketio.on('join_competition_room')
def handle_join_room(data):
    competition_id = data.get('competition_id')
    username = get_username_from_token(request.cookies.get('auth_token'))
    
    if not competition_id or not username:
        return
    
    room = f"competition_{competition_id}"
    join_room(room)
    
    # Update connected users for this competition
    competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
    if competition:
        connected_users = competition.get('connected_users', [])
        if username not in connected_users:
            competition_collection.update_one(
                {'_id': ObjectId(competition_id)},
                {'$addToSet': {'connected_users': username}}
            )
            
        # Emit updated user list to all users in the room
        emit('user_joined', {
            'username': username,
            'connected_users': connected_users + [username]
        }, room=room)

@socketio.on('leave_competition_room')
def handle_leave_room(data):
    competition_id = data.get('competition_id')
    username = get_username_from_token(request.cookies.get('auth_token'))
    
    if not competition_id or not username:
        return
        
    room = f"competition_{competition_id}"
    leave_room(room)
    
    # Remove user from connected users
    competition_collection.update_one(
        {'_id': ObjectId(competition_id)},
        {'$pull': {'connected_users': username}}
    )
    
    competition = competition_collection.find_one({'_id': ObjectId(competition_id)})
    if competition:
        emit('user_left', {
            'username': username,
            'connected_users': competition.get('connected_users', [])
        }, room=room)

# Modify your create_competition route to redirect to the new page
@app.route('/create_competition', methods=['POST'])
@limiter.limit("10 per 10 seconds")
def create_competition():
    # Remove @login_required and handle auth manually
    token = request.cookies.get('auth_token')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
        
    challenger = get_username_from_token(token)
    if not challenger:
        return jsonify({'error': 'Invalid authentication'}), 401
        
    try:
        opponent = request.form.get('opponent')
        recipe_id = request.form.get('recipe_id')
        
        if not opponent or not recipe_id:
            return jsonify({'error': 'Missing required fields'}), 400
            
        recipe = recipeCollection.find_one({'_id': ObjectId(recipe_id)})
        if not recipe:
            return jsonify({'error': 'Recipe not found'}), 404
            
        competition_id = competition_collection.insert_one({
            'player1': challenger,
            'player2': opponent,
            'recipe_id': recipe_id,
            'recipe_name': recipe['recipe'],
            'current_player': challenger,
            'player1_time': 0,
            'player2_time': 0,
            'turn_active': False,
            'created_at': time.time(),
            'status': 'pending',
            'connected_users': [challenger]
        }).inserted_id
        
        competition_locks[str(competition_id)] = Lock()
        
        return jsonify({
            'competition_id': str(competition_id),
            'redirect_url': f'/competition/{str(competition_id)}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_users', methods=['GET'])
@limiter.limit("10 per 10 seconds")
def get_users():
    # Get current user to exclude from list
    current_user = get_username_from_token(request.cookies.get('auth_token'))
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401
        
    # Get all users except current user
    users = list(users_collection.find(
        {"username": {"$ne": current_user}}, 
        {"username": 1, "_id": 0}
    ))
    
    return jsonify({'users': [user['username'] for user in users]})

def get_username_from_token(token):
    """Helper function to get username from auth token"""
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_doc = tokens_collection.find_one({'token': token_hash})
    return token_doc['username'] if token_doc else None


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
        ip = get_client_ip()
        if is_ip_blocked(ip):
            return jsonify(error="Too Many Requests", message="You have exceeded the allowed number of requests in a short duration. Please try again in 30 seconds."), 429
        return func(*args, **kwargs)

    return decorated_function



@app.errorhandler(429)
# creates a json response for users that exceed the rate
def rate_limit_handler(e):
    ip = get_client_ip()
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


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

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



# @app.route("/testing")
# def testing():
#     x_real_ip = request.headers.get('X-Real-IP', 'N/A')
#     x_forwarded_for = request.headers.get('X-Forwarded-For', 'N/A')
#
#     # Create a dictionary to return as JSON
#     headers_info = {
#         "X-Real-IP": x_real_ip,
#         "X-Forwarded-For": x_forwarded_for
#     }
#
#     # Return the dictionary as a JSON response
#     return jsonify(headers_info)

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




# Dummy recipe collection for demonstration

@app.route('/download', methods=['POST'])
@limiter.limit("16 per 10 seconds")
@check_ip_block
def download_recipe():
    recipe_id = request.form.get('recipe_id')
    recipe = recipeCollection.find_one({"_id": ObjectId(recipe_id)})

    if not recipe:
        return jsonify({"error": "Recipe not found"}), 404

    pdf_buffer = BytesIO()

    # Generate PDF
    pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
    pdf.drawString(100, 750, f"Recipe: {recipe['recipe']}")
    pdf.drawString(100, 730, "Ingredients:")

    y_position = 710

    for ingredient in recipe['ingredients'].split(","):
        pdf.drawString(120, y_position, f"- {ingredient}")
        y_position -= 20

    y_position -= 20

    pdf.drawString(100, y_position, "Recipe By: " + recipe['username'])

    y_position -= 20

    try:
        image_path = recipe['image']

        y_position -= 320

        pdf.drawImage(image_path, 100, y_position, width=320, height=320)
        y_position -= 20

        pdf.drawString(100, y_position, f"Recipe Made using recipehub.me")

    except Exception as e:
        error_message = f"Image not available. {e}"
        wrapped_message = textwrap.wrap(error_message, width=70)

        for line in wrapped_message:
            pdf.drawString(100, y_position, line)
            y_position -= 20

        print(f"Error fetching image: {e}")

    pdf.save()
    pdf_buffer.seek(0)
    return send_file(pdf_buffer, as_attachment=True, download_name=f"{recipe['recipe']}.pdf", mimetype='application/pdf')


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
        recipe_id = random.randint(0, 1000000)

        if username:
            recipeCollection.insert_one({"recipe" : recipe_name, "ingredients": ingredients, "username": username, "likes": (0, []), "image": full_file_path, "id": recipe_id})
            recipe_find = recipeCollection.find_one({"recipe": recipe_name, "ingredients": ingredients, "username": username})
        #If username doesnt exist
        else:
            recipeCollection.insert_one({"recipe" : recipe_name, "ingredients": ingredients, "username": "Guest", "likes": (0, []), "image": full_file_path, "id": recipe_id})
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
        tokens_collection.replace_one({"username": username}, {"username": username, "token": token_hash, "session_start": datetime.now()}, upsert=True)

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

@app.route('/userlist', methods=['GET'])
def get_userlist():
    all_data = tokens_collection.find({})
    current_users = []

    for user in all_data:
        if user.get("username") and user.get("session_start"):
            current_users.append({"username": user.get("username"), "elapsedtime": round((datetime.now() - user.get("session_start")).total_seconds(),2)})
    
    top_users = sorted(current_users, key=lambda x: x["elapsedtime"], reverse=True)[:5]

    return jsonify(top_users), 200


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

if __name__ == '__main__':
    app.run(debug=True)


