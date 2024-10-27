from flask import Flask, render_template, make_response, request
from pymongo import MongoClient
mongoClient = MongoClient("mongo")
dataBase = mongoClient["recipe_database"]
recipeCollection = dataBase["recipeCollection"]

app = Flask(__name__, template_folder='templates')

"will add headers to any response.  Edit it to add more headers as needed "
@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    template = render_template('index.html')
    response = make_response(template)

    return response

@app.route('/home')
def home():
    template = render_template('home.html')
    response = make_response(template)

    return response
@app.route('/recipe')
def recipe():
    template = render_template('recipe.html')
    response = make_response(template)

    return response

@app.route('/post_recipe', methods = ['POST'])
def post_recipe():
    recipe_request = request.form.get("recipe_name")
    ingredient_request = request.form.get("ingredients")

    recipeCollection.insert_one({"recipe" : recipe_request, "ingredients": ingredient_request})
if __name__ == "__main__":
    app.run(debug=True)