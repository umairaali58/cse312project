from flask import Flask, render_template, make_response, request


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
    print(request.form.get('Recipe Name'))

if __name__ == "__main__":
    app.run(debug=True)