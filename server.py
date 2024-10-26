from flask import Flask, render_template, make_response

app = Flask(__name__, template_folder='templates')

"will add headers to any response.  Edit it to add more headers as needed "
@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    template = render_template('index.html')
    return render_template('index.html')


@app.route('/home')
def home():
    template = render_template('home.html')
    return render_template(template)







if __name__ == "__main__":
    app.run(debug=True)