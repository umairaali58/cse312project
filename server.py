from tempfile import template

from flask import Flask, render_template, make_response

app = Flask(__name__, template_folder='templates')


@app.route('/')
def index():
    template = render_template('index.html')
    response = make_response(template)

    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response







if __name__ == "__main__":
    app.run(debug=True)