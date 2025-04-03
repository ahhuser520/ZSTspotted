from flask import Flask, render_template, redirect, request, abort, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mysql.connector

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

@app.before_request
def before_request():
    if not request.is_secure and app.env != "development":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

@app.route('/')
def index():
    return render_template('index.html')

@limiter.limit('1 per hour')
@app.route('/sendanonymousmessage')
def sendanonymousmessage():
    jsonData = request.get_json()
    if not jsonData['message']:
        abort(400)
    response = make_response('', 200)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
