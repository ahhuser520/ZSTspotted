from flask import Flask, render_template, redirect, request, abort, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Ustawienie Limiter bez błędów w przekazywaniu key_func
limiter = Limiter(get_remote_address, app=app)
'''@app.before_request
def before_request():
    #if not request.is_secure and app.env != "development":
        #url = request.url.replace("http://", "https://", 1)
        #return redirect(url, code=301)
    pass'''
siteName = 'ZSTspotted'

@app.route('/')
def index():
    return render_template('index.html', siteName=siteName)

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('legal/prywatnosc.html', siteName=siteName)

# Apply limit only to POST requests
@limiter.limit('1 per hour')
@app.route('/sendanonymousmessage', methods=['POST'])
def sendanonymousmessage():
    jsonData = request.get_json()
    if not jsonData or not jsonData.get('message'):  # Check if 'message' key exists
        abort(400)
    response = make_response('', 200)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=400, debug=True)
