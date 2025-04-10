from flask import Flask, render_template, redirect, request, abort, make_response, jsonify, session, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import sqlite3 as sqlite
import random
from dotenv import load_dotenv
import os
from functools import wraps
import secrets
from base64 import b64encode, b64decode
import base64
import string
import time
import jwt
import json
import requests

app = Flask(__name__)

load_dotenv()

from flask import Flask
from flask_cors import CORS

# Configure CORS for a specific domain and allow credentials
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://7ia7pk5wzcva6izkyqjdjsgnyge724byfbtf5fvegh3wh6bfnqjk25ad.onion", "https://zstspotted.pl"],  # Corrected: added a comma
        "supports_credentials": True,  # Allow credentials (cookies, headers, etc.)
        "methods": ["GET", "POST", "OPTIONS"],  # Allowed HTTP methods
        "allow_headers": ["Content-Type", "Authorization"]  # Allowed headers
    }
})

@app.route('/api/data')
def get_data():
    return {"message": "This is some data"}

app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['SECRET_KEY'] = '2dca86e594a1b6890e47e16a6a5978b0f0a584118254f2e7fd086a277ad46958'

# Ustawienie Limiter bez błędów w przekazywaniu key_func
limiter = Limiter(get_remote_address, app=app)

siteName = 'ZSTspotted'

# Before request - Adding footer to context
@app.before_request
def add_footer_to_context():
    g.footer = render_template('modules/footer.html')

# Admin session check decorator
def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin'))  # Redirect to login page if not logged in
        return f(*args, **kwargs)
    return decorated_function

# Initialize the database
def init_db():
    con = sqlite.connect('database.db')
    cur = con.cursor()

    # Check if the 'admin' table exists; if not, create it
    cur.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            passkey TEXT NOT NULL
        )
    ''')

    con.commit()

    # Check if the passkey exists
    cur.execute("SELECT passkey FROM admin WHERE id = 1")
    admin_row = cur.fetchone()

    if admin_row is None:
        random_passkey = ''.join(random.choices('0123456789abcdef', k=32))

        # Store the generated passkey in the database
        cur.execute("INSERT INTO admin (passkey) VALUES (?)", (random_passkey,))
        con.commit()

        # Print the passkey to the console for app restart
        print(f"Generated new passkey: {random_passkey}")

    else:
        print(f"Using existing passkey: {admin_row[0]}")

    con.close()

# Admin login and panel route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    con = sqlite.connect('database.db')
    cur = con.cursor()

    # If already logged in, show the admin panel
    if session.get('admin_logged_in'):
        listaUzytkownikow = ""
        response = cur.execute("SELECT id, personalData FROM users").fetchall()
        for row in response:
            listaUzytkownikow = listaUzytkownikow + str(row[0]) + " " + row[1] + ", "
        return render_template('admin/panel.html', siteName=siteName, listaUzytkownikow=listaUzytkownikow)

    # Handle GET request: Show login form
    if request.method == 'GET':
        return render_template('admin/login.html', siteName=siteName)

    # Handle POST request: Validate passkey
    if request.method == 'POST':
        cur.execute("SELECT passkey FROM admin WHERE id = 1")
        admin_row = cur.fetchone()

        passkey = admin_row[0]
        submitted_passkey = request.form.get('passkey')

        # Check if the submitted passkey matches the stored passkey
        if submitted_passkey and submitted_passkey == passkey:
            # Correct passkey, set session to indicate logged-in status
            session['admin_logged_in'] = True
            return redirect('/admin')  # Use url_for to ensure correct URL routing
        else:
            # Incorrect passkey, render login form with an error message
            return render_template('admin/login.html', incorrect=True, siteName=siteName)

# Admin routes with session check
@app.route('/admin/postbyid', methods=['POST'])
def postbyid():
    try:
        json_data = request.get_json()
        post_id = json_data.get('id')

        if not post_id:
            return jsonify({"error": "ID not provided"}), 400

        db = sqlite.connect('database.db')
        post = db.execute("SELECT rowid, timestamp, content FROM posty WHERE rowid = ?", (post_id,)).fetchone()
        db.close()

        if post:
            # Ensure correct mapping from the query result
            return jsonify({
                "id": post[0],  # post[0] is the rowid (post ID)
                "timestamp": post[1],  # post[1] is the timestamp
                "content": post[2]  # post[2] is the content
            }), 200
        else:
            return jsonify({"error": "Post not found"}), 404

    except sqlite.Error as e:
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/usunkonto', methods=['POST'])
@requires_admin
def usunkonto():
    try:
        json_data = request.get_json()
        accId = json_data.get('id')

        if not accId:
            return jsonify({"error": "accId not provided"}), 400
        db = sqlite.connect('database.db')
        accUsername = db.execute('SELECT username FROM users WHERE id=?', (accId,)).fetchone()

        accUsername = accUsername[0]
    
        db.execute("DELETE FROM users WHERE username = ?", (accUsername,))
        db.execute("DELETE FROM komentarze WHERE creatorUsername = ?", (accUsername,))
        db.commit()
        db.close()

        return jsonify({"message": "Post successfully removed"}), 200

    except sqlite.Error as e:
        print(e)
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/usunpost', methods=['POST'])
@requires_admin
def usunpost():
    try:
        json_data = request.get_json()
        post_id = json_data.get('id')

        if not post_id:
            return jsonify({"error": "ID not provided"}), 400
        
        db = sqlite.connect('database.db')
        db.execute('''
            CREATE TABLE IF NOT EXISTS usuniete_posty(
                timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                content TEXT NOT NULL
            )
        ''')
        #db.execute("UPDATE posty SET content = 'Post został usunięty, ze względu na naruszenie regulaminu.' WHERE rowid = ?", (post_id,))
        db.execute("DELETE FROM posty WHERE rowid = ?", (post_id,))
        db.execute("DELETE FROM komentarze WHERE postId = ?", (post_id,))
        db.commit()
        db.close()

        return jsonify({"message": "Post successfully removed"}), 200

    except sqlite.Error as e:
        return jsonify({"error": "Internal Server Error"}), 500
    
'''@app.route('/api/changePersonalData')
def changePersonalData():
    json = request.get_json()
    username = json.get('username')
    personalData = json.get('personalData')
    usernameFromToken = verify_token(token)
    if usernameFromToken != username or usernameFromToken == "expired" or usernameFromToken == "invalid":
        abort(401)
    else:
        db = sqlite.connect('database.db')
        db.execute("UPDATE users SET personalData = substr(?, 0, 100) WHERE username = ?", (personalData, username,))
        db.commit()
        db.close()'''
    
@app.route('/admin/wyswietlZgloszenie', methods=['POST'])
@requires_admin
def wyswietlZgloszenia():
    try:
        db = sqlite.connect('database.db')
        zgloszenia = db.execute("SELECT * FROM support ORDER BY timestamp DESC").fetchall()  # Pobierz wszystkie zgłoszenia
        db.close()

        if zgloszenia:
            # Tworzymy listę słowników, gdzie każdy słownik odpowiada pojedynczemu zgłoszeniu
            response = []
            for zgloszenie in zgloszenia:
                response.append({
                    "id": zgloszenie[0],
                    "timestamp": zgloszenie[1],
                    "content": zgloszenie[2],
                    "email": zgloszenie[3]
                })
            return jsonify(response), 200  # Zwracamy wszystkie zgłoszenia w formie JSON

        else:
            return jsonify({"error": "Tickets not found"}), 404

    except sqlite.Error as e:
        print(e)
        return jsonify({"error": "Internal Server Error"}), 500

# Public routes
@app.route('/')
def index():
    return render_template('index.html', siteName=siteName, footer=g.footer)

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('legal/prywatnosc.html', siteName=siteName, footer=g.footer)

@app.route('/support')
def support():
    return render_template('support.html', siteName=siteName, footer=g.footer)

@app.route('/post')
def post():
    return render_template('wyslij/index.html', siteName=siteName, footer=g.footer)

@app.route('/tos')
def tos():
    return render_template('legal/tos.html', siteName=siteName, footer=g.footer)

@limiter.limit('1 per hour')
@app.route('/sendanonymousmessage', methods=['POST'])
def sendanonymousmessage():
    jsonData = request.get_json()
    if not jsonData or not jsonData.get('message') or len(jsonData.get('message')) == 0 or len(jsonData.get('message')) > 500:  # Check if 'message' key exists
        abort(400)

    response = make_response('', 200)
    db = sqlite.connect('database.db')
    db.execute('''
        CREATE TABLE IF NOT EXISTS posty(
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            content TEXT NOT NULL
        )
    ''')
    try:
        token = jsonData.get("cf-turnstile-response")
        ip = request.headers.get("CF-Connecting-IP")

        body = {
            "secret": "0x4AAAAAABHTz1E62TH1iexNg8qA570y4Zk",
            "response": token
        }

        print(body)

        response2 = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body  # Przesyłamy dane jako 'data', aby używać 'application/x-www-form-urlencoded'
        )

        result = response2.json()
        print(result)
        if result.get("success"):
            print("antybot success")
            db.execute("INSERT INTO posty (content) VALUES (?)", (jsonData.get('message'),))
            db.commit()
            last_row_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            response.set_data(str(last_row_id))
        else:
            print("antybot error")
            response3 = {"antyboterror": "antyboterror"}
            return jsonify(response3)
    except sqlite.Error as e:
        response.status_code = 500
        response.set_data(str(e))
    finally:
        db.close()

    return response

@limiter.limit('6 per hour')
@app.route('/sendMessageToSupport', methods=['POST'])
def sendMessageToSupport():
    jsonData = request.get_json()
    if not jsonData or not jsonData.get('contentMessage'):  # Check if 'message' key exists
        abort(400)

    if jsonData.get('contentMessage') == "":
        abort(400)

    if jsonData.get('policyPrivacyAggrement') == "false":
        abort(400)
    elif jsonData.get('policyPrivacyAggrement') != "true":
        abort(400)

    response = make_response('', 200)
    db = sqlite.connect('database.db')
    db.execute('''
        CREATE TABLE IF NOT EXISTS support(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            contentMessage TEXT NOT NULL,
            email TEXT DEFAULT ""
        )
    ''')
    try:
        email = jsonData.get('email')
        db.execute("INSERT INTO support (contentMessage, email) VALUES (?, ?)", (jsonData.get('contentMessage'), email))
        db.commit()
        last_row_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        response.set_data(str(last_row_id))
    except sqlite.Error as e:
        response.status_code = 500
        response.set_data(str(e))
    finally:
        db.close()

    return response

@app.route('/stworzKomentarz', methods=['POST'])
def stworzKomentarz():
    json = request.get_json()
    username = json.get('username')
    wiadomosc = json.get('wiadomosc')
    postId = json.get('postId')

    token = request.cookies.get('jwt_token')
    print(token)

    tokenFromUsername = verify_token(token)

    # Token is invalid if it doesn't match username or is expired/invalid
    if tokenFromUsername != username or tokenFromUsername in ("invalid", "expired"):
        abort(400)

    db = sqlite.connect('database.db')
    db.row_factory = sqlite.Row

    # Create komentarze table if it doesn't exist
    db.execute("""
        CREATE TABLE IF NOT EXISTS komentarze (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            postId INTEGER NOT NULL,
            content TEXT NOT NULL,
            creatorUsername TEXT NOT NULL,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime'))
        )
    """)

    # Insert new comment
    user_data = db.execute(
    "SELECT username FROM users WHERE username = ? AND personalData IS NOT NULL AND personalData != ''",
    (username,)
    ).fetchone()

    # Check if user exists and data is not empty
    if user_data is not None:
        db.execute(
            'INSERT INTO komentarze (postId, content, creatorUsername) VALUES (?, ?, ?)',
            (postId, wiadomosc, username)
        )

    db.commit()
    db.close()

    return make_response('', 201)

@app.route('/usunKomentarz', methods=['POST'])
def usunKomentarz():
    json = request.get_json()
    komentarzId = json.get('komentarzId')
    username = json.get('username')

    token = request.cookies.get('jwt_token')
    print(token)

    tokenFromUsername = verify_token(token)

    # Token is invalid if it doesn't match username or is expired/invalid
    if tokenFromUsername != username or tokenFromUsername in ("invalid", "expired"):
        abort(400)

    db = sqlite.connect('database.db')
    db.row_factory = sqlite.Row

    # Check if the comment exists and belongs to the user
    komentarz = db.execute(
        'SELECT * FROM komentarze WHERE id = ? AND creatorUsername = ?',
        (komentarzId, username)
    ).fetchone()

    if komentarz is None:
        # Comment not found or does not belong to the user
        db.close()
        abort(404)

    # Delete the comment
    db.execute('DELETE FROM komentarze WHERE id = ?', (komentarzId,))
    db.commit()
    db.close()

    return make_response('', 204)

@app.route('/zmienPersonalData', methods=['POST'])
def zmienPersonalData():
    json = request.get_json()
    usernameFromToken = verify_token(request.cookies.get('jwt_token'))
    if usernameFromToken != "invalid" and usernameFromToken != "expired":
        db = sqlite.connect('database.db')
        newPersonalData = json.get('personalData')
        db.execute('UPDATE users SET personalData = substr(?, 0, 100) WHERE username=?', (newPersonalData, usernameFromToken))
        db.commit()
        db.close()
        return make_response('', 200)
    else:
        abort(401)

@app.route('/posty')
def posty():
    page = request.args.get('page', default=1, type=int)
    postow_na_scroll = 50

    offset = (page - 1) * postow_na_scroll

    db = sqlite.connect('database.db')
    db.row_factory = sqlite.Row  # This allows access to columns by name

    # Create komentarze table if it doesn't exist
    db.execute("""
        CREATE TABLE IF NOT EXISTS komentarze (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            postId INTEGER NOT NULL,
            content TEXT NOT NULL,
            creatorUsername TEXT NOT NULL,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime'))
        )
    """)


    posts_raw = db.execute(
        "SELECT rowid, * FROM posty ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (postow_na_scroll, offset)
    ).fetchall()

    posts = []
    for post in posts_raw:
        comments_raw = db.execute(
            "SELECT * FROM komentarze WHERE postId = ? ORDER BY timestamp DESC",
            (post['rowid'],)
        ).fetchall()

        comments = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            username = comment_dict['creatorUsername']
            
            # domyślnie: "Anonymous"
            display_name = "Anonymous"

            # próbujemy znaleźć dane personalne
            user_data = db.execute(
                "SELECT personalData FROM users WHERE username = ? AND personalData IS NOT NULL AND personalData != ''",
                (username,)
            ).fetchone()

            if user_data:
                display_name = user_data['personalData']
            else:
                display_name = "Konto zostało usunięte"

            # nadpisujemy display name
            comment_dict['personalData'] = display_name
            comments.append(comment_dict)

        posts.append({
            "id": post['rowid'],
            "timestamp": post['timestamp'],
            "content": post['content'],
            "comments": comments
        })

    db.commit()
    db.close()
    return jsonify(posts)

@app.after_request
def add_onion_location_header(response):
    response.headers["Onion-Location"] = "http://7ia7pk5wzcva6izkyqjdjsgnyge724byfbtf5fvegh3wh6bfnqjk25ad.onion"
    return response

def generate_random_string(length=128):
    characters = string.ascii_letters + string.digits + string.punctuation.replace('"', '').replace("'", '')
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def generate_salt(length=16):
    salt = secrets.token_bytes(length)
    return base64.b64encode(salt).decode('utf-8')

def generate_random_int():
    return random.randint(100, 4500)

# Function to delete token by token or id
def delete_token(token="", id=""):
    if token != "":
        blacklist.add(token)
        with open("blacklist.json", "w") as file:
            json.dump(list(blacklist), file)
        conn = sqlite.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tokens WHERE token=?", (token,))
        conn.commit()
        conn.close()
    elif id != "":
        token = ""
        conn = sqlite.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM tokens WHERE id=?", (id,))
        # Device name is encrypted, unless it was server-generated
        row = cursor.fetchone()
        if row:
            token = row[0]  # Access the token value
        blacklist.add(token)
        with open("blacklist.json", "w") as file:
            json.dump(list(blacklist), file)
        conn = sqlite.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tokens WHERE token=?", (token,))
        conn.commit()
        conn.close()

@app.route('/api/getSalt', methods=['POST'])
@limiter.limit("3 per minute")
def getSalt():
    try:
        salt = ""
        response = {"salt": salt}
        data = request.get_json()
        username = data.get('username')
        if type(username) == str and len(username) >= 64:
            #if type(username)==str and len(username) > 3: #this line is for testing
            db = sqlite.connect('database.db')
            cursor = db.cursor()
            cursor.execute("SELECT salt FROM users WHERE username=?", (username,))
            row = cursor.fetchone()
            if row:
                salt = row[0]  # Accessing the salt value
                response = {"salt": salt}
                return jsonify(response), 200
            else:
                salt = generate_salt(16)  # user has not been found, but due to privacy reasons script has to return some kind of salt anyway
                response = {"salt": salt}
                return jsonify(response), 200
        else:
            print("app.py, getSalt(), InvalidDataError, type of username: "+str(type(username)))
            abort(400)
    except sqlite.Error as err:
        print("app.py, getSalt(), SQLiteDataBaseConnectionError: "+str(err))
        abort(500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


@app.route('/api/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    try:
        row = 0
        token = ""
        tokenCloudflare = ""
        success = {"success": "no"}
        try:
            data = request.get_json()
            tokenCloudflare = data.get("cf-turnstile-response")
            username = str(data.get('username'))
            password = str(data.get('password'))
            personalData = str(data.get('personalData'))
            agreement = str(data.get('policyPrivacyAgr', ""))
            print("agrrement: ", agreement)
            if agreement == "false" or agreement != "true":
                abort(400)
        except KeyError:
            abort(400)
        
        body = {
            "secret": "0x4AAAAAABHTz1E62TH1iexNg8qA570y4Zk",
            "response": tokenCloudflare
        }

        print(body)

        response2 = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body  # Przesyłamy dane jako 'data', aby używać 'application/x-www-form-urlencoded'
        )
        db = sqlite.connect('database.db')
        result2 = response2.json()
        print(result2)
        if result2.get("success"):
            if (type(username) == str and type(password) == str and len(username) > 4 and len(password) > 4) and (len(username) <= 256 and len(password) <= 256):
                salt = str(data.get('salt'))
                if salt != "" and len(salt) == 16:
                    cursor = db.cursor()
                    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        personalData VARCHAR(100) DEFAULT NULL,
                        password TEXT NOT NULL,
                        salt TEXT NOT NULL)''')

                    cursor.execute("SELECT salt FROM users WHERE username=?", (username,))
                    row = cursor.fetchone()
                    if row:
                        success = {"success": "no", "token": ""}
                        return jsonify(success), 200
                    else:
                        cursor.execute("INSERT INTO users (username, personalData, password, salt) VALUES (?, substr(?, 0, 100), ?, ?);", (username, personalData, password, salt))
                        db.commit()
                        token = generate_token(username)
                        success = {"success": "yes", "token": str(token)}
                        return jsonify(success), 201
                else:
                    abort(400)
            else:
                abort(400)
        else:
            try:
                abort(405)
            except:
                abort(405)
    except sqlite.Error as err:
        print('app.py, register(), SQLiteDataBaseConnectionError: ', err)
        abort(500)
    finally:
        if db:
            db.close()

@app.route('/api/login', methods=['POST'])
@limiter.limit("3 per minute")
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON body", "row": "0"}), 400
    username = ""
    password = ""
    try:
        username = str(data.get('username'))
        password = str(data.get('password'))
    except KeyError:
        success = {"success": "dataerror", "token": ""}
        return jsonify(success), 400

    # Validate username and password lengths
    if (type(username) == str) and (type(password) == str) and (len(username) > 4) and (len(password) > 6):
        try:
            token = ""
            response = {"row": "0", "token": str(token)}
            db = sqlite.connect('database.db')
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE username=? AND password=?", (username, password))
            rows = cursor.fetchall()

            if len(rows) > 1:
                abort(409, description="Duplicate records found.")

            if len(rows) == 1:
                deviceName = str(data.get('deviceName')) or ""
                if len(deviceName) > 128:
                    abort(400)
                token = generate_token(username, deviceName)
                db.commit()
                response = {"row": "1", "token": str(token)}
                return jsonify(response), 200
            else:
                abort(401)
        except sqlite.Error as err:
            abort(500)
        finally:
            if 'cursor' in locals() and cursor is not None:
                cursor.close()
            if 'db' in locals() and db is not None:
                db.close()
    else:
        abort(400)

# Function to verify the token
def verify_token(token, max_age=3600*24*30):
    try:
        if token in blacklist:
            print("token is in blacklist")
            return 'invalid'

        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        current_time = int(time.time())
        if current_time - payload['timestamp'] > max_age:
            delete_token(token)
            return 'invalid'
        
        conn = sqlite.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM tokens WHERE token=?", (token,))
        row = cursor.fetchone()
        if not row:
            print("brak tokenu")
            return 'invalid'
        return payload['username']
    except jwt.ExpiredSignatureError:
        return 'invalid'
    except jwt.InvalidTokenError:
        return 'invalid'

# Function to check token validity
def checkToken(token):
    try:
        verified_token = verify_token(token)
        if isinstance(verified_token, str):
            if verified_token == "invalid" or verified_token == "expired":
                response = {"isTokenOkay": "False"}
                return response
            else:
                response = {"isTokenOkay": "True"}
                return response
        else:
            response = "dataError"
            return response
    except sqlite.Error as err:
        response = "SQLiteDataBaseConnectionError"
        return response


def generate_token(username, deviceName = ""):
    payload = {
        'username': username,
        'timestamp': int(time.time())
    }

    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    if deviceName == "" or len(deviceName) > 128:
        deviceName = generate_random_string(132)
    db = sqlite.connect('database.db')
    db.execute('''
        CREATE TABLE IF NOT EXISTS tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deviceName DATETIME DEFAULT CURRENT_TIMESTAMP,
            token TEXT NOT NULL,
            username TEXT NOT NULL
        )
    ''')
    db.execute("INSERT INTO tokens (deviceName, token, username) VALUES(?, ?, ?)", (deviceName, token, username))
    db.commit()
    db.close()
    return token

blacklist = set()

try:
    with open("blacklist.json", "r") as file:
        blacklist = set(json.load(file))
except FileNotFoundError:
    blacklist = set()


@app.route('/account')
def account():
    token = request.cookies.get('jwt_token')
    if token:
        #user has jwt_token cookie, but there is still chance that token is outdated
        response = checkToken(token)
        print(token)
        if response != 'dataError' and response != 'SQLiteDataBaseConnectionError':
            if response['isTokenOkay'] == "True":
                isTokenValid = verify_token(token)
                personalData = ""
                if isTokenValid != "invalid" and isTokenValid != "expired":
                    conn = sqlite.connect('database.db')
                    cursor = conn.cursor()
                    cursor.execute("SELECT personalData FROM users WHERE username=?", (isTokenValid,)) #isTokenValid is username
                    row = cursor.fetchone()
                    if row:
                        personalData = row[0]
                else:
                    abort(403)
                return render_template('login/panel.html', siteName=siteName, footer=g.footer, personalData=personalData)
            else:
                return render_template('login/login.html', siteName=siteName, footer=g.footer)
        else:
            return render_template('login/login.html', siteName=siteName, footer=g.footer)
    else:
        print("User is not logged in")
        return render_template('login/login.html', siteName=siteName, footer=g.footer)

init_db()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3123, debug=True)