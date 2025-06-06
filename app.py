from flask import Flask, render_template, redirect, request, abort, make_response, jsonify, session, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
#import sqlite3 as sqlite
import random
from dotenv import load_dotenv, set_key
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
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

load_dotenv()

db_pass = os.getenv('DB_PASS')
cloudflareSecret = os.getenv('cloudflareSecret')
usernamedb = os.getenv('usernamedb')

connData = {
    'user': usernamedb,
    'password': db_pass,
    'host': '192.168.1.104',
    'port': 3306,
    'database': 'zstspotted',
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_general_ci',
}

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

secret_key = os.getenv('FLASK_SECRET_KEY')

def generate_secret_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))

if not secret_key:
    secret_key = generate_secret_key()
    set_key('.env', 'FLASK_SECRET_KEY', secret_key)

app.secret_key = secret_key
app.config['SECRET_KEY'] = app.secret_key

# Ustawienie Limiter bez błędów w przekazywaniu key_func
limiter = Limiter(get_remote_address, app=app)

siteName = 'ZSTspotted'

# Before request - Adding footer to context
@app.before_request
def redirect_to_https_and_add_footer():
    if request.host == 'zstspotted.pl':
        return redirect('https://www.zstspotted.pl/', code=301)
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
    con = mysql.connector.connect(**connData)
    cur = con.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS support (
            id INT PRIMARY KEY AUTO_INCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            contentMessage TEXT NOT NULL,
            email TEXT DEFAULT ''
        );
    ''')

    # Check if the 'admin' table exists; if not, create it
    cur.execute('''
    CREATE TABLE IF NOT EXISTS admin (
            id INT PRIMARY KEY AUTO_INCREMENT,
            passkey TEXT NOT NULL
        )
    ''')

    cur.execute("""
        CREATE TABLE IF NOT EXISTS komentarze (
            id INT PRIMARY KEY AUTO_INCREMENT,
            postId INT NOT NULL,
            content TEXT NOT NULL,
            creatorUsername TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    cur.execute('''
    CREATE TABLE IF NOT EXISTS tokens (
            id INT PRIMARY KEY AUTO_INCREMENT,
            deviceName VARCHAR(255) DEFAULT NULL,
            token TEXT NOT NULL,
            username TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS posty (
            id INT PRIMARY KEY AUTO_INCREMENT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            content TEXT NOT NULL
        );
    ''')


    con.commit()

    # Check if the passkey exists
    cur.execute("SELECT passkey FROM admin WHERE id = 1")
    admin_row = cur.fetchone()

    if admin_row is None:
        random_passkey = ''.join(random.choices('0123456789abcdef', k=32))

        # Store the generated passkey in the database
        cur.execute("INSERT INTO admin (passkey) VALUES (%s)", (random_passkey,))
        con.commit()

        # Print the passkey to the console for app restart
        print(f"Generated new passkey: {random_passkey}")

    else:
        print(f"Using existing passkey: {admin_row[0]}")

    con.close()

# Admin login and panel route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    con = mysql.connector.connect(**connData)
    cur = con.cursor()

    # If already logged in, show the admin panel
    if session.get('admin_logged_in'):
        listaUzytkownikow = ""
        response = (cur.execute("SELECT id, personalData FROM users"))
        response = cur.fetchall()
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

        db = mysql.connector.connect(**connData)
        cur = db.cursor(dictionary=True)
        post = cur.execute("SELECT id, timestamp, content FROM posty WHERE id = %s", (post_id,))
        post = cur.fetchone()
        db.close()

        if post:
            # Ensure correct mapping from the query result
            return jsonify({
                "id": post['rowid'],  # post[0] is the rowid (post ID)
                "timestamp": post['timestamp'],  # post[1] is the timestamp
                "content": post['content']  # post[2] is the content
            }), 200
        else:
            return jsonify({"error": "Post not found"}), 404

    except Error as e:
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/usunkonto', methods=['POST'])
@requires_admin
def usunkonto():
    try:
        json_data = request.get_json()
        accId = json_data.get('id')

        if not accId:
            return jsonify({"error": "accId not provided"}), 400
        db = mysql.connector.connect(**connData)
        cur = db.cursor()
        accUsername = cur.execute('SELECT username FROM users WHERE id=%s', (accId,))
        accUsername = cur.fetchone()

        accUsername = accUsername[0]
    
        cur.execute("DELETE FROM users WHERE username = %s", (accUsername,))
        cur.execute("DELETE FROM komentarze WHERE creatorUsername = %s", (accUsername,))
        db.commit()
        db.close()

        return jsonify({"message": "Post successfully removed"}), 200

    except Error as e:
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
        
        db = mysql.connector.connect(**connData)
        cursor = db.cursor()
        #db.execute("UPDATE posty SET content = 'Post został usunięty, ze względu na naruszenie regulaminu.' WHERE rowid = ?", (post_id,))
        cursor.execute("DELETE FROM posty WHERE id = %s", (post_id,))
        cursor.execute("DELETE FROM komentarze WHERE postId = %s", (post_id,))
        db.commit()
        db.close()

        return jsonify({"message": "Post successfully removed"}), 200

    except Error as e:
        return jsonify({"error": "Internal Server Error"}), 500
    
@app.route('/admin/wyswietlZgloszenie', methods=['POST'])
@requires_admin
def wyswietlZgloszenia():
    try:
        db = mysql.connector.connect(**connData)
        cur = db.cursor()
        zgloszenia = cur.execute("SELECT * FROM support ORDER BY timestamp DESC")  # Pobierz wszystkie zgłoszenia
        zgloszenia = cur.fetchall()
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

    except Exception as e:
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
    db = mysql.connector.connect(**connData)
    cursor = db.cursor()
    try:
        token = jsonData.get("cf-turnstile-response")
        ip = request.headers.get("CF-Connecting-IP")

        body = {
            "secret": cloudflareSecret,
            "response": token
        }

        print(body)

        response2 = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body  # Przesyłamy dane jako 'data', aby używać 'application/x-www-form-urlencoded'
        )

        result = response2.json()
        print(result)
        if True:#result.get("success"):
            print("antybot success")
            cursor.execute("INSERT INTO posty (content) VALUES (%s)", (jsonData.get('message'),))
            db.commit()
            last_row_id = cursor.execute("SELECT LAST_INSERT_ID()")
            last_row_id = cursor.fetchone()
            print("lastrowid: ", last_row_id)
            cursor.close()
            db.close()
            return jsonify({"SUCCESS": "True"})
        else:
            print("antybot error")
            response3 = {"antyboterror": "antyboterror"}
            return jsonify(response3)
    except Exception as e:
        response.status_code = 500
        print(e)
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
    db = mysql.connector.connect(**connData)
    cur = db.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS support (
            id INT PRIMARY KEY AUTO_INCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            contentMessage TEXT NOT NULL,
            email TEXT DEFAULT ''
        );
    ''')
    try:
        email = jsonData.get('email')
        cur.execute("INSERT INTO support (contentMessage, email) VALUES (%s, %s)", (jsonData.get('contentMessage'), email))
        db.commit()
        cur.execute("SELECT LAST_INSERT_ID()")
        response.set_data(str(cur.fetchone()[0]))
    except Exception as e:
        response.status_code = 500
        print(e)
        response.set_data(str(e))
    finally:
        db.close()
        cur.close()

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

    db = mysql.connector.connect(**connData)
    cursor = db.cursor(dictionary=True)

    # Insert new comment
    user_data = cursor.execute(
        "SELECT username FROM users WHERE username = %s",
        (username,)
    )
    user_data = cursor.fetchone()

    # Check if user exists and data is not empty
    print("dasdsasa")
    if user_data is not None:
        print(postId)
        print(wiadomosc)
        print(username)
        cursor.execute(
            'INSERT INTO komentarze (postId, content, creatorUsername) VALUES (%s, substr(%s, 1, 1000), %s)',
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

    db = mysql.connector.connect(**connData)
    cursor = db.cursor()
    # Check if the comment exists and belongs to the user
    komentarz = cursor.execute(
        'SELECT * FROM komentarze WHERE id = %s AND creatorUsername = %s',
        (komentarzId, username)
    )
    komentarz = cursor.fetchone()

    if komentarz is None:
        # Comment not found or does not belong to the user
        cursor.close()
        abort(404)

    # Delete the comment
    cursor.execute('DELETE FROM komentarze WHERE id = %s', (komentarzId,))
    db.commit()
    db.close()

    return make_response('', 204)

@app.route('/zmienPersonalData', methods=['POST'])
def zmienPersonalData():
    json = request.get_json()
    usernameFromToken = verify_token(request.cookies.get('jwt_token'))
    
    if usernameFromToken != "invalid" and usernameFromToken != "expired":
        db = mysql.connector.connect(**connData)
        newPersonalData = json.get('personalData')
        
        # Debugging: print the values
        print("Received personal data:", newPersonalData)
        print("Username from token:", usernameFromToken)
        
        cursor = db.cursor()
        
        # Execute the query
        cursor.execute('UPDATE users SET personalData = substr(%s, 1, 100) WHERE username=%s', (newPersonalData, usernameFromToken))
        
        # Commit the transaction
        db.commit()
        
        # Check how many rows were affected
        if cursor.rowcount > 0:
            print(f"{cursor.rowcount} rows updated.")
        else:
            print("No rows were updated.")
        
        db.close()
        cursor.close()
        
        return make_response('', 200)
    else:
        abort(401)


@app.route('/posty')
def posty():
    page = request.args.get('page', default=1, type=int)
    postow_na_scroll = 50

    offset = (page - 1) * postow_na_scroll

    db = mysql.connector.connect(**connData)
    #db.row_factory = sqlite.Row  # This allows access to columns by name
    cursor = db.cursor(dictionary=True)
    # Zapytanie do MySQL Connector
    cursor.execute(
        "SELECT * FROM posty ORDER BY timestamp DESC LIMIT %s OFFSET %s",
        (postow_na_scroll, offset)
    )

    posts_raw = cursor.fetchall()

    posts = []
    for post in posts_raw:
        comments_raw = cursor.execute(
            "SELECT * FROM komentarze WHERE postId = %s ORDER BY timestamp DESC",
            (post['id'],)
        )
        comments_raw = cursor.fetchall()

        comments = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            username = comment_dict['creatorUsername']
            
            # domyślnie: "Anonymous"
            display_name = "Anonymous"

            # próbujemy znaleźć dane personalne
            user_data = cursor.execute(
                "SELECT personalData FROM users WHERE username = %s AND personalData IS NOT NULL AND personalData != ''",
                (username,)
            )
            user_data = cursor.fetchone()

            if user_data:
                display_name = user_data['personalData']
            else:
                display_name = "Anonymous"

            # nadpisujemy display name
            comment_dict['personalData'] = display_name
            comments.append(comment_dict)

        posts.append({
            "id": post['id'],
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
        conn = mysql.connector.connect(**connData)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tokens WHERE token=%s", (token,))
        conn.commit()
        conn.close()
    elif id != "":
        token = ""
        conn = mysql.connector.connect(**connData)
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM tokens WHERE id=%s", (id,))
        # Device name is encrypted, unless it was server-generated
        row = cursor.fetchone()
        if row:
            token = row[0]  # Access the token value
        blacklist.add(token)
        with open("blacklist.json", "w") as file:
            json.dump(list(blacklist), file)
        conn = mysql.connector.connect(**connData)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tokens WHERE token=%s", (token,))
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
            db = mysql.connector.connect(**connData)
            cursor = db.cursor()
            cursor.execute("SELECT salt FROM users WHERE username=%s", (username,))
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
    except Error as err:
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
            "secret": cloudflareSecret,
            "response": tokenCloudflare
        }

        print(body)

        response2 = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body  # Przesyłamy dane jako 'data', aby używać 'application/x-www-form-urlencoded'
        )
        result2 = response2.json()
        db = mysql.connector.connect(**connData)
        #print(result2)
        if True:#result2.get("success"):
            if (type(username) == str and type(password) == str and len(username) > 4 and len(password) > 4) and (len(username) <= 256 and len(password) <= 256):
                salt = str(data.get('salt'))
                if salt != "" and len(salt) == 16:
                    cursor = db.cursor()
                    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        username VARCHAR(255) NOT NULL UNIQUE,
                        personalData VARCHAR(100) DEFAULT NULL,
                        password VARCHAR(255) NOT NULL,
                        salt VARCHAR(255) NOT NULL
                    );
                    ''')

                    cursor.execute("SELECT salt FROM users WHERE username=%s", (username,))
                    row = cursor.fetchone()
                    if row:
                        success = {"success": "no", "token": ""}
                        return jsonify(success), 200
                    else:
                        cursor.execute("INSERT INTO users (username, personalData, password, salt) VALUES (%s, substr(%s, 1, 100), %s, %s);", (username, personalData, password, salt))
                        db.commit()
                        cursor.close()
                        token = generate_token(username)
                        success = {"success": "yes", "token": str(token)}
                        return jsonify(success), 201
                else:
                    return make_response('400', 400)
            else:
                return make_response('400', 400)
        else:
            make_response('405', 405)
    except Exception as err:
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
            db = mysql.connector.connect(**connData)
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE username=%s AND password=%s", (username, password))
            rows = cursor.fetchall()

            if len(rows) > 1:
                return make_response('Duplicate records found', 409)

            if len(rows) == 1:
                deviceName = str(data.get('deviceName')) or ""
                if len(deviceName) > 128:
                    return make_response('INVALID DATA', 400)
                token = generate_token(username, deviceName)
                db.commit()
                response = {"row": "1", "token": str(token)}
                return jsonify(response), 200
            else:
                return make_response('INVALID LOGIN DATA', 401)
        except Exception as err:
            print(err)
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
        
        conn = mysql.connector.connect(**connData)
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM tokens WHERE token=%s", (token,))
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
    except Error as err:
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
    db = mysql.connector.connect(**connData)
    cur = db.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS tokens (
            id INT PRIMARY KEY AUTO_INCREMENT,
            deviceName VARCHAR(255) DEFAULT NULL,
            token TEXT NOT NULL,
            username TEXT NOT NULL
        )
    ''')

    cur.execute("INSERT INTO tokens (deviceName, token, username) VALUES(%s, %s, %s)", (deviceName, token, username))
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
                    conn = mysql.connector.connect(**connData)
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT personalData FROM users WHERE username=%s", (isTokenValid,)) #isTokenValid is username
                    row = cursor.fetchone()
                    if row:
                        personalData = row['personalData']
                    if conn:
                        conn.close()
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