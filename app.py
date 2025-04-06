from flask import Flask, render_template, redirect, request, abort, make_response, jsonify, session, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3 as sqlite
import random
from dotenv import load_dotenv
import os
import hashlib
from functools import wraps
app = Flask(__name__)

load_dotenv()

app.secret_key = os.getenv('FLASK_SECRET_KEY')

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
            return redirect(url_for('admin'))  
        return f(*args, **kwargs)
    return decorated_function

# Initialize the database
def init_db():
    con = sqlite.connect('database.db')
    cur = con.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            passkey TEXT NOT NULL
        )
    ''')

    con.commit()

    if not os.path.exists('passkey.txt'):
        random_passkey = ''.join(random.choices('0123456789abcdef', k=32))
        
        hashed_passkey = hashlib.sha256(random_passkey.encode()).hexdigest()

        with open('passkey.txt', 'w') as f:
            f.write(random_passkey)

        cur.execute("INSERT INTO admin (passkey) VALUES (?)", (hashed_passkey,))
        con.commit()

        print(f"Generated new passkey: {random_passkey}")
    else:
        cur.execute("SELECT passkey FROM admin WHERE id = 1")
        admin_row = cur.fetchone()
        if admin_row:
            print(f"Using existing passkey: {admin_row[0]}")
        else:
            print("Error: Admin passkey not found in the database.")
    
    con.close()


def init_db():
    db_exists = os.path.exists('database.db')

    con = sqlite.connect('database.db')
    cur = con.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            passkey TEXT NOT NULL
        )
    ''')

    con.commit()

    if os.path.exists('passkey.txt'):
        with open('passkey.txt', 'r') as f:
            random_passkey = f.read().strip()

        hashed_passkey = hashlib.sha256(random_passkey.encode()).hexdigest()

        if not db_exists:
            cur.execute("INSERT INTO admin (passkey) VALUES (?)", (hashed_passkey,))
            con.commit()
    else:
        random_passkey = ''.join(random.choices('0123456789abcdef', k=32))
        hashed_passkey = hashlib.sha256(random_passkey.encode()).hexdigest()

        with open('passkey.txt', 'w') as f:
            f.write(random_passkey)

        cur.execute("INSERT INTO admin (passkey) VALUES (?)", (hashed_passkey,))
        con.commit()

    con.close()


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
            return jsonify({
                "id": post[0],  
                "timestamp": post[1], 
                "content": post[2]  
            }), 200
        else:
            return jsonify({"error": "Post not found"}), 404

    except sqlite.Error as e:
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
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                content TEXT NOT NULL
            )
        ''')
        db.execute("UPDATE posty SET content = 'Post usuniety' WHERE rowid = ?", (post_id,))
        db.commit()
        db.close()

        return jsonify({"message": "Post successfully removed"}), 200

    except sqlite.Error as e:
        return jsonify({"error": "Internal Server Error"}), 500

# Public routes
@app.route('/')
def index():
    return render_template('index.html', siteName=siteName, footer=g.footer)

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('legal/prywatnosc.html', siteName=siteName, footer=g.footer)

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
    if not jsonData or not jsonData.get('message'):  
        abort(400)

    response = make_response('', 200)
    db = sqlite.connect('database.db')
    db.execute('''
        CREATE TABLE IF NOT EXISTS posty(
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            content TEXT NOT NULL
        )
    ''')
    try:
        db.execute("INSERT INTO posty (content) VALUES (?)", (jsonData.get('message'),))
        db.commit()
        last_row_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        response.set_data(str(last_row_id))
    except sqlite.Error as e:
        response.status_code = 500
        response.set_data(str(e))
    finally:
        db.close()

    return response

@app.route('/posty')
def posty():
    page = request.args.get('page', default=1, type=int)
    postow_na_scroll = 50

    offset = (page - 1) * postow_na_scroll

    db = sqlite.connect('database.db')

    posts = db.execute(
        "SELECT rowid, * FROM posty ORDER BY rowid DESC LIMIT ? OFFSET ?",
        (postow_na_scroll, offset)
    ).fetchall()

    db.close()
    return jsonify([{"id": post[0], "timestamp": post[1], "content": post[2]} for post in posts])

@app.after_request
def add_onion_location_header(response):
    response.headers["Onion-Location"] = "http://7ia7pk5wzcva6izkyqjdjsgnyge724byfbtf5fvegh3wh6bfnqjk25ad.onion"
    return response

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=4000, debug=True)
