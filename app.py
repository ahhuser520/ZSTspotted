from flask import Flask, render_template, redirect, request, abort, make_response, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3 as sqlite

app = Flask(__name__)

# Ustawienie Limiter bez błędów w przekazywaniu key_func
limiter = Limiter(get_remote_address, app=app)

siteName = 'ZSTspotted'

# Przed każdym zapytaniem będziemy dodawać stopkę do kontekstu
@app.before_request
def add_footer_to_context():
    g.footer = render_template('modules/footer.html')  # Ładujemy footer.html do zmiennej globalnej
    '''if not request.is_secure:# and app.env != "development":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)'''

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

# Apply limit only to POST requests
@limiter.limit('1 per hour')
@app.route('/sendanonymousmessage', methods=['POST'])
def sendanonymousmessage():
    jsonData = request.get_json()
    if not jsonData or not jsonData.get('message'):  # Check if 'message' key exists
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

    # Wylicz offset wzgledem na obecna strone
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
    app.run(host='0.0.0.0', port=4000, debug=True)
