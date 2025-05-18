from flask import Flask, render_template, request, redirect, url_for, make_response
import sqlite3
import jwt
import datetime
import requests
from flask import jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
DATABASE = "data/app.db"
ELASTIC_URL = "http://localhost:9200/logs/_doc"

def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

def create_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return None

def get_user_from_token():
    token = request.cookies.get('token')
    if not token:
        return None
    data = decode_token(token)
    return data.get('username') if data else None

@app.route('/')
def index():
    username = get_user_from_token()
    if not username:
        return redirect(url_for('login'))
    return render_template('index.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            token = create_token(username)
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('token', token)
            return resp
        error = "Credenciales incorrectas"
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "El usuario ya existe"
        except Exception as e:
            error = f"Error inesperado: {str(e)}"
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/logs', methods=['POST'])
def receive_log():
    if not request.is_json:
        return jsonify({"error": "Formato no válido"}), 400

    data = request.get_json()

    # Opcional: añade timestamp aquí si no viene en la data
    from datetime import datetime
    data['received_at'] = datetime.utcnow().isoformat()

    # Enviar a Elasticsearch
    try:
        es_resp = requests.post(ELASTIC_URL, json=data)
        es_resp.raise_for_status()
        return jsonify({"message": "Log recibido", "es_id": es_resp.json()["_id"]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def init_db():
    conn = sqlite3.connect("data/app.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
