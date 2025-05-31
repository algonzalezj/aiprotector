from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
import sqlite3
import jwt
import requests
from dotenv import load_dotenv
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = "data/app.db"
SECRET_KEY = os.getenv('SECRET_KEY')
ELASTIC_URL = os.getenv('ELASTIC_URL')

def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

def create_token(username):
    payload = {
        'username': username,
        'exp': datetime.now(timezone.utc) + timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
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

    # Si es JSON (desde API o curl)
    if request.is_json:
        datos = request.get_json()
        username = datos.get('username')
        password = datos.get('password')

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  # user[2] es la columna 'password'
            token = create_token(username)
            return jsonify({"token": token})
        else:
            return jsonify({"error": "Credenciales inválidas"}), 401

    # Si es POST desde navegador (formulario)
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  # user[2] es la columna 'password'
            token = create_token(username)
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('token', token)
            return resp
        else:
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
            hashed_password = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
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

# envío de logs siendo un usuario
@app.route('/logs', methods=['POST'])
def receive_log():
    username = get_user_from_token()
    if not username:
        return jsonify({"error": "No autorizado"}), 401

    if not request.is_json:
        return jsonify({"error": "Formato no válido"}), 400

    data = request.get_json()
    data['received_at'] = datetime.datetime.now(datetime.UTC).isoformat()
    data['submitted_by'] = username  # opcional: quién lo envió

    try:
        es_resp = requests.post(ELASTIC_URL, json=data)
        es_resp.raise_for_status()
        return jsonify({"message": "Log recibido", "es_id": es_resp.json()["_id"]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ruta válida para el envío desde servidores, agregando token jwt en la cabecera
@app.route('/api/logs', methods=['POST'])
def api_receive_log():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace("Bearer ", "")
    data_decoded = decode_token(token)

    if not data_decoded:
        return jsonify({"error": "Token inválido o expirado"}), 401

    if not request.is_json:
        return jsonify({"error": "Formato no válido"}), 400

    data = request.get_json()
    data['received_at'] = datetime.datetime.utcnow().isoformat()
    data['submitted_by'] = data_decoded.get("username")

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
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user', 'server'))
        )
    """)
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
