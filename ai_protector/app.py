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
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

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

# Ver listado de usuarios
@app.route('/admin/users')
def manage_users():
    current_user = get_user_from_token()
    if not current_user:
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=?", (current_user,))
    if c.fetchone()[0] != 'admin':
        return "Acceso denegado", 403

    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', username=current_user, users=users)

# Crear nuevo usuario
@app.route('/admin/users/add', methods=['POST'])
def add_user():
    current_user = get_user_from_token()
    if not current_user:
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    hashed = generate_password_hash(password)

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, hashed, role))
        conn.commit()
        conn.close()
        flash("Usuario creado correctamente", "success")
    except sqlite3.IntegrityError:
        flash("El usuario ya existe", "danger")

    return redirect(url_for('manage_users'))

# Eliminar usuario
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    current_user = get_user_from_token()
    if not current_user:
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=? AND username!=?", (user_id, current_user))
    conn.commit()
    conn.close()
    flash("Usuario eliminado", "info")

    return redirect(url_for('manage_users'))


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/logs/manual', methods=['GET', 'POST'])
def submit_log_manual():
    username = get_user_from_token()
    if not username:
        return redirect(url_for('login'))

    result = None
    log_data = ""

    if request.method == 'POST':
        try:
            log_data = request.form['log']
            data = eval(log_data)  # ⚠️ Usar json.loads() en producción
            data['received_at'] = datetime.now(timezone.utc).isoformat()
            data['submitted_by'] = username

            # Llamada a Ollama
            prompt = f"""Evalúa el siguiente log de ciberseguridad:

                {str(data)}

                Responde exclusivamente con una de estas categorías: CRÍTICO, ALTO, MEDIO o BAJO."""
            try:
                ollama_resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model": OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False
                    },
                    timeout=30
                )
                ollama_resp.raise_for_status()
                result = ollama_resp.json().get("response", "").strip()
                data["ollama_diagnosis"] = result
            except Exception as e:
                result = f"Error llamando a Ollama: {str(e)}"
                data["ollama_diagnosis"] = result

            # Guardar en Elasticsearch
            requests.post(ELASTIC_URL, json=data)

        except Exception as e:
            result = f"Error procesando el log: {str(e)}"

    return render_template("submit_log.html", result=result, log_data=log_data)


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
    log_text = str(data)  # Convertimos el dict completo a string para analizar

    # Enviar el log a Ollama
    prompt = f"""Analiza este log de ciberseguridad:

        {log_text}

        Devuélveme únicamente una de estas categorías de riesgo: CRÍTICO, ALTO, MEDIO, BAJO. 
        No añadas explicación. Responde solo con la categoría."""
    try:
        ollama_resp = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )
        ollama_resp.raise_for_status()
        response_text = ollama_resp.json().get("response", "").strip()
        print(f"[Ollama → Análisis]: {response_text}")
    except Exception as e:
        print(f"[ERROR → Ollama]: {e}")
        response_text = "Error al analizar con Ollama"

    # Añadir metainformación al log y enviarlo a Elasticsearch
    data['received_at'] = datetime.now(timezone.utc).isoformat()
    data['submitted_by'] = data_decoded.get("username")
    data['ollama_diagnosis'] = response_text  # (opcional) guardar respuesta de Ollama en Elasticsearch

    try:
        es_resp = requests.post(ELASTIC_URL, json=data)
        es_resp.raise_for_status()
        return jsonify({
            "message": "Log recibido",
            "es_id": es_resp.json()["_id"]
        }), 201
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
