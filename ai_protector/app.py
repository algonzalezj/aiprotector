from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, flash
import sqlite3
import jwt
import requests
import re # Necesario para buscar
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
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
app.secret_key = SECRET_KEY  # 🔐 Necesario para flash, sesiones, etc.

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

def notify_telegram(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[Telegram] Token o chat_id no configurado.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    # print(f"[Telegram message] {message}")
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
    except Exception as e:
        print(f"[Telegram ERROR] {e}")

def get_knowledge_base():
    """Carga toda la base de conocimiento desde la tabla de SQLite."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, description, risk FROM knowledge_base")
    # Usa un diccionario para una búsqueda más eficiente por nombre de vulnerabilidad
    knowledge_data = [{"name": row[0], "description": row[1], "risk": row[2]} for row in c.fetchall()]
    conn.close()
    return knowledge_data

def retrieve_context(log_text, knowledge_base):
    """
    Busca en la base de datos de conocimiento las palabras clave relevantes
    y devuelve los fragmentos únicos.
    """
    relevant_chunks = []
    log_text_lower = log_text.lower()
    
    # 🕵️‍♂️ NUEVO: Usamos un conjunto para almacenar nombres de entradas ya encontradas
    found_entries = set()
    
    for entry in knowledge_base:
        # Si esta entrada ya ha sido añadida, la saltamos para evitar duplicados.
        if entry['name'] in found_entries:
            continue
            
        # Crea una lista de palabras clave a partir del nombre de la entrada
        # Ejemplo: 'CVE-2017-0144 (EternalBlue)' -> ['cve', '2017', '0144', 'eternalblue']
        keywords = re.findall(r'\b\w+\b', entry['name'].lower())
        
        # Busca cada palabra clave individualmente en el log
        for keyword in keywords:
            # Filtra palabras clave cortas o no relevantes
            if len(keyword) < 4:
                continue

            # Busca coincidencias de palabras completas
            if re.search(r'\b' + re.escape(keyword) + r'\b', log_text_lower):
                # Añade la información al chunk
                relevant_chunks.append(f"Información adicional sobre '{entry['name']}': {entry['description']}")
                
                # 🕵️‍♂️ NUEVO: Añade el nombre de la entrada al conjunto de encontrados
                found_entries.add(entry['name'])
                
                # Sale del bucle interior para pasar a la siguiente entrada de la base de conocimiento
                break 
    
    return "\n".join(relevant_chunks)

@app.route('/')
def index():
    username = get_user_from_token()
    if not username:
        return redirect(url_for('login'))
    return render_template('index.html', username=username)

# Login de usuarios
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

# Registro de usuarios
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

    c.execute("SELECT id, username, role, preferred_model FROM users")
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
    preferred_model = request.form['preferred_model']
    hashed = generate_password_hash(password)

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, role, preferred_model) VALUES (?, ?, ?, ?)",
                  (username, hashed, role, preferred_model))
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

# Editar modelo usuario
@app.route('/admin/users/update_model/<int:user_id>', methods=['POST'])
def update_model(user_id):
    current_user = get_user_from_token()
    if not current_user:
        return redirect(url_for('login'))

    preferred_model = request.form.get('preferred_model')

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET preferred_model = ? WHERE id = ?", (preferred_model, user_id))
    conn.commit()
    conn.close()

    flash("Modelo actualizado correctamente", "success")
    return redirect(url_for('manage_users'))

# Deslogeo
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    return resp

# Consulta de logs manual
@app.route('/logs/manual', methods=['GET', 'POST'])
def submit_log_manual():
    username = get_user_from_token()
    if not username:
        return redirect(url_for('login'))

    result = None
    log_data = ""
    risk_level = "DESCONOCIDO"

    # Obtener modelo actual del usuario
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT preferred_model FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    model_actual = row[0] if row else OLLAMA_MODEL

    if request.method == 'POST':
        try:
            log_data = request.form['log']
            data = eval(log_data)  # ⚠️ Sustituir por json.loads() en producción
            data['received_at'] = datetime.now(timezone.utc).isoformat()
            data['submitted_by'] = username
            data['server_ip'] = request.remote_addr  # 🔍 IP de quien envía el log (servidor cliente)

            #  Cargar la base de conocimiento y recuperar el contexto
            knowledge_base = get_knowledge_base()
            retrieved_info = retrieve_context(str(data), knowledge_base)

            # Llamada a Ollama con modelo personalizado
            prompt = f"""Evalúa el siguiente log de ciberseguridad:

{str(data)}

---
Información adicional relevante de nuestra base de conocimiento:
{retrieved_info if retrieved_info else 'No se encontró información adicional.'}
---

Responde exclusivamente con una de estas categorías: CRÍTICO, ALTO, MEDIO o BAJO. No añadas explicación. Responde solo con la categoría."""
            
            # 🕵️‍♂️ TRAZAS DE LA LLAMADA A OLLAMA
            print("-" * 50)
            print("[OLLAMA TRACE] Enviando el siguiente prompt al modelo:")
            print(prompt)
            print("-" * 50)

            try:
                ollama_resp = requests.post(
                    OLLAMA_URL,
                    json={
                        "model": model_actual,
                        "prompt": prompt,
                        "stream": False
                    },
                    timeout=30
                )
                ollama_resp.raise_for_status()
                response_json = ollama_resp.json()
                result = response_json.get("response", "").strip()

                # 🕵️‍♂️ TRAZA DE LA RESPUESTA DE OLLAMA
                print("-" * 50)
                print("[OLLAMA TRACE] Respuesta recibida:")
                print(f"Modelo: {response_json.get('model')}")
                print(f"Diagnóstico: {result}")
                print(f"Token de diagnóstico: {response_json.get('total_duration')}") # O cualquier otro token de diagnóstico
                print("-" * 50)

                data["ollama_diagnosis"] = result
                data['model'] = model_actual

                # Extraer la primera palabra (esperada: CRÍTICO, ALTO, MEDIO, BAJO)
                risk_level = result.split()[0].upper()
                if risk_level not in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
                    risk_level = "DESCONOCIDO"
                if risk_level == "CRÍTICO":
                    notify_telegram(f"🚨 *Alerta crítica detectada* 🚨\nIP: {data.get('source_ip')}\nServicio: {data.get('service')}\nModeloIA: {model_actual}\nMensaje: {data.get('message')}")

            except Exception as e:
                result = f"Error llamando a Ollama: {str(e)}"
                data["ollama_diagnosis"] = result
                risk_level = "ERROR"

            # Guardar en Elasticsearch
            requests.post(ELASTIC_URL, json=data)

        except Exception as e:
            result = f"Error procesando el log: {str(e)}"
            risk_level = "ERROR"

    return render_template("submit_log.html", result=result, log_data=log_data, risk_level=risk_level, model_actual=model_actual)

# REST de consulta de logs externa
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

    # 🔍 Obtener modelo preferido del usuario
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT preferred_model FROM users WHERE username=?", (data_decoded.get("username"),))
    row = c.fetchone()
    conn.close()
    ollama_model = row[0] if row else OLLAMA_MODEL

    # 🕵️‍♂️ NUEVO: RAG - Cargar la base de conocimiento y obtener el contexto
    knowledge_base = get_knowledge_base()
    retrieved_info = retrieve_context(log_text, knowledge_base)

    # Preparar el prompt para Ollama
    prompt = f"""Analiza este log de ciberseguridad:

{log_text}

---
Información adicional relevante de nuestra base de conocimiento:
{retrieved_info if retrieved_info else 'No se encontró información adicional.'}
---

Devuélveme únicamente una de estas categorías de riesgo: CRÍTICO, ALTO, MEDIO, BAJO. 
No añadas explicación. Responde solo con la categoría."""
    
    try:
        ollama_resp = requests.post(
            OLLAMA_URL,
            json={
                "model": ollama_model,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )
        ollama_resp.raise_for_status()
        response_text = ollama_resp.json().get("response", "").strip()
        print(f"[Ollama → Análisis]: {response_text}")

        # Extraer criticidad del texto devuelto
        risk_level = response_text.split()[0].upper()
        if risk_level not in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
            risk_level = "DESCONOCIDO"
        if risk_level == "CRÍTICO":
            notify_telegram(f"🚨 *Alerta crítica detectada* 🚨\nIP: {data.get('source_ip')}\nServicio: {data.get('service')}\nModeloIA: {ollama_model}\nMensaje: {data.get('message')}")

    except Exception as e:
        print(f"[ERROR → Ollama]: {e}")
        response_text = "Error al analizar con Ollama"
        risk_level = "ERROR"

    # Añadir metadatos
    data['received_at'] = datetime.now(timezone.utc).isoformat()
    data['submitted_by'] = data_decoded.get("username")
    data['server_ip'] = request.remote_addr  # 🔍 IP de quien envía el log (servidor cliente)
    data['ollama_diagnosis'] = response_text
    data['risk_level'] = risk_level
    data['model'] = ollama_model
    print(f"[TRACE] Log recibido desde servidor IP: {data['server_ip']}")
    try:
        es_resp = requests.post(ELASTIC_URL, json=data)
        es_resp.raise_for_status()
        return jsonify({
            "message": "Log recibido",
            "es_id": es_resp.json()["_id"],
            "diagnosis": response_text,
            "risk_level": risk_level,
            "model": ollama_model
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Inicializar base de datos
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Tabla de usuarios
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user', 'server')),
            preferred_model TEXT NOT NULL DEFAULT 'llama3'
        )
    """)
    
    # Tabla de la base de conocimiento (RAG)
    c.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_base (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            risk TEXT NOT NULL
        )
    """)
    
    # Inserts de datos para la base de conocimiento
    # Se intentan insertar, pero si ya existen, no se produce error gracias al control try-except
    try:
        # Vulnerabilidades comunes y ataques
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('SQL Injection', 'Vulnerabilidad donde un atacante inserta código SQL malicioso para filtrar datos o bypassar la autenticación.', 'ALTO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('Cross-Site Scripting (XSS)', 'Permite a un atacante ejecutar scripts en el navegador de los usuarios para robar información.', 'MEDIO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('Buffer Overflow', 'Ataque que sobreescribe un buffer de memoria, causando un fallo o la ejecución de código arbitrario.', 'CRÍTICO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('Denial of Service (DoS)', 'Un ataque que inunda un servicio o red con tráfico ilegítimo para hacerlo inaccesible.', 'ALTO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('Ransomware', 'Malware que encripta los archivos de la víctima y exige un rescate a cambio de la clave de descifrado.', 'CRÍTICO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('Phishing', 'Intento de engañar a los usuarios para que revelen información sensible, como contraseñas, haciéndose pasar por una entidad legítima.', 'MEDIO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)", 
                  ('Man-in-the-Middle (MitM)', 'Ataque donde el atacante se sitúa entre dos partes que se comunican, interceptando y alterando la comunicación.', 'ALTO'))

        # Ejemplos de CVEs
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)",
                  ('CVE-2021-44228 (Log4j)', 'Una vulnerabilidad de ejecución remota de código (RCE) en la popular biblioteca de Java Apache Log4j.', 'CRÍTICO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)",
                  ('CVE-2014-0160 (Heartbleed)', 'Vulnerabilidad grave en la biblioteca de criptografía OpenSSL que permitía a los atacantes robar información sensible.', 'ALTO'))
        c.execute("INSERT INTO knowledge_base (name, description, risk) VALUES (?, ?, ?)",
                  ('CVE-2017-0144 (EternalBlue)', 'Un exploit de la NSA que permite a un atacante ejecutar código malicioso de forma remota en sistemas Windows. Utilizado por el ransomware WannaCry.', 'CRÍTICO'))
        
        conn.commit()
    except sqlite3.IntegrityError:
        # Se ignora el error si los datos ya existen.
        print("La base de conocimiento ya está poblada.")
        
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
