from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, flash
import sqlite3
import jwt
import requests
import json
# import re 
from dotenv import load_dotenv
load_dotenv()
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort

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
    """
    Carga la base de conocimiento desde la tabla de SQLite,
    incluyendo las nuevas columnas.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, description, risk, attack_signatures, mitigation_steps FROM knowledge_base")
    knowledge_data = []
    for row in c.fetchall():
        try:
            # 🕵️‍♂️ Decodifica el JSON de las firmas de ataque
            signatures = json.loads(row[3])
        except (json.JSONDecodeError, TypeError):
            signatures = []
        
        knowledge_data.append({
            "name": row[0],
            "description": row[1],
            "risk": row[2],
            "attack_signatures": signatures,
            "mitigation_steps": row[4]
        })
    conn.close()
    return knowledge_data

def retrieve_context(log_message, knowledge_base):
    """
    Busca coincidencias en la base de conocimiento con el mensaje del log,
    utilizando las firmas de ataque.
    """
    print("-" * 50)
    print(">>> Iniciando el proceso de RAG")
    print(f">>> Log de texto a analizar: '{log_message}'")
    
    retrieved_info = []
    log_message_lower = log_message.lower()
    
    # 🔍 Itera sobre cada entrada de la base de conocimiento
    for entry in knowledge_base:
        # 🔍 Comprueba si alguna de las firmas de ataque está en el mensaje del log
        for signature in entry.get("attack_signatures", []):
            # 🕵️‍♂️ Convertimos todo a minúsculas para una búsqueda sin distinción de mayúsculas y minúsculas
            if signature.lower() in log_message_lower:
                # ✍️ Si se encuentra una firma, formatea la información relevante
                context = (
                    f"Vulnerabilidad Detectada: {entry.get('name', 'Desconocida')}\n"
                    f"Descripción: {entry.get('description', 'N/A')}\n"
                    f"Riesgo: {entry.get('risk', 'N/A')}\n"
                    f"Pasos de Mitigación: {entry.get('mitigation_steps', 'N/A')}"
                )
                retrieved_info.append(context)
                # ➡️ Sal del bucle de firmas una vez que se encuentre una coincidencia
                break
    
    print(">>> Depuración de RAG finalizada.")
    print("-" * 50)
    
    # ➡️ Devuelve la información formateada o un mensaje predeterminado
    if retrieved_info:
        return "\n\n".join(retrieved_info)
    else:
        return "No se encontró información adicional relevante en la base de conocimiento para este log."

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_user_from_token()
        if not user:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_user_from_token()
        if not user:
            return redirect(url_for('login'))
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE username=?", (user,))
            row = c.fetchone()
        if not row or row[0] != 'admin':
            return "Acceso denegado", 403
        return f(*args, **kwargs)
    return wrapper

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
            resp.set_cookie(
                'token', token,
                httponly=True,
                secure=False,        # ponlo True en producción (HTTPS)
                samesite='Strict',  # o 'Lax' si necesitas cross-site
                max_age=7200
            )
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
@admin_required
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
@admin_required
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
@admin_required
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
@admin_required
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
    rag_enabled_status = True

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
            rag_enabled_status = 'rag_enabled' in request.form

            # ⚠️ Sustituir por json.loads() en producción
            # He usado json.loads aquí para hacer el código más robusto,
            # pero considera que eval() es peligroso en producción.
            data = json.loads(log_data)
            data['received_at'] = datetime.now(timezone.utc).isoformat()
            data['submitted_by'] = username
            data['server_ip'] = request.remote_addr  # 🔍 IP de quien envía el log (servidor cliente)

            #  Cargar la base de conocimiento y recuperar el contexto
            retrieved_info = ""
            # 🕵️‍♂️ CONDICIONAL RAG: SOLO SE BUSCA EL CONTEXTO SI ESTÁ ACTIVADO
            if rag_enabled_status:
                knowledge_base = get_knowledge_base()
                # 🕵️‍♂️ CORRECCIÓN: Pasar solo el campo 'message' del log a la función RAG
                log_message = data.get('message', '')
                retrieved_info = retrieve_context(log_message, knowledge_base)

            # Llamada a Ollama con modelo personalizado
            prompt = f"""Evalúa el siguiente log de ciberseguridad:

{str(data)}

---
Información adicional relevante de nuestra base de conocimiento:
{retrieved_info if retrieved_info else 'No se encontró información adicional.'}
---

Evalúa el log y la información relevante para emitir un diagnóstico de seguridad.

Si la información adicional te ayuda a llegar a tu conclusión, explica brevemente cómo la usaste en tu razonamiento y si lo usaste o no.

Responde exclusivamente en formato JSON con dos campos:
"risk_level": la categoría de riesgo, que debe ser una de las siguientes: CRÍTICO, ALTO, MEDIO o BAJO.
"reasoning": una breve explicación (máximo 2-3 frases) de por qué se asignó esa categoría y si usaste la información adicional o no.
"""
            
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
                        "stream": False,
                        "format": "json"  # <-- Solicita una respuesta en formato JSON
                    },
                    timeout=30
                )
                ollama_resp.raise_for_status()
                
                # Manejar la respuesta. La respuesta de Ollama puede llegar como una cadena si no hay JSON
                response_text = ollama_resp.json().get("response", "").strip()
                
                # Intentar parsear el JSON
                try:
                    result = json.loads(response_text)
                except json.JSONDecodeError as json_e:
                    # Si falla el parseo, creamos un resultado de error
                    result = {
                        "risk_level": "ERROR",
                        "reasoning": f"Error al decodificar la respuesta JSON de Ollama: {str(json_e)}. Respuesta recibida: '{response_text}'"
                    }
                
                # 🕵️‍♂️ TRAZA DE LA RESPUESTA DE OLLAMA
                print("-" * 50)
                print("[OLLAMA TRACE] Respuesta recibida:")
                # Usar .get() con un valor por defecto para evitar errores si las claves no existen
                print(f"Diagnóstico: {result.get('risk_level', 'No disponible')}")
                print(f"Razonamiento: {result.get('reasoning', 'No disponible')}")
                print(f"Token de diagnóstico: {ollama_resp.json().get('total_duration', 'No disponible')}")
                print("-" * 50)
                
                # Verificar si result es un diccionario antes de intentar acceder a sus claves
                if isinstance(result, dict):
                    data["ollama_diagnosis"] = result.get('risk_level')
                    data["ollama_reasoning"] = result.get('reasoning')
                else:
                    data["ollama_diagnosis"] = "ERROR"
                    data["ollama_reasoning"] = "Respuesta inesperada de Ollama"
                
                data['model'] = model_actual

                # Extraer la primera palabra (esperada: CRÍTICO, ALTO, MEDIO, BAJO)
                risk_level = data.get('ollama_diagnosis', '').upper()
                if risk_level not in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
                    risk_level = "DESCONOCIDO"
                if risk_level == "CRÍTICO":
                    notify_telegram(f"🚨 *Alerta crítica detectada* 🚨\nIP: {data.get('source_ip')}\nServicio: {data.get('service')}\nModeloIA: {model_actual}\nMensaje: {data.get('message')}")

            except Exception as e:
                # Capturar cualquier otro error en la llamada a Ollama
                result = {"risk_level": "ERROR", "reasoning": f"Error llamando a Ollama: {str(e)}"}
                risk_level = "ERROR"

            # Guardar en Elasticsearch
            requests.post(ELASTIC_URL, json=data)

        except Exception as e:
            # Capturar errores en el procesamiento del log
            result = {"risk_level": "ERROR", "reasoning": f"Error procesando el log: {str(e)}"}
            risk_level = "ERROR"
    
    return render_template("submit_log.html", result=result, log_data=log_data, risk_level=risk_level, model_actual=model_actual)


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
    # 🕵️‍♂️ Corregido para usar solo el campo 'message' del log para la búsqueda RAG
    log_message = data.get('message', '')
    retrieved_info = retrieve_context(log_message, knowledge_base)

    # Preparar el prompt para Ollama
    prompt = f"""Evalúa el siguiente log de ciberseguridad:

{str(data)}

---
Información adicional relevante de nuestra base de conocimiento:
{retrieved_info if retrieved_info else 'No se encontró información adicional.'}
---

Evalúa el log y la información relevante para emitir un diagnóstico de seguridad.

Si la información adicional te ayuda a llegar a tu conclusión, explica brevemente cómo la usaste en tu razonamiento y si lo usaste o no.

Responde exclusivamente en formato JSON con dos campos:
"risk_level": la categoría de riesgo, que debe ser una de las siguientes: CRÍTICO, ALTO, MEDIO o BAJO.
"reasoning": una breve explicación (máximo 2-3 frases) de por qué se asignó esa categoría y si usaste la información adicional o no.
"""
    
    try:
        ollama_resp = requests.post(
            OLLAMA_URL,
            json={
                "model": ollama_model,
                "prompt": prompt,
                "stream": False,
                "format": "json"  # <-- Solicita una respuesta en formato JSON
            },
            timeout=60
        )
        ollama_resp.raise_for_status()
        response_text = ollama_resp.json().get("response", "").strip()

        # Manejar la respuesta. La respuesta de Ollama puede llegar como una cadena si no hay JSON
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError as json_e:
            # Si falla el parseo, creamos un resultado de error
            result = {
                "risk_level": "ERROR",
                "reasoning": f"Error al decodificar la respuesta JSON de Ollama: {str(json_e)}. Respuesta recibida: '{response_text}'"
            }
        
        # 🕵️‍♂️ TRAZA DE LA RESPUESTA DE OLLAMA
        print("-" * 50)
        print("[OLLAMA TRACE] Respuesta recibida:")
        # Usar .get() con un valor por defecto para evitar errores si las claves no existen
        print(f"Diagnóstico: {result.get('risk_level', 'No disponible')}")
        print(f"Razonamiento: {result.get('reasoning', 'No disponible')}")
        print(f"Token de diagnóstico: {ollama_resp.json().get('total_duration', 'No disponible')}")
        print("-" * 50)

        # Verificar si result es un diccionario antes de intentar acceder a sus claves
        if isinstance(result, dict):
            data["ollama_diagnosis"] = result.get('risk_level')
            data["ollama_reasoning"] = result.get('reasoning')
        else:
            data["ollama_diagnosis"] = "ERROR"
            data["ollama_reasoning"] = "Respuesta inesperada de Ollama"

        data['model'] = ollama_model    
        
        # Extraer la primera palabra (esperada: CRÍTICO, ALTO, MEDIO, BAJO)
        risk_level = data.get('ollama_diagnosis', '').upper()
        if risk_level not in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
            risk_level = "DESCONOCIDO"
        if risk_level == "CRÍTICO":
            notify_telegram(f"🚨 *Alerta crítica detectada* 🚨\nIP: {data.get('source_ip')}\nServicio: {data.get('service')}\nModeloIA: {ollama_model}\nMensaje: {data.get('message')}")

    except Exception as e:
        print(f"[ERROR → Ollama]: {e}")
        result = {"risk_level": "ERROR", "reasoning": f"Error al analizar con Ollama: {str(e)}"}
        risk_level = "ERROR"

    # Añadir metadatos
    data['received_at'] = datetime.now(timezone.utc).isoformat()
    data['submitted_by'] = data_decoded.get("username")
    data['server_ip'] = request.remote_addr  # 🔍 IP de quien envía el log (servidor cliente)
    data['ollama_diagnosis'] = result.get('risk_level')
    data['ollama_reasoning'] = result.get('reasoning')
    data['risk_level'] = risk_level
    data['model'] = ollama_model
    print(f"[TRACE] Log recibido desde servidor IP: {data['server_ip']}")
    try:
        es_resp = requests.post(ELASTIC_URL, json=data)
        es_resp.raise_for_status()
        return jsonify({
            "message": "Log recibido",
            "es_id": es_resp.json()["_id"],
            "diagnosis": result.get('risk_level'),
            "reasoning": result.get('reasoning'),
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
    
    # ⚠️ Modificación del esquema de la tabla de conocimiento
    # Primero se elimina la tabla para recrearla con las nuevas columnas
    c.execute("DROP TABLE IF EXISTS knowledge_base")

    c.execute("""
        CREATE TABLE knowledge_base (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            risk TEXT NOT NULL,
            attack_signatures TEXT,
            mitigation_steps TEXT
        )
    """)
    
    # 🕵️‍♂️ Inserts de datos para la base de conocimiento (con firmas de ataque)
    try:
        # Vulnerabilidades comunes y ataques
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('SQL Injection', 'Vulnerabilidad donde un atacante inserta código SQL malicioso para filtrar datos o bypassar la autenticación.', 'ALTO', json.dumps(['union select', "' or '1'='1", "1' or '1'='1", "sleep("]), 'Utilizar sentencias preparadas (Prepared Statements) o ORMs para parametrizar las consultas.'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('Cross-Site Scripting (XSS)', 'Permite a un atacante ejecutar scripts en el navegador de los usuarios para robar información.', 'MEDIO', json.dumps(['<script>', 'alert(', 'prompt(', 'confirm(', 'onerror=']), 'Sanear y validar todas las entradas de usuario y utilizar una política de seguridad de contenido (CSP).'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('Buffer Overflow', 'Ataque que sobreescribe un buffer de memoria, causando un fallo o la ejecución de código arbitrario.', 'CRÍTICO', json.dumps(['segmentation fault', 'stack overflow', 'buffer overflow']), 'Utilizar lenguajes de programación con protección de memoria (Rust, Go) o funciones seguras para manejo de cadenas (strlcpy en lugar de strcpy).'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('Denial of Service (DoS)', 'Un ataque que inunda un servicio o red con tráfico ilegítimo para hacerlo inaccesible.', 'ALTO', json.dumps(['Too many requests', 'Connection refused', 'timeout error', 'service unavailable']), 'Implementar limitación de tasa (rate limiting) y sistemas de detección de intrusiones (IDS).'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('Ransomware', 'Malware que encripta los archivos de la víctima y exige un rescate a cambio de la clave de descifrado.', 'CRÍTICO', json.dumps(['.crypt', '.locky', '.cerber']), 'Mantener copias de seguridad de los datos, usar software antivirus y educar a los usuarios.'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('Phishing', 'Intento de engañar a los usuarios para que revelen información sensible, como contraseñas, haciéndose pasar por una entidad legítima.', 'MEDIO', json.dumps(['Suspicious link', 'please click here', 'password reset', 'security alert']), 'Capacitación en seguridad y uso de autenticación multifactor (MFA).'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)", 
                  ('Man-in-the-Middle (MitM)', 'Ataque donde el atacante se sitúa entre dos partes que se comunican, interceptando y alterando la comunicación.', 'ALTO', json.dumps(['http:', 'untrusted certificate', 'certificate error']), 'Utilizar HTTPS con TLS/SSL para toda la comunicación.'))

        # Ejemplos de CVEs
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)",
                  ('CVE-2021-44228 (Log4j)', 'Una vulnerabilidad de ejecución remota de código (RCE) en la popular biblioteca de Java Apache Log4j.', 'CRÍTICO', json.dumps(['jndi:ldap:', 'jndi:rmi:', 'jndi:dns:', 'jndi:iiop:', 'jndi:corba:']), 'Actualizar a la versión 2.17.1 de Apache Log4j2 o posterior. Si no es posible, establecer la propiedad de sistema "log4j2.formatMsgNoLookups" a "true".'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)",
                  ('CVE-2014-0160 (Heartbleed)', 'Vulnerabilidad grave en la biblioteca de criptografía OpenSSL que permitía a los atacantes robar información sensible.', 'ALTO', json.dumps(['heartbeat extension', 'heartbeat request']), 'Actualizar OpenSSL a la versión 1.0.1g o posterior.'))
        c.execute("INSERT INTO knowledge_base (name, description, risk, attack_signatures, mitigation_steps) VALUES (?, ?, ?, ?, ?)",
                  ('CVE-2017-0144 (EternalBlue)', 'Un exploit de la NSA que permite a un atacante ejecutar código malicioso de forma remota en sistemas Windows. Utilizado por el ransomware WannaCry.', 'CRÍTICO', json.dumps(['SMBv1 exploit', 'ETERNALBLUE', 'MS17-010']), 'Deshabilitar SMBv1 y aplicar el parche de seguridad de Microsoft (MS17-010).'))
        
        conn.commit()
    except sqlite3.IntegrityError:
        # Se ignora el error si los datos ya existen.
        print("La base de conocimiento ya está poblada.")
        
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
