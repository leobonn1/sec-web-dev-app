from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from msal import ConfidentialClientApplication, SerializableTokenCache
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'example.db'

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
SECRET_ID = os.environ.get("SECRET_ID")
AUTHORITY = 'https://login.microsoftonline.com/common'
REDIRECT_PATH = '/getAToken'
ENDPOINT = 'https://graph.microsoft.com/User.Read'
SCOPE = ['User.Read']

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            task TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    # Inserir um usuário administrador padrão
    admin_username = os.environ.get(ADMIN_USERNAME)
    admin_password_clear = os.environ.get(ADMIN_PASSWORD_CLEAR)
    admin_password = generate_password_hash(admin_password_clear)  
    admin_role = 'admin'
    c.execute('SELECT * FROM users WHERE username = ?', (admin_username,))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                  (admin_username, admin_password, admin_role))
    conn.commit()
    conn.close()

# Função para obter o banco de dados
def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):  # Verificando hash da senha
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            #mfa com MS Authenticator
            auth_url = _build_auth_url(scopes=SCOPE)
            return redirect(auth_url)
            #return redirect(url_for('index'))
        return 'Login Failed'
    return render_template('login.html')

# Página de logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Página inicial
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM tasks WHERE user_id = ?', (session['user_id'],))
    tasks = c.fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)

# Página para adicionar tarefas
@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        task = request.form['task']
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO tasks (user_id, task) VALUES (?, ?)', (session['user_id'], task))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('add.html')

# Página de gerenciamento de usuários (somente para administradores)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  # Usando hashing seguro
        role = request.form['role']
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))
        conn.commit()
    c.execute('SELECT * FROM users')
    users = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

#Página de redirect após mfa
@app.route(REDIRECT_PATH)
def authorized():
    print(request)
    if request.args.get('error'):
        return request.args.get('error')
    if 'code' in request.args:
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=SCOPE,
            redirect_uri=url_for('authorized', _external=True, _scheme='https'))
        print(result)
        if 'access_token' in result:
            session['user'] = result.get('id_token_claims')
            print(session['user'])
            session['preferred_username'] = result.get('id_token_claims', {}).get('preferred_username')
            print(session['preferred_username'])
            _save_cache(cache)
    return redirect(url_for('index'))

def _build_msal_app(cache=None):
    return ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY,
        client_credential=CLIENT_SECRET, token_cache=cache)

def _build_auth_url(scopes=None):
    return _build_msal_app().get_authorization_request_url(
        scopes or [],
        redirect_uri=url_for('authorized', _external=True, _scheme='https'))

def _load_cache():
    cache = SerializableTokenCache()
    if session.get('token_cache'):
        cache.deserialize(session['token_cache'])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session['token_cache'] = cache.serialize()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
