"""Teste para Casais — backend FastAPI/SQLite, sessões seguras e admin separado."""
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import ssl
import tempfile
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from email.message import EmailMessage
from typing import Literal, Optional

from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel, Field, StrictInt, field_validator
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).resolve().parent
STATIC = ROOT
DB_PATH = Path(os.getenv('DB_PATH', str(ROOT / 'data' / 'casais.sqlite3')))
SECRET_KEY = os.getenv('SESSION_SECRET') or secrets.token_urlsafe(48)
IS_PRODUCTION = os.getenv('APP_ENV', '').lower() == 'production'
if IS_PRODUCTION and not os.getenv('SESSION_SECRET'):
    raise RuntimeError('Defina SESSION_SECRET antes de executar em produção.')

app = FastAPI(title='Curso de Casais Aliança', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY,
                   session_cookie='casais_session', max_age=604800,
                   same_site='lax', https_only=IS_PRODUCTION)
# Os arquivos de mídia são versionados na raiz do projeto.
# Exponha somente os arquivos públicos, nunca a raiz inteira.
PUBLIC_ASSETS = {
    'casal-carinho.webp', 'casal-conversa.webp', 'familia-penha.png',
    'icon-192.png', 'icon-512.png', 'icon.svg',
    'logo-alianca-original.png', 'familia-penha-escuro.png', 'alianca-home.webp', 'alianca-curso.webp', 'alianca-testes.webp',
}

@app.get('/assets/{filename}')
def public_asset(filename: str):
    if filename not in PUBLIC_ASSETS:
        raise HTTPException(404, 'Arquivo não encontrado.')
    path = ROOT / filename
    if not path.is_file():
        raise HTTPException(404, 'Arquivo não encontrado.')
    return FileResponse(path)

@contextmanager
def database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys = ON')
    con.execute('PRAGMA busy_timeout = 10000')
    try:
        yield con
        con.commit()
    finally:
        con.close()

def init_db():
    with database() as con:
        con.execute('PRAGMA journal_mode = WAL')
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            gender TEXT NOT NULL CHECK(gender IN ('M','F')),
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
            session_version INTEGER NOT NULL DEFAULT 0,
            accepted_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS test_answers (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            test_code TEXT NOT NULL CHECK(test_code IN ('TI','LA')),
            answers TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, test_code)
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_attempts_key_time ON login_attempts(key, attempted_at);
        CREATE TABLE IF NOT EXISTS account_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose TEXT NOT NULL CHECK(purpose IN ('verify', 'reset')),
            email TEXT NOT NULL,
            session_version INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lesson_answers (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            lesson_number INTEGER NOT NULL CHECK(lesson_number BETWEEN 1 AND 12),
            question_id INTEGER NOT NULL,
            answer TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, lesson_number, question_id)
        );
        ''')
        columns = {row['name'] for row in con.execute('PRAGMA table_info(users)')}
        if 'email' not in columns:
            con.execute('ALTER TABLE users ADD COLUMN email TEXT')
        if 'email_verified' not in columns:
            con.execute('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0')
        con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL')


# --- Mudança de endereço (temporário) ---------------------------------------------------
# No site NOVO: com MIGRATE_FROM e MIGRATION_TOKEN definidos e sem banco no disco, baixa o
# banco do site antigo antes de iniciar. Se falhar, o app não sobe (evita abrir com banco vazio).
def import_db_from_old_site():
    source, token = os.getenv('MIGRATE_FROM', '').rstrip('/'), os.getenv('MIGRATION_TOKEN', '')
    if not source or len(token) < 32:
        return
    if DB_PATH.exists():
        print(f'[migração] banco já existe em {DB_PATH}; nada a importar.', flush=True)
        return
    import urllib.request
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = DB_PATH.with_suffix('.importando')
    req = urllib.request.Request(source + '/api/internal/db-backup', headers={'X-Migration-Token': token})
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, 'wb') as out:
        while chunk := resp.read(1 << 16):
            out.write(chunk)
    con = sqlite3.connect(tmp)
    try:
        if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Banco importado está corrompido.')
        users = con.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    finally:
        con.close()
    tmp.replace(DB_PATH)
    print(f'[migração] banco importado de {source}: {users} cadastros.', flush=True)

import_db_from_old_site()
init_db()

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def phone_normalize(value: str):
    value = re.sub(r'\D', '', value or '')
    if value.startswith('55') and len(value) == 13:
        value = value[2:]
    if not re.fullmatch(r'[1-9][0-9]9[0-9]{8}', value):
        raise ValueError('Informe um celular brasileiro com DDD: (11) 99999-9999.')
    return value

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
    return 'pbkdf2_sha256$600000$' + salt.hex() + '$' + digest.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        method, iterations, salt, value = encoded.split('$')
        if method != 'pbkdf2_sha256' or int(iterations) < 100000:
            return False
        check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(check, bytes.fromhex(value))
    except (ValueError, TypeError, OverflowError):
        return False

def normalize_email(value: str):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}", value):
        raise ValueError('Informe um e-mail válido.')
    return value

class EmailAddress(BaseModel):
    email: str = Field(max_length=254)
    @field_validator('email')
    @classmethod
    def valid_email(cls, value):
        return normalize_email(value)

class Register(EmailAddress):
    name: str = Field(min_length=5, max_length=100)
    phone: str = Field(max_length=40)
    gender: Literal['M', 'F']
    password: str = Field(min_length=8, max_length=128)
    consent: bool
    @field_validator('name')
    @classmethod
    def normal_name(cls, value):
        s = ' '.join(value.split())
        if len(s.split()) < 2:
            raise ValueError('Informe seu nome completo.')
        return s

class Login(BaseModel):
    phone: str
    password: str

class Answers(BaseModel):
    answers: list[Optional[StrictInt]]

class ProfileUpdate(BaseModel):
    name: str = Field(min_length=5, max_length=100)
    @field_validator('name')
    @classmethod
    def normal_name(cls, value):
        s = ' '.join(value.split())
        if len(s.split()) < 2:
            raise ValueError('Informe seu nome completo.')
        return s

class PasswordUpdate(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

class AdminPasswordReset(BaseModel):
    admin_password: str = Field(max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

class DeleteAccount(BaseModel):
    password: str

class ProfileEmail(EmailAddress):
    password: str = Field(max_length=128)

class AccountToken(BaseModel):
    token: str = Field(min_length=40, max_length=128)

class ResetPassword(AccountToken):
    new_password: str = Field(min_length=8, max_length=128)


def safe_user(u):
    return {k: u[k] for k in ('id', 'name', 'phone', 'gender', 'role', 'created_at', 'email', 'email_verified')}

def current_user(request: Request):
    uid = request.session.get('uid')
    if not isinstance(uid, int):
        raise HTTPException(401, 'Faça login para continuar.')
    with database() as con:
        user = con.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not user or request.session.get('sver') != user['session_version']:
        request.session.clear()
        raise HTTPException(401, 'Sua sessão expirou. Entre novamente.')
    return user

def admin_user(u=Depends(current_user)):
    if u['role'] != 'admin':
        raise HTTPException(403, 'Acesso administrativo restrito.')
    return u

def csrf_protect(request: Request):
    token = request.headers.get('x-csrf-token', '')
    expected = request.session.get('csrf', '')
    if not expected or not hmac.compare_digest(token, expected):
        raise HTTPException(403, 'Token de segurança inválido. Atualize a página.')

def throttle(key: str, max_attempts=8, seconds=900):
    t = int(time.time())
    with database() as con:
        con.execute('DELETE FROM login_attempts WHERE attempted_at < ?', (t - seconds,))
        n = con.execute('SELECT COUNT(*) FROM login_attempts WHERE key=? AND attempted_at>=?',(key, t-seconds)).fetchone()[0]
        if n >= max_attempts:
            raise HTTPException(429, 'Muitas tentativas. Tente novamente em 15 minutos.')
        con.execute('INSERT INTO login_attempts (key, attempted_at) VALUES(?,?)', (key, t))

def sign_in(request, user):
    token = request.session.get('csrf') or secrets.token_urlsafe(24)
    request.session.clear()
    request.session['uid'] = user['id']
    request.session['sver'] = user['session_version']
    request.session['csrf'] = token

def email_delivery_configured():
    required = ('SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM', 'PUBLIC_BASE_URL')
    return all(os.getenv(key) for key in required) and os.getenv('PUBLIC_BASE_URL', '').startswith('https://')

def require_email_delivery():
    if not email_delivery_configured():
        raise HTTPException(503, 'O envio de e-mail ainda não está disponível. Fale com o administrador pelo link no rodapé.')

def issue_account_email(user_id: int, purpose: str):
    # Executado em segundo plano: o pedido público não revela se a conta existe.
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with database() as con:
        user = con.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if not user or not user['email'] or (purpose == 'reset' and not user['email_verified']):
            return
        con.execute('DELETE FROM account_tokens WHERE expires_at < ? OR (user_id=? AND purpose=?)',
                    (int(time.time()), user_id, purpose))
        con.execute('INSERT INTO account_tokens VALUES(?,?,?,?,?,?)',
                    (digest, user_id, purpose, user['email'], user['session_version'],
                     int(time.time()) + (1800 if purpose == 'reset' else 86400)))
    fragment = 'redefinir-senha' if purpose == 'reset' else 'confirmar-email'
    link = os.environ['PUBLIC_BASE_URL'].rstrip('/') + '/#' + fragment + '=' + token
    message = EmailMessage()
    message['From'] = os.environ['SMTP_FROM']
    message['To'] = user['email']
    message['Subject'] = 'Redefinir sua senha · Curso de Casais Aliança' if purpose == 'reset' else 'Confirme seu e-mail · Curso de Casais Aliança'
    action = 'escolher uma nova senha' if purpose == 'reset' else 'confirmar seu e-mail para recuperar sua conta'
    validity = '30 minutos' if purpose == 'reset' else '24 horas'
    message.set_content(f'Olá!\n\nAcesse o link para {action}:\n{link}\n\nO link vale por {validity} e só pode ser usado uma vez.\nSe você não fez essa solicitação, ignore esta mensagem.\n\nCurso de Casais Aliança · Família Penha')
    try:
        use_ssl = os.getenv('SMTP_SSL', '').lower() == 'true'
        client = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        kwargs = {'timeout': 20}
        if use_ssl:
            kwargs['context'] = ssl.create_default_context()
        with client(os.environ['SMTP_HOST'], int(os.getenv('SMTP_PORT', '465' if use_ssl else '587')), **kwargs) as smtp:
            if not use_ssl:
                smtp.starttls(context=ssl.create_default_context())
            smtp.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
            smtp.send_message(message)
    except Exception:
        # Não registre destinatários, credenciais ou links de recuperação.
        import logging
        logging.getLogger(__name__).error('Falha ao enviar e-mail de acesso. Verifique a configuração SMTP no Render.')
        with database() as con:
            con.execute('DELETE FROM account_tokens WHERE token_hash=?', (digest,))

def consume_account_token(data, purpose: str):
    digest = hashlib.sha256(data.token.encode()).hexdigest()
    with database() as con:
        con.execute('BEGIN IMMEDIATE')
        rec = con.execute('''SELECT t.*, u.email current_email, u.session_version current_version,
                             u.email_verified FROM account_tokens t JOIN users u ON u.id=t.user_id
                             WHERE t.token_hash=? AND t.purpose=?''', (digest, purpose)).fetchone()
        if (not rec or rec['expires_at'] <= int(time.time()) or rec['email'] != rec['current_email']
                or rec['session_version'] != rec['current_version']
                or (purpose == 'reset' and not rec['email_verified'])):
            raise HTTPException(400, 'Link inválido ou expirado. Solicite um novo link.')
        if purpose == 'reset':
            con.execute('UPDATE users SET password_hash=?, session_version=session_version+1 WHERE id=?',
                        (hash_password(data.new_password), rec['user_id']))
            con.execute('DELETE FROM account_tokens WHERE user_id=?', (rec['user_id'],))
        else:
            con.execute('UPDATE users SET email_verified=1 WHERE id=?', (rec['user_id'],))
            con.execute('DELETE FROM account_tokens WHERE token_hash=?', (digest,))

@app.post('/api/password/forgot')
def forgot_password(data: EmailAddress, request: Request, background: BackgroundTasks, _: None=Depends(csrf_protect)):
    require_email_delivery()
    throttle('forgot-ip:' + (request.client.host if request.client else 'unknown'), max_attempts=20)
    throttle('forgot-email:' + hashlib.sha256(data.email.encode()).hexdigest(), max_attempts=3)
    with database() as con:
        user = con.execute('SELECT id FROM users WHERE email=? AND email_verified=1', (data.email,)).fetchone()
    if user:
        background.add_task(issue_account_email, user['id'], 'reset')
    return {'message': 'Se este e-mail estiver cadastrado e confirmado, você receberá um link para criar uma nova senha. Confira também o spam.'}

@app.post('/api/password/reset')
def reset_password(data: ResetPassword, request: Request, _: None=Depends(csrf_protect)):
    throttle('reset-ip:' + (request.client.host if request.client else 'unknown'), max_attempts=20)
    consume_account_token(data, 'reset')
    request.session.clear()
    return {'ok': True}

@app.post('/api/email/verify')
def verify_email(data: AccountToken, _: None=Depends(csrf_protect)):
    consume_account_token(data, 'verify')
    return {'ok': True}

@app.post('/api/profile/email')
def profile_email(data: ProfileEmail, background: BackgroundTasks, user=Depends(current_user), _: None=Depends(csrf_protect)):
    require_email_delivery()
    throttle('profile-email:' + str(user['id']), max_attempts=3)
    if not verify_password(data.password, user['password_hash']):
        raise HTTPException(400, 'Senha atual incorreta.')
    with database() as con:
        # Um e-mail só passa a ser utilizável na recuperação após sua confirmação.
        if data.email != user['email']:
            try:
                con.execute('UPDATE users SET email=?, email_verified=0 WHERE id=?', (data.email, user['id']))
            except sqlite3.IntegrityError:
                raise HTTPException(409, 'Este e-mail não está disponível. Use outro ou fale com o administrador.')
            con.execute('DELETE FROM account_tokens WHERE user_id=?', (user['id'],))
    background.add_task(issue_account_email, user['id'], 'verify')
    return {'ok': True, 'message': 'Enviamos um link de confirmação para seu e-mail. Confira também o spam.'}

@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    if request.url.path.startswith('/api/') or request.url.path in ('/', '/admin'):
        response.headers['Cache-Control'] = 'no-store'
    return response

# No site ANTIGO: REDIRECT_TO manda todos os acessos para o novo endereço, mantendo o caminho
# (assim o QR Code antigo continua funcionando). /health e o backup da migração continuam aqui.
REDIRECT_TO = os.getenv('REDIRECT_TO', '').rstrip('/')

@app.middleware('http')
async def redirect_to_new_site(request, call_next):
    path = request.url.path
    if REDIRECT_TO and path not in ('/health', '/api/internal/db-backup'):
        target = REDIRECT_TO + path + (('?' + request.url.query) if request.url.query else '')
        return RedirectResponse(target, status_code=301 if request.method in ('GET', 'HEAD') else 308)
    return await call_next(request)

# CANONICAL_HOST (ex.: casais.familiapenha.com.br) é o endereço oficial do app.
# Acessos por outros endereços (o .onrender.com) vão para ele, mantendo o caminho.
# Enquanto o site da igreja não existe, www.familiapenha.com.br/appcasais também
# leva ao app (redirecionamento temporário, para o site futuro poder assumir o www).
CANONICAL_HOST = os.getenv('CANONICAL_HOST', '').strip().lower()
SHORTCUT_PATH = '/appcasais'

@app.middleware('http')
async def redirect_to_canonical_host(request, call_next):
    host = request.headers.get('host', '').split(':')[0].lower()
    path = request.url.path
    if CANONICAL_HOST and host and host != CANONICAL_HOST and path != '/health':
        base = 'https://' + CANONICAL_HOST
        parent = CANONICAL_HOST.split('.', 1)[1] if '.' in CANONICAL_HOST else ''
        if parent and host in (parent, 'www.' + parent):
            rest = path[len(SHORTCUT_PATH):] if path == SHORTCUT_PATH or path.startswith(SHORTCUT_PATH + '/') else ''
            return RedirectResponse(base + (rest or '/'), status_code=302)
        query = ('?' + request.url.query) if request.url.query else ''
        return RedirectResponse(base + path + query, status_code=301 if request.method in ('GET', 'HEAD') else 308)
    return await call_next(request)

@app.get('/api/internal/db-backup')
def db_backup(request: Request, background: BackgroundTasks):
    """Cópia consistente do banco para o site novo. Só existe com MIGRATION_TOKEN definido."""
    token = os.getenv('MIGRATION_TOKEN', '')
    if len(token) < 32 or not hmac.compare_digest(request.headers.get('x-migration-token', ''), token):
        raise HTTPException(404, 'Not Found')
    fd, name = tempfile.mkstemp(suffix='.sqlite3'); os.close(fd)
    src, dst = sqlite3.connect(DB_PATH), sqlite3.connect(name)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    background.add_task(os.remove, name)
    print('[migração] backup do banco enviado ao site novo.', flush=True)
    return FileResponse(name, media_type='application/octet-stream', headers={'Cache-Control': 'no-store'})

# Em ambientes de teste, ENV_BANNER (por exemplo "STAGING") mostra uma tarja vermelha
# no topo de todas as páginas. Em produção a variável não existe e nada muda.
ENV_BANNER = re.sub(r'[^A-Za-z0-9 ._-]', '', os.getenv('ENV_BANNER', ''))[:30].strip()

def html_page(name: str):
    if not ENV_BANNER:
        return FileResponse(STATIC / name)
    html = (STATIC / name).read_text('utf-8')
    tag = f'<div class="env-banner" role="note">{ENV_BANNER} · ambiente de testes</div>'
    html = html.replace('<body>', '<body class="has-env-banner">' + tag, 1)
    html = re.sub(r'<title>', f'<title>[{ENV_BANNER}] ', html, count=1)
    return HTMLResponse(html, headers={'Cache-Control': 'no-store'})

@app.get('/')
def index():
    return html_page('index.html')

@app.get('/admin')
def admin():
    return html_page('admin.html')

@app.get('/styles.css')
def styles():
    return FileResponse(STATIC / 'styles.css', media_type='text/css')

@app.get('/app.js')
def appjs():
    return FileResponse(STATIC / 'app.js', media_type='application/javascript')

@app.get('/admin.js')
def adminjs():
    return FileResponse(STATIC / 'admin.js', media_type='application/javascript')

@app.get('/manifest.webmanifest')
def manifest():
    return FileResponse(STATIC / 'manifest.webmanifest', media_type='application/manifest+json')

@app.get('/sw.js')
def serviceworker():
    return FileResponse(STATIC / 'sw.js', media_type='application/javascript', headers={'Cache-Control':'no-cache'})

@app.get('/api/session')
def session(request: Request):
    if 'csrf' not in request.session:
        request.session['csrf'] = secrets.token_urlsafe(24)
    user = None
    uid = request.session.get('uid')
    if isinstance(uid, int):
        with database() as con:
            u = con.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if u and request.session.get('sver') == u['session_version']:
            user = safe_user(u)
        else:
            request.session.pop('uid', None)
    return {'user': user, 'csrf': request.session['csrf']}

@app.post('/api/register')
def register(data: Register, request: Request, background: BackgroundTasks, _: None=Depends(csrf_protect)):
    if not data.consent:
        raise HTTPException(400, 'É necessário aceitar o aviso de privacidade.')
    try:
        phone = phone_normalize(data.phone)
    except ValueError as e:
        raise HTTPException(422, str(e))
    throttle('register:'+request.client.host if request.client else 'register:unknown', max_attempts=150,seconds=3600)
    with database() as con:
        try:
            t = now()
            cur = con.execute('''INSERT INTO users(name,phone,gender,password_hash,accepted_at,created_at,last_login_at,email)
                              VALUES(?,?,?,?,?,?,?,?)''',
                              (data.name, phone, data.gender, hash_password(data.password), t, t, t, data.email))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'Celular ou e-mail já cadastrado. Entre com sua senha ou use a recuperação.')
        user = con.execute('SELECT * FROM users WHERE id=?',(cur.lastrowid,)).fetchone()
    sign_in(request, user)
    if email_delivery_configured():
        background.add_task(issue_account_email, user['id'], 'verify')
    return {'user': safe_user(user)}

@app.post('/api/login')
def login(data: Login, request: Request, _: None=Depends(csrf_protect)):
    try:
        phone = phone_normalize(data.phone)
    except ValueError:
        raise HTTPException(401, 'Celular ou senha incorretos.')
    throttle('login:'+phone)
    with database() as con:
        user = con.execute('SELECT * FROM users WHERE phone=?',(phone,)).fetchone()
        valid = verify_password(data.password, user['password_hash']) if user else verify_password(data.password, DUMMY_HASH)
        if not valid or not user:
            raise HTTPException(401, 'Celular ou senha incorretos.')
        con.execute('UPDATE users SET last_login_at=? WHERE id=?',(now(),user['id']))
    sign_in(request,user)
    return {'user':safe_user(user)}

# Hash valid to normalize work done for nonexistent account; no default user is created.
DUMMY_HASH = hash_password(secrets.token_urlsafe(20))

@app.post('/api/logout')
def logout(request: Request, _: None=Depends(csrf_protect)):
    request.session.clear()
    return {'ok':True}

@app.get('/api/tests')
def get_tests(user=Depends(current_user)):
    output = {'TI':[None]*16,'LA':[None]*30}
    with database() as con:
        for rec in con.execute('SELECT test_code,answers FROM test_answers WHERE user_id=?',(user['id'],)):
            try:
                vals = json.loads(rec['answers'])
                if len(vals) == len(output[rec['test_code']]):
                    output[rec['test_code']] = vals
            except (ValueError, KeyError, TypeError):
                continue
    return output

@app.put('/api/tests/{test_code}')
def save_test(test_code: str, data: Answers, user=Depends(current_user), _: None=Depends(csrf_protect)):
    if test_code not in ('TI','LA'):
        raise HTTPException(404, 'Teste não encontrado.')
    length, allowed = (16, range(1,6)) if test_code=='TI' else (30, (0,1))
    if len(data.answers)!=length or any(v is not None and (type(v) is not int or v not in allowed) for v in data.answers):
        raise HTTPException(422, 'Respostas inválidas.')
    with database() as con:
        con.execute('''INSERT INTO test_answers(user_id,test_code,answers,updated_at)
                       VALUES(?,?,?,?) ON CONFLICT(user_id,test_code) DO UPDATE SET
                       answers=excluded.answers,updated_at=excluded.updated_at''',
                    (user['id'],test_code,json.dumps(data.answers),now()))
    return {'ok':True,'answered':sum(x is not None for x in data.answers)}

@app.patch('/api/profile')
def update_profile(data: ProfileUpdate, user=Depends(current_user), _: None=Depends(csrf_protect)):
    with database() as con:
        con.execute('UPDATE users SET name=? WHERE id=?',(data.name,user['id']))
        result=con.execute('SELECT * FROM users WHERE id=?',(user['id'],)).fetchone()
    return {'user':safe_user(result)}

@app.post('/api/profile/password')
def change_password(data: PasswordUpdate, request: Request, user=Depends(current_user), _: None=Depends(csrf_protect)):
    if not verify_password(data.current_password,user['password_hash']):
        raise HTTPException(400, 'Senha atual incorreta.')
    with database() as con:
        con.execute('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',(hash_password(data.new_password),user['id']))
    request.session.clear()
    return {'ok':True,'login_required':True}

@app.post('/api/profile/delete')
def delete_account(data: DeleteAccount,request:Request,user=Depends(current_user), _: None=Depends(csrf_protect)):
    if not verify_password(data.password,user['password_hash']):
        raise HTTPException(400, 'Senha incorreta.')
    with database() as con:
        con.execute('DELETE FROM users WHERE id=?',(user['id'],))
    request.session.clear()
    return {'ok':True}

@app.get('/api/admin/registrations')
def registrations(q: str='', page: int=1, user=Depends(admin_user)):
    page = max(1,min(page,100000))
    q = q.strip()[:100]
    term = '%'+q.replace('%','\\%').replace('_','\\_')+'%'
    where = "WHERE (u.name LIKE ? ESCAPE '\\' OR u.phone LIKE ? ESCAPE '\\')" if q else ''
    args = (term,term) if q else ()
    with database() as con:
        total = con.execute('SELECT COUNT(*) FROM users u '+where,args).fetchone()[0]
        rows = con.execute(f'''SELECT u.id,u.name,u.phone,u.gender,u.role,u.created_at,u.last_login_at,
                         t.answers AS ti, l.answers AS la
                         FROM users u LEFT JOIN test_answers t ON t.user_id=u.id AND t.test_code='TI'
                         LEFT JOIN test_answers l ON l.user_id=u.id AND l.test_code='LA'
                         {where} ORDER BY u.created_at DESC,u.id DESC LIMIT 50 OFFSET ?''', args+((page-1)*50,)).fetchall()
    def count_answers(raw):
        try: return sum(x is not None for x in json.loads(raw)) if raw else 0
        except (TypeError,ValueError): return 0
    return {'total':total,'page':page,'page_size':50,'items':[
        {'id':r['id'],'name':r['name'],'phone':r['phone'],'gender':r['gender'],'role':r['role'],
         'created_at':r['created_at'],'last_login_at':r['last_login_at'],
         'ti_answered':count_answers(r['ti']),'la_answered':count_answers(r['la'])} for r in rows]}

@app.post('/api/admin/users/{user_id}/password')
def admin_reset_password(user_id: int, data: AdminPasswordReset, user=Depends(admin_user), _: None=Depends(csrf_protect)):
    """O administrador define uma nova senha para um participante que perdeu o acesso."""
    throttle(f"admin-reset:{user['id']}", max_attempts=20)
    if not verify_password(data.admin_password, user['password_hash']):
        raise HTTPException(400, 'Sua senha de administrador está incorreta.')
    if user_id == user['id']:
        raise HTTPException(400, 'Para trocar a sua própria senha, use Meu perfil.')
    with database() as con:
        target = con.execute('SELECT id FROM users WHERE id=?', (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, 'Cadastro não encontrado.')
        # Encerra as sessões abertas do participante e invalida links de recuperação pendentes.
        con.execute('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',
                    (hash_password(data.new_password), user_id))
        con.execute("DELETE FROM account_tokens WHERE user_id=? AND purpose='reset'", (user_id,))
    print(f'[admin] senha redefinida: participante id={user_id} por admin id={user["id"]}', flush=True)
    return {'ok': True}

@app.get('/api/admin/export.csv')
def export(q: str='', user=Depends(admin_user)):
    q=q.strip()[:100]
    term='%'+q.replace('%','\\%').replace('_','\\_')+'%'
    where="WHERE (u.name LIKE ? ESCAPE '\\' OR u.phone LIKE ? ESCAPE '\\')" if q else ''
    args=(term,term) if q else ()
    with database() as con:
        rows=con.execute(f'''SELECT u.name,u.phone,u.gender,u.created_at,u.last_login_at,
                            t.answers ti,l.answers la FROM users u
                            LEFT JOIN test_answers t ON t.user_id=u.id AND t.test_code='TI'
                            LEFT JOIN test_answers l ON l.user_id=u.id AND l.test_code='LA'
                            {where} ORDER BY u.id''',args).fetchall()
    stream=io.StringIO()
    writer=csv.writer(stream,delimiter=';')
    writer.writerow(['Nome','Celular','Versão','Cadastro','Último acesso','Termômetro respondidas','Linguagens respondidas'])
    def safe(s):
        s=str(s or '')
        return "'"+s if s.lstrip().startswith(('=','+','-','@','\t','\r')) else s
    for r in rows:
        def count(s):
            try:return sum(x is not None for x in json.loads(s)) if s else 0
            except (ValueError,TypeError):return 0
        writer.writerow([safe(r['name']),safe(r['phone']),r['gender'],r['created_at'],r['last_login_at'],count(r['ti']),count(r['la'])])
    data='\ufeff'+stream.getvalue()
    return StreamingResponse(iter([data]),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="cadastros_casais.csv"','Cache-Control':'no-store'})

@app.get('/api/course')
def course_material(user=Depends(current_user)):
    """Material didático disponível apenas para participantes autenticados."""
    return FileResponse(ROOT / 'curso_alianca_12_aulas.json', media_type='application/json',
                        headers={'Cache-Control': 'private, no-store'})

# Perguntas da "Reflexão em Casal" de cada aula. O id é a posição do bloco na lição,
# então continua válido enquanto o JSON da apostila não for reorganizado.
COURSE_FILE = ROOT / 'curso_alianca_12_aulas.json'
MAX_ANSWER_CHARS = 5000

def load_course_questions():
    try:
        data = json.loads(COURSE_FILE.read_text('utf-8'))
    except (OSError, ValueError):
        return {}
    out = {}
    for lesson in data.get('lessons', []):
        number, heading, ids = int(lesson['number']), '', set()
        for idx, block in enumerate(lesson.get('blocks', [])):
            if block.get('kind') == 'heading':
                heading = block.get('text', '')
            elif heading.startswith('Reflexão') and block.get('kind') in ('text', 'bullet') \
                    and re.match(r'^\d+[.)]\s', block.get('text', '')):
                ids.add(idx)
        out[number] = ids
    return out

COURSE_QUESTIONS = load_course_questions()

class LessonAnswer(BaseModel):
    answer: str

def check_question(lesson_number: int, question_id: int):
    if question_id not in COURSE_QUESTIONS.get(lesson_number, set()):
        raise HTTPException(404, 'Pergunta não encontrada.')

@app.get('/api/course/answers')
def get_lesson_answers(user=Depends(current_user)):
    """Respostas pessoais dos exercícios. Só o próprio participante tem acesso."""
    out = {}
    with database() as con:
        for rec in con.execute('SELECT lesson_number,question_id,answer,updated_at FROM lesson_answers WHERE user_id=?', (user['id'],)):
            out.setdefault(str(rec['lesson_number']), {})[str(rec['question_id'])] = {'answer': rec['answer'], 'updated_at': rec['updated_at']}
    return {'answers': out}

@app.put('/api/course/answers/{lesson_number}/{question_id}')
def save_lesson_answer(lesson_number: int, question_id: int, data: LessonAnswer, user=Depends(current_user), _: None=Depends(csrf_protect)):
    check_question(lesson_number, question_id)
    text = data.answer.replace('\r\n', '\n').strip()
    if not text:
        raise HTTPException(422, 'Escreva sua resposta antes de salvar.')
    if len(text) > MAX_ANSWER_CHARS:
        raise HTTPException(422, f'A resposta pode ter até {MAX_ANSWER_CHARS} caracteres.')
    stamp = now()
    with database() as con:
        con.execute('''INSERT INTO lesson_answers(user_id,lesson_number,question_id,answer,updated_at)
                       VALUES(?,?,?,?,?) ON CONFLICT(user_id,lesson_number,question_id) DO UPDATE SET
                       answer=excluded.answer,updated_at=excluded.updated_at''',
                    (user['id'], lesson_number, question_id, text, stamp))
    return {'ok': True, 'answer': text, 'updated_at': stamp}

@app.delete('/api/course/answers/{lesson_number}/{question_id}')
def delete_lesson_answer(lesson_number: int, question_id: int, user=Depends(current_user), _: None=Depends(csrf_protect)):
    check_question(lesson_number, question_id)
    with database() as con:
        con.execute('DELETE FROM lesson_answers WHERE user_id=? AND lesson_number=? AND question_id=?',
                    (user['id'], lesson_number, question_id))
    return {'ok': True}

@app.get('/health')
def health():
    return {'status':'ok'}


def seed_test_admin():
    """Só para o site de testes: cria um admin se TEST_ADMIN_PHONE e TEST_ADMIN_PASSWORD
    estiverem definidos. Em produção essas variáveis não existem e nada acontece."""
    phone, password = os.getenv('TEST_ADMIN_PHONE', ''), os.getenv('TEST_ADMIN_PASSWORD', '')
    if not phone or len(password) < 12:
        return
    t = now()
    with database() as con:
        con.execute('''INSERT OR IGNORE INTO users(name,phone,gender,password_hash,role,accepted_at,created_at)
                       VALUES(?,?,?,?,?,?,?)''', ('Admin Teste', phone_normalize(phone), 'M', hash_password(password), 'admin', t, t))

seed_test_admin()
