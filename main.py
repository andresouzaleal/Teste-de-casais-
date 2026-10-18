"""Teste para Casais — backend FastAPI/SQLite, sessões seguras e admin separado."""
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictInt, field_validator
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).resolve().parent
STATIC = ROOT
DB_PATH = Path(os.getenv('DB_PATH', str(ROOT / 'data' / 'casais.sqlite3')))
SECRET_KEY = os.getenv('SESSION_SECRET') or secrets.token_urlsafe(48)
IS_PRODUCTION = os.getenv('APP_ENV', '').lower() == 'production'
if IS_PRODUCTION and not os.getenv('SESSION_SECRET'):
    raise RuntimeError('Defina SESSION_SECRET antes de executar em produção.')

app = FastAPI(title='Teste para Casais', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY,
                   session_cookie='casais_session', max_age=604800,
                   same_site='lax', https_only=IS_PRODUCTION)
app.mount('/assets', StaticFiles(directory=STATIC / 'assets'), name='assets')

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
        ''')

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

class Register(BaseModel):
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

class DeleteAccount(BaseModel):
    password: str


def safe_user(u):
    return {k: u[k] for k in ('id', 'name', 'phone', 'gender', 'role', 'created_at')}

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

@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')

@app.get('/admin')
def admin():
    return FileResponse(STATIC / 'admin.html')

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
def register(data: Register, request: Request, _: None=Depends(csrf_protect)):
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
            cur = con.execute('''INSERT INTO users(name,phone,gender,password_hash,accepted_at,created_at,last_login_at)
                              VALUES(?,?,?,?,?,?,?)''',
                              (data.name, phone, data.gender, hash_password(data.password), t, t, t))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'Este celular já possui cadastro. Entre com sua senha.')
        user = con.execute('SELECT * FROM users WHERE id=?',(cur.lastrowid,)).fetchone()
    sign_in(request, user)
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

@app.get('/health')
def health():
    return {'status':'ok'}
