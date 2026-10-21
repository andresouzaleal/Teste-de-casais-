import hashlib
import re
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
import main


@pytest.fixture(autouse=True)
def email_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'test.sqlite3')
    main.init_db()
    for key, value in {'SMTP_HOST': 'smtp.example.com', 'SMTP_USER': 'sender@example.com',
                       'SMTP_PASSWORD': 'test-only', 'SMTP_FROM': 'sender@example.com',
                       'PUBLIC_BASE_URL': 'https://testes-para-casais.onrender.com'}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('SMTP_SSL', raising=False)
    smtp = MagicMock()
    monkeypatch.setattr(main.smtplib, 'SMTP', smtp)
    return smtp.return_value.__enter__.return_value


def client():
    return TestClient(main.app)


def post(c, path, data):
    csrf = c.get('/api/session').json()['csrf']
    return c.post(path, json=data, headers={'X-CSRF-Token': csrf})


def register(c):
    r = post(c, '/api/register', {'name': 'Teste Pessoa', 'phone': '11987654321',
             'gender': 'M', 'password': 'SenhaOriginal123!', 'email': 'pessoa@example.com', 'consent': True})
    assert r.status_code == 200, r.text


def token(smtp):
    message = smtp.send_message.call_args.args[0]
    return re.search(r'#(?:confirmar-email|redefinir-senha)=([A-Za-z0-9_-]+)', message.get_content()).group(1)


def verified(c, smtp):
    register(c)
    confirmation = token(smtp)
    assert post(c, '/api/email/verify', {'token': confirmation}).status_code == 200
    assert post(c, '/api/email/verify', {'token': confirmation}).status_code == 400
    return c


def test_recovery_preserves_answers_and_invalidates_sessions(email_setup):
    c = verified(client(), email_setup)
    csrf = c.get('/api/session').json()['csrf']
    assert c.put('/api/tests/TI', json={'answers': [3]*16}, headers={'X-CSRF-Token': csrf}).status_code == 200
    old_session = client()
    assert post(old_session, '/api/login', {'phone': '11987654321', 'password': 'SenhaOriginal123!'}).status_code == 200
    visitor = client()
    assert post(visitor, '/api/password/forgot', {'email': 'PESSOA@example.com'}).status_code == 200
    reset = token(email_setup)
    with main.database() as con:
        row = con.execute("SELECT * FROM account_tokens WHERE purpose='reset'").fetchone()
        assert row['token_hash'] == hashlib.sha256(reset.encode()).hexdigest()
        assert reset not in str(dict(row))
    assert post(visitor, '/api/password/reset', {'token': reset, 'new_password': 'NovaSenha123!'}).status_code == 200
    assert post(visitor, '/api/password/reset', {'token': reset, 'new_password': 'OutraSenha123!'}).status_code == 400
    assert c.get('/api/tests').status_code == 401
    assert old_session.get('/api/tests').status_code == 401
    assert post(visitor, '/api/login', {'phone': '11987654321', 'password': 'SenhaOriginal123!'}).status_code == 401
    assert post(visitor, '/api/login', {'phone': '11987654321', 'password': 'NovaSenha123!'}).status_code == 200
    assert visitor.get('/api/tests').json()['TI'] == [3]*16


def test_unknown_and_unverified_email_have_same_response(email_setup):
    c = client()
    register(c)
    email_setup.send_message.reset_mock()
    a = post(c, '/api/password/forgot', {'email': 'pessoa@example.com'})
    b = post(c, '/api/password/forgot', {'email': 'unknown@example.com'})
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()
    email_setup.send_message.assert_not_called()


def test_expired_replaced_and_wrong_purpose_tokens(email_setup):
    c = verified(client(), email_setup)
    post(c, '/api/password/forgot', {'email': 'pessoa@example.com'})
    previous = token(email_setup)
    post(c, '/api/password/forgot', {'email': 'pessoa@example.com'})
    latest = token(email_setup)
    assert post(c, '/api/password/reset', {'token': previous, 'new_password': 'NovaSenha123!'}).status_code == 400
    assert post(c, '/api/email/verify', {'token': latest}).status_code == 400
    with main.database() as con:
        con.execute('UPDATE account_tokens SET expires_at=?', (int(time.time())-1,))
    assert post(c, '/api/password/reset', {'token': latest, 'new_password': 'NovaSenha123!'}).status_code == 400


def test_legacy_account_can_add_confirmed_email(email_setup):
    c = client()
    register(c)
    with main.database() as con:
        con.execute('UPDATE users SET email=NULL, email_verified=0')
    assert post(c, '/api/profile/email', {'email': 'novo@example.com', 'password': 'errada'}).status_code == 400
    assert post(c, '/api/profile/email', {'email': 'novo@example.com', 'password': 'SenhaOriginal123!'}).status_code == 200
    assert not c.get('/api/session').json()['user']['email_verified']
    assert post(c, '/api/email/verify', {'token': token(email_setup)}).status_code == 200
    user = c.get('/api/session').json()['user']
    assert user['email'] == 'novo@example.com' and user['email_verified']


def test_csrf_validation_and_throttling(email_setup):
    c = client()
    assert c.post('/api/password/forgot', json={'email': 'pessoa@example.com'}).status_code == 403
    assert post(c, '/api/password/forgot', {'email': 'invalido'}).status_code == 422
    for _ in range(3):
        assert post(c, '/api/password/forgot', {'email': 'pessoa@example.com'}).status_code == 200
    assert post(c, '/api/password/forgot', {'email': 'pessoa@example.com'}).status_code == 429
    assert post(c, '/api/password/reset', {'token': 'x'*43, 'new_password': 'curta'}).status_code == 422


def test_missing_delivery_config_and_failed_delivery(email_setup, monkeypatch):
    c = client()
    verified(c, email_setup)
    email_setup.send_message.side_effect = OSError('SMTP indisponível')
    assert post(c, '/api/password/forgot', {'email': 'pessoa@example.com'}).status_code == 200
    with main.database() as con:
        assert con.execute("SELECT count(*) FROM account_tokens WHERE purpose='reset'").fetchone()[0] == 0
    monkeypatch.delenv('SMTP_PASSWORD')
    assert post(c, '/api/password/forgot', {'email': 'pessoa@example.com'}).status_code == 503


def test_migration_preserves_legacy_user(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / 'old.sqlite3'
    monkeypatch.setattr(main, 'DB_PATH', path)
    with sqlite3.connect(path) as con:
        con.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, phone TEXT,
                    gender TEXT, password_hash TEXT, role TEXT, session_version INTEGER,
                    accepted_at TEXT, created_at TEXT, last_login_at TEXT)''')
        con.execute("INSERT INTO users VALUES (1,'Pessoa Antiga','11987654321','M','hash','user',0,'data','data',NULL)")
    main.init_db()
    main.init_db()
    with main.database() as con:
        user = con.execute('SELECT * FROM users WHERE id=1').fetchone()
        assert user['name'] == 'Pessoa Antiga'
        assert user['email'] is None and user['email_verified'] == 0


def test_signup_still_works_without_email_configuration(email_setup, monkeypatch):
    monkeypatch.delenv('SMTP_PASSWORD')
    c = client()
    register(c)
    email_setup.send_message.assert_not_called()
    user = c.get('/api/session').json()['user']
    assert user['email'] == 'pessoa@example.com' and not user['email_verified']
