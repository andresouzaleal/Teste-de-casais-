import sqlite3
from test_app import prepare, register, main
from fastapi.testclient import TestClient

TOKEN = 'x' * 40


def test_backup_endpoint_needs_token(monkeypatch, tmp_path):
    tmp = prepare()
    try:
        c = TestClient(main.app)
        assert c.get('/api/internal/db-backup').status_code == 404          # desligado sem token
        monkeypatch.setenv('MIGRATION_TOKEN', TOKEN)
        assert c.get('/api/internal/db-backup', headers={'X-Migration-Token': 'errado'}).status_code == 404
        register(c)
        r = c.get('/api/internal/db-backup', headers={'X-Migration-Token': TOKEN})
        assert r.status_code == 200
        f = tmp_path / 'b.sqlite3'; f.write_bytes(r.content)
        assert sqlite3.connect(f).execute('SELECT COUNT(*) FROM users').fetchone()[0] == 1
    finally:
        tmp.cleanup()


def test_redirect_keeps_path_but_not_health(monkeypatch):
    monkeypatch.setattr(main, 'REDIRECT_TO', 'https://novo.example.com')
    c = TestClient(main.app, follow_redirects=False)
    r = c.get('/admin?x=1')
    assert r.status_code == 301 and r.headers['location'] == 'https://novo.example.com/admin?x=1'
    assert c.post('/api/login', json={}).status_code == 308
    assert c.get('/health').status_code == 200
