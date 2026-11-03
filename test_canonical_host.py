import importlib, os, sys
from fastapi.testclient import TestClient

def make_client(tmp_path, monkeypatch):
    monkeypatch.setenv('DB_PATH', str(tmp_path / 'db.sqlite3'))
    monkeypatch.setenv('CANONICAL_HOST', 'casais.familiapenha.com.br')
    sys.modules.pop('main', None)
    import main
    return TestClient(main.app, follow_redirects=False)

def test_shortcut_and_hosts(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch)
    r = c.get('/appcasais', headers={'host': 'www.familiapenha.com.br'})
    assert r.status_code == 302 and r.headers['location'] == 'https://casais.familiapenha.com.br/'
    r = c.get('/appcasais/admin.html', headers={'host': 'familiapenha.com.br'})
    assert r.headers['location'] == 'https://casais.familiapenha.com.br/admin.html'
    r = c.get('/', headers={'host': 'www.familiapenha.com.br'})
    assert r.status_code == 302 and r.headers['location'] == 'https://casais.familiapenha.com.br/'
    r = c.get('/admin.html?x=1', headers={'host': 'curso-de-casais-alianca.onrender.com'})
    assert r.status_code == 301 and r.headers['location'] == 'https://casais.familiapenha.com.br/admin.html?x=1'
    assert c.get('/health', headers={'host': 'curso-de-casais-alianca.onrender.com'}).status_code == 200
    assert c.get('/', headers={'host': 'casais.familiapenha.com.br'}).status_code == 200
