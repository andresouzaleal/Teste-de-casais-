import os
import tempfile
from pathlib import Path
import sys
from unittest.mock import MagicMock
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import main
from fastapi.testclient import TestClient

@pytest.fixture(autouse=True)
def mock_email_delivery(monkeypatch):
    for key, value in {'SMTP_HOST': 'smtp.example.com', 'SMTP_USER': 'sender@example.com',
                       'SMTP_PASSWORD': 'test-only', 'SMTP_FROM': 'sender@example.com',
                       'PUBLIC_BASE_URL': 'https://testes-para-casais.onrender.com'}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main.smtplib, 'SMTP', MagicMock())


def prepare():
    tmp=tempfile.TemporaryDirectory()
    main.DB_PATH=Path(tmp.name)/'test.sqlite3'
    main.init_db()
    return tmp


def register(client,phone='11987654321',gender='M',name='Teste Pessoa'):
    csrf=client.get('/api/session').json()['csrf']
    response=client.post('/api/register',json={'name':name,'phone':phone,'gender':gender,
             'password':'Seguro1234!', 'email':phone+'@example.com', 'consent':True},headers={'X-CSRF-Token':csrf})
    return response


def test_registration_and_resume():
    tmp=prepare()
    try:
        a=TestClient(main.app)
        assert a.get('/api/tests').status_code==401
        assert a.get('/api/admin/registrations').status_code==401
        assert register(a).status_code==200
        info=a.get('/api/session').json()
        assert info['user']['phone']=='11987654321'
        assert info['user']['gender']=='M'
        assert 'password_hash' not in str(info)
        csrf=info['csrf']
        assert a.put('/api/tests/TI',json={'answers':[3]*16}).status_code==403
        assert a.put('/api/tests/TI',headers={'X-CSRF-Token':csrf},json={'answers':[3]*16}).status_code==200
        assert a.get('/api/tests').json()['TI']==[3]*16
        assert a.get('/api/admin/registrations').status_code==403
        assert register(TestClient(main.app),phone='11987654321').status_code==409
        b=TestClient(main.app)
        assert register(b,'21998887766','F','Outra Pessoa').status_code==200
        assert b.get('/api/tests').json()['TI']==[None]*16
        assert b.get('/api/tests').json()['LA']==[None]*30
        assert b.put('/api/tests/LA',json={'answers':[2]*30},headers={'X-CSRF-Token':b.get('/api/session').json()['csrf']}).status_code==422
        assert a.post('/api/logout',headers={'X-CSRF-Token':csrf}).status_code==200
        assert a.get('/api/tests').status_code==401
        new_csrf=a.get('/api/session').json()['csrf']
        wrong=a.post('/api/login',json={'phone':'11987654321','password':'foo'},headers={'X-CSRF-Token':new_csrf})
        assert wrong.status_code==401
        assert a.post('/api/login',json={'phone':'11987654321','password':'Seguro1234!'},headers={'X-CSRF-Token':new_csrf}).status_code==200
        assert a.get('/api/tests').json()['TI']==[3]*16
    finally:
        tmp.cleanup()


def test_admin_only_listing_and_csv():
    tmp=prepare()
    try:
        with main.database() as con:
            t=main.now()
            con.execute('INSERT INTO users(name,phone,gender,password_hash,role,accepted_at,created_at) VALUES(?,?,?,?,?,?,?)',
                       ('Painel Gestor','31999997777','M',main.hash_password('MasterSenha!23'),'admin',t,t))
        admin=TestClient(main.app)
        csrf=admin.get('/api/session').json()['csrf']
        assert admin.post('/api/login',json={'phone':'31999997777','password':'MasterSenha!23'},headers={'X-CSRF-Token':csrf}).status_code==200
        user=TestClient(main.app)
        assert register(user,phone='11999998888').status_code==200
        listing=admin.get('/api/admin/registrations')
        assert listing.status_code==200
        rows=listing.json()['items']
        assert len(rows)==2
        assert all('answers' not in r for r in rows)
        assert any(r['name']=='Teste Pessoa' for r in rows)
        assert 'Teste Pessoa' in admin.get('/api/admin/export.csv').text
        assert user.get('/api/admin/export.csv').status_code==403
    finally:
        tmp.cleanup()


def test_deletion_removes_answers():
    tmp=prepare()
    try:
        c=TestClient(main.app)
        assert register(c).status_code==200
        csrf=c.get('/api/session').json()['csrf']
        assert c.put('/api/tests/LA',json={'answers':[0]*30},headers={'X-CSRF-Token':csrf}).status_code==200
        assert c.post('/api/profile/delete',json={'password':'Seguro1234!'},headers={'X-CSRF-Token':csrf}).status_code==200
        assert c.get('/api/tests').status_code==401
        with main.database() as con:
            assert con.execute('SELECT count(*) FROM users').fetchone()[0]==0
            assert con.execute('SELECT count(*) FROM test_answers').fetchone()[0]==0
    finally:
        tmp.cleanup()
