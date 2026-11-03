from test_app import prepare, register, main
from fastapi.testclient import TestClient

ADMIN_PHONE, ADMIN_PASS = '31999997777', 'MasterSenha!23'


def login(client, phone, password):
    csrf = client.get('/api/session').json()['csrf']
    return client.post('/api/login', json={'phone': phone, 'password': password}, headers={'X-CSRF-Token': csrf})


def setup_admin_and_user():
    with main.database() as con:
        t = main.now()
        con.execute('INSERT INTO users(name,phone,gender,password_hash,role,accepted_at,created_at) VALUES(?,?,?,?,?,?,?)',
                    ('Painel Gestor', ADMIN_PHONE, 'M', main.hash_password(ADMIN_PASS), 'admin', t, t))
    admin, user = TestClient(main.app), TestClient(main.app)
    assert login(admin, ADMIN_PHONE, ADMIN_PASS).status_code == 200
    assert register(user, phone='11999998888').status_code == 200
    uid = next(r['id'] for r in admin.get('/api/admin/registrations').json()['items'] if r['phone'] != ADMIN_PHONE)
    return admin, user, uid


def test_admin_sets_new_password_and_logs_user_out():
    tmp = prepare()
    try:
        admin, user, uid = setup_admin_and_user()
        h = {'X-CSRF-Token': admin.get('/api/session').json()['csrf']}
        r = admin.post(f'/api/admin/users/{uid}/password', json={'admin_password': ADMIN_PASS, 'new_password': 'NovaSenha2026'}, headers=h)
        assert r.status_code == 200
        assert user.get('/api/tests').status_code == 401          # sessão antiga encerrada
        fresh = TestClient(main.app)
        assert login(fresh, '11999998888', 'Seguro1234!').status_code != 200
        assert login(fresh, '11999998888', 'NovaSenha2026').status_code == 200
    finally:
        tmp.cleanup()


def test_reset_requires_admin_password_csrf_and_role():
    tmp = prepare()
    try:
        admin, user, uid = setup_admin_and_user()
        h = {'X-CSRF-Token': admin.get('/api/session').json()['csrf']}
        url = f'/api/admin/users/{uid}/password'
        body = {'admin_password': ADMIN_PASS, 'new_password': 'NovaSenha2026'}
        assert admin.post(url, json=body).status_code == 403                                   # sem CSRF
        assert admin.post(url, json={**body, 'admin_password': 'errada'}, headers=h).status_code == 400
        assert admin.post(url, json={**body, 'new_password': 'curta'}, headers=h).status_code == 422
        assert admin.post('/api/admin/users/99999/password', json=body, headers=h).status_code == 404
        admin_id = next(r['id'] for r in admin.get('/api/admin/registrations').json()['items'] if r['phone'] == ADMIN_PHONE)
        assert admin.post(f'/api/admin/users/{admin_id}/password', json=body, headers=h).status_code == 400
        hu = {'X-CSRF-Token': user.get('/api/session').json()['csrf']}
        assert user.post(f'/api/admin/users/{admin_id}/password', json={'admin_password': 'Seguro1234!', 'new_password': 'Hack12345'}, headers=hu).status_code == 403
        assert login(TestClient(main.app), '11999998888', 'Seguro1234!').status_code == 200   # nada mudou
    finally:
        tmp.cleanup()
