from test_app import prepare, register, main
from fastapi.testclient import TestClient


def first_question():
    lesson = 1
    return lesson, min(main.COURSE_QUESTIONS[lesson])


def test_every_lesson_has_reflection_questions():
    assert sorted(main.COURSE_QUESTIONS) == list(range(1, 13))
    assert all(len(ids) >= 4 for ids in main.COURSE_QUESTIONS.values())


def test_save_edit_delete_answer_is_private():
    tmp = prepare()
    try:
        a, b = TestClient(main.app), TestClient(main.app)
        lesson, q = first_question()
        url = f'/api/course/answers/{lesson}/{q}'
        assert a.get('/api/course/answers').status_code == 401
        assert register(a).status_code == 200
        assert register(b, phone='11912345678', gender='F', name='Outra Pessoa').status_code == 200
        ha = {'X-CSRF-Token': a.get('/api/session').json()['csrf']}
        hb = {'X-CSRF-Token': b.get('/api/session').json()['csrf']}

        assert a.put(url, json={'answer': 'Primeira versão'}).status_code == 403  # sem CSRF
        assert a.put(url, json={'answer': '  Primeira versão  '}, headers=ha).json()['answer'] == 'Primeira versão'
        assert a.put(url, json={'answer': 'Versão editada'}, headers=ha).status_code == 200
        saved = a.get('/api/course/answers').json()['answers']
        assert saved[str(lesson)][str(q)]['answer'] == 'Versão editada'

        # o cônjuge (outra conta) não vê a resposta
        assert b.get('/api/course/answers').json()['answers'] == {}

        assert a.delete(url, headers=ha).status_code == 200
        assert a.get('/api/course/answers').json()['answers'] == {}
        assert b.delete(url, headers=hb).status_code == 200
    finally:
        tmp.cleanup()


def test_rejects_invalid_answers_and_questions():
    tmp = prepare()
    try:
        a = TestClient(main.app)
        register(a)
        h = {'X-CSRF-Token': a.get('/api/session').json()['csrf']}
        lesson, q = first_question()
        assert a.put(f'/api/course/answers/{lesson}/{q}', json={'answer': '   '}, headers=h).status_code == 422
        assert a.put(f'/api/course/answers/{lesson}/{q}', json={'answer': 'x' * 5001}, headers=h).status_code == 422
        assert a.put(f'/api/course/answers/{lesson}/0', json={'answer': 'oi'}, headers=h).status_code == 404
        assert a.put(f'/api/course/answers/13/{q}', json={'answer': 'oi'}, headers=h).status_code == 404
    finally:
        tmp.cleanup()


def test_account_deletion_removes_lesson_answers():
    tmp = prepare()
    try:
        a = TestClient(main.app)
        register(a)
        h = {'X-CSRF-Token': a.get('/api/session').json()['csrf']}
        lesson, q = first_question()
        a.put(f'/api/course/answers/{lesson}/{q}', json={'answer': 'Algo pessoal'}, headers=h)
        assert a.post('/api/profile/delete', json={'password': 'Seguro1234!'}, headers=h).status_code == 200
        with main.database() as con:
            assert con.execute('SELECT COUNT(*) FROM lesson_answers').fetchone()[0] == 0
    finally:
        tmp.cleanup()
