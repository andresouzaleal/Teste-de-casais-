"""Use: python create_admin.py --phone 11999999999 --name 'Administrador Geral'"""
import argparse
import getpass
from main import database, hash_password, now, phone_normalize

parser=argparse.ArgumentParser(description='Cria ou atualiza uma conta administradora.')
parser.add_argument('--phone',required=True,help='Celular com DDD, 11 dígitos')
parser.add_argument('--name',default='Administrador Geral')
parser.add_argument('--gender',choices=['M','F'],default='M')
args=parser.parse_args()
phone=phone_normalize(args.phone)
password=getpass.getpass('Crie uma senha administrativa (mínimo 12 caracteres): ')
if len(password)<12:
    raise SystemExit('Senha muito curta. Mínimo: 12 caracteres.')
if getpass.getpass('Confirme a senha: ') != password:
    raise SystemExit('As senhas não coincidem.')
with database() as con:
    old=con.execute('SELECT id FROM users WHERE phone=?',(phone,)).fetchone()
    if old:
        con.execute('UPDATE users SET role=?,password_hash=?,name=?,session_version=session_version+1 WHERE id=?',('admin',hash_password(password),args.name,old['id']))
    else:
        t=now()
        con.execute('INSERT INTO users(name,phone,gender,password_hash,role,accepted_at,created_at) VALUES(?,?,?,?,?,?,?)',
                  (args.name,phone,args.gender,hash_password(password),'admin',t,t))
print('Conta administradora configurada. Login no próprio aplicativo ou em /admin.')
