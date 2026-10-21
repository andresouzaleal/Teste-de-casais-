Testes para Casais — Família Penha
Versão com cadastro, login, banco e painel administrativo
Esta edição é um WebApp instalável em Android e iPhone (PWA) COM SERVIDOR. Não é um HTML para abrir no gerenciador de arquivos. Acesse via URL HTTPS após publicar.
O que foi entregue
Cabeçalho fixo de altura compacta com pequeno banner fotográfico, ícone maior e marca tipográfica Testes para Casais.
Home com os dois testes: Termômetro da Intimidade (16 afirmações/8 áreas, escala 1–5) e 5 Linguagens do Amor (30 escolhas).
Cadastro individual obrigatório antes do teste, com nome completo, celular com DDD, versão masculina/feminina, senha e concordância com a finalidade do armazenamento.
Login pelo número de celular, senha armazenada com PBKDF2-HMAC-SHA256 e sessão por cookie assinado.
Salva respostas e progresso no banco do servidor. O participante pode sair e continuar de outro celular após login.
Perfil com edição do nome, mudança de senha e exclusão do cadastro e respostas.
Área /admin exclusiva para administradores: consulta de cadastros, pesquisa por nome/celular, progresso por teste e exportação CSV.
Comparação voluntária entre cônjuges por códigos resumidos e impressão de resultados via navegador (Salvar como PDF).
UI responsiva e manifest para "Adicionar à tela inicial".
Atenção a recursos da versão anterior
O relatório consolidado automático do casal (ambos os testes de marido e esposa no mesmo PDF) não está implementado nesta edição com contas individuais. A comparação por códigos de pontuações resumidas continua disponível em cada teste.
O aplicativo não importa automaticamente resultados/cadastros dos antigos arquivos localStorage. A nova versão exige cadastro online.
O banco começa vazio. Não existem usuários nem administradores pré-cadastrados.
Número de celular é login, não autenticação por SMS/WhatsApp. A posse do celular não é verificada nesta edição.
Senhas esquecidas podem ser redefinidas por e-mail ("Esqueci minha senha"), desde que a pessoa tenha um e-mail confirmado no perfil. O envio só funciona depois de configurar o provedor de e-mail — veja CONFIGURAR_EMAIL.md. Não há redefinição por SMS/WhatsApp.
Executar para testes no computador
Requer Python 3.10+ e acesso ao terminal.
python -m venv .venv
# Linux/Mac:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Defina SESSION_SECRET em uma variável de ambiente (veja abaixo)
uvicorn main:app --host 0.0.0.0 --port 8000
Acesse http://localhost:8000/. No celular, use a URL pública HTTPS depois do deploy (localhost do computador não serve para o celular remoto).
Criar seu usuário administrador
Após instalar as dependências e configurar DB_PATH se desejado:
python create_admin.py --phone 11999999999 --name "Administrador Geral" --gender M
Substitua o número fictício pelo seu celular com DDD. O terminal solicitará uma senha forte (12+ caracteres) e confirmação, sem gravá-la no código. Esse login poderá entrar na aplicação e abrir /admin (ou o botão "Painel administrativo" no perfil).
Banco de dados
O banco é SQLite. Por padrão, salvo em data/casais.sqlite3 (local ao servidor). Ajuste o caminho com DB_PATH. A pasta do banco precisa ser persistente em hospedagem: se o serviço reiniciar sem volume persistente, os dados podem se perder. Programe backups do arquivo usando o mecanismo de backup do SQLite.
Tabelas: users (cadastro, hash de senha, papel), test_answers (respostas individuais com acesso por user_id), login_attempts (limitação de tentativas). Ninguém consegue ler outro questionário pela API e a API administrativa não devolve respostas.
Publicar para Android e iPhone
O projeto inclui Dockerfile e render.yaml como ponto de partida para provedor compatível com containers e armazenamento persistente.
APP_ENV=production exige SESSION_SECRET (chave longa, gerada aleatoriamente) e usa cookie Secure para HTTPS.
DB_PATH deve apontar para a pasta montada em volume, por exemplo /app/data/casais.sqlite3.
Configure HTTPS na hospedagem, DNS e controle de acesso ao servidor.
Em Android/iPhone, abra a URL HTTPS no navegador e escolha "Adicionar à tela inicial".
Não publique simplesmente em GitHub Pages: GitHub Pages só serve arquivos estáticos e não executa o backend Python/SQLite. Se sua versão anterior está no GitHub Pages, você precisará migrar a publicação para uma hospedagem com servidor e banco persistente.
Segurança e privacidade
Esta é uma base funcional, não uma auditoria completa de segurança. Para produção pública: configure backup, monitoramento, o envio de e-mail para recuperação de senhas (CONFIGURAR_EMAIL.md), política de retenção e privacidade adequada à LGPD; confirme HTTPS e os requisitos do provedor. Dados sobre a intimidade do casal são particularmente delicados.
Salvaguardas já presentes: senha com hash/salt; sessões assinadas e cookie HttpOnly, SameSite e Secure em produção; checagem CSRF; bloqueio simples de tentativas de login; isolamento das respostas por usuário; validações no servidor; administração baseada em papel; exclusão dos dados da conta.
Testes automatizados
pip install pytest httpx
python -m pytest -q test_app.py test_email_recovery.py
Testam acesso negado sem autenticação, cadastro/login, respostas salvas, continuidade, isolamento entre contas, proteção de painel, exportação, exclusão, confirmação de e-mail e recuperação de senha (o envio de e-mail é simulado; nenhuma mensagem real é enviada).
