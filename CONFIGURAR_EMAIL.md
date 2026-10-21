# Recuperação de senha por e-mail

Esta atualização adiciona e-mail ao cadastro e ao perfil, confirmação de endereço,
“Esqueci minha senha” e o contato do administrador no rodapé.
O login continua usando celular. A atualização do banco ocorre automaticamente,
preservando usuários e respostas existentes. Faça um backup do SQLite antes de publicar.

## Configurar no Render

Em seu serviço, abra **Environment** e adicione as variáveis abaixo. Use os dados
do serviço de e-mail que você escolher. Não coloque senhas no GitHub.

| Variável | Valor |
| --- | --- |
| `PUBLIC_BASE_URL` | `https://testes-para-casais.onrender.com` |
| `SMTP_HOST` | Servidor SMTP do seu provedor |
| `SMTP_PORT` | `587` para STARTTLS ou `465` para TLS direto |
| `SMTP_SSL` | `false` para porta 587 ou `true` para porta 465 |
| `SMTP_USER` | Usuário de envio |
| `SMTP_PASSWORD` | Credencial de envio/senha de aplicativo fornecida pelo provedor |
| `SMTP_FROM` | Endereço de remetente autorizado pelo provedor |

Salve e faça uma nova implantação. Alguns provedores têm opções sem custo,
sujeitas a limites e regras. Não há integração paga de SMS ou WhatsApp nesta versão.
Confirme se seu plano de hospedagem permite saída SMTP antes de escolher o provedor;
serviços gratuitos do Render podem restringir essas portas. Se houver bloqueio,
será necessário usar um provedor de e-mail com API HTTPS e adaptar o envio.

Sem as variáveis, o cadastro e o login continuam funcionando. O e-mail fica
pendente de confirmação; a confirmação e a recuperação informam que o envio está
indisponível até que o administrador configure o provedor.
Uma falha de entrega SMTP é registrada nos logs sem dados pessoais, senhas ou links.
A pessoa pode tentar novamente mais tarde, respeitando o limite de tentativas.

## Como testar depois de configurar

1. Entre com uma conta existente e abra **Meu perfil → E-mail de recuperação**.
2. Informe o e-mail e a senha atual; clique em **Salvar e enviar confirmação**.
3. Abra o e-mail e clique no link. No site, clique em **Confirmar meu e-mail**.
4. Saia da conta. Em **Já tenho cadastro**, clique em **Esqueci minha senha**.
5. Informe o e-mail confirmado, abra o link recebido e escolha uma nova senha.
6. Entre com o celular e a nova senha; confira se os testes anteriores continuam salvos.
7. O mesmo link não deve funcionar uma segunda vez. Os links de recuperação
   expiram em 30 minutos; os de confirmação, em 24 horas.

Contas antigas sem e-mail precisam adicioná-lo enquanto ainda conseguem entrar.
Se a pessoa já perdeu a senha e não tem e-mail confirmado, deve contatar o
administrador, que precisará verificar a identidade antes de qualquer intervenção.
O link no rodapé abre o WhatsApp do administrador e não envia mensagens sozinho.

## Testes automatizados

Instale as dependências de `requirements.txt` e, no ambiente de desenvolvimento,
`pytest` e `httpx`. Execute `python -m pytest test_app.py test_email_recovery.py -q`.
Os testes simulam o provedor SMTP; não enviam mensagens reais.
