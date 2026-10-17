# Testar o WebApp v5 no Android — sem instalar Python

1. Pelo Chrome do tablet, entre em https://replit.com/import e faça login ou crie conta.
2. Escolha a opção **ZIP** e selecione este arquivo ZIP salvo em Downloads.
3. Quando o projeto abrir, verifique se a pasta principal mostra main.py, requirements.txt, .replit e static/.
4. Clique em **Run/Executar**. O arquivo .replit já contém o comando de instalação e execução.
5. Abra a aba **Preview/Prévia** para acessar a tela inicial do WebApp.
6. Para testar administração, abra a ferramenta Shell do Replit e execute
   `python create_admin.py --phone 11999999999 --name "Administrador Geral"`
   substituindo pelo seu celular com DDD. Digite e confirme uma senha com pelo menos 12 caracteres.
7. Na aba Preview, acesse o link exibido pela prévia, acrescente `/admin` ao fim, e entre com celular e senha.

**Notas importantes:**
- Este pacote é para testar com participantes fictícios. Evite incluir dados pessoais ou íntimos reais nesta instância de desenvolvimento.
- O Replit pode requerer cadastro, limites de uso ou pagamento de acordo com o plano.
- Banco SQLite em instância de desenvolvimento não substitui o armazenamento persistente adequado para produção.
- Não é preciso publicar a aplicação para testar no ambiente de desenvolvimento.
- Se a importação abrir um assistente, instrua: "Importe o projeto sem alterar seus arquivos; inicie pelo comando de .replit e exiba a prévia".
- Para produção, utilize o pacote v5 original e hospedagem com disco persistente, HTTPS, segredo de sessão e backups.
