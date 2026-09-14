# PackGuard — Servidor (Node + SQLite)

Servidor de armazenamento para o app de gravação de embalagens. O servidor
Node serve a página do PackGuard (pasta `public/`) e a API na mesma porta.

Exige **login**. Cada usuário grava e vê apenas o **setor** dele — os vídeos
ficam em pastas separadas por setor no disco (`uploads/<setor>/`), e a
listagem no app só mostra gravações do setor do usuário logado. Usuários do
tipo **ADM** veem todos os setores e podem gerenciar usuários.

## Instalar e rodar

```bash
cd packguard-server
npm install
npm start
```

O servidor sobe em `http://localhost:9000` por padrão.

## Primeiro acesso

Na primeira vez que o servidor roda (banco vazio), ele cria automaticamente
um usuário administrador:

```
login: admin
senha: admin123
```

**Troque essa senha assim que possível** — clique em "Alterar senha" no menu
lateral (disponível para qualquer usuário logado, inclusive o admin padrão).

Depois de logar como admin, vá em **Usuários** para cadastrar o time:

- **ID**: login que a pessoa vai usar (ex: `joao`)
- **Nome**: nome de exibição
- **Setor**: define tanto a pasta onde os vídeos daquele usuário são salvos
  quanto o que ele consegue ver no Banco de Vídeos. Setores são só texto
  livre — não precisa cadastrar antes, a pasta é criada automaticamente na
  primeira gravação daquele setor.
- **Tipo**: `Comum` (só vê/grava no próprio setor) ou `Administrador` (vê
  todos os setores, gerencia usuários, e é o único que pode excluir vídeos
  marcados como protegidos/críticos).

## Alterar a própria senha

Qualquer usuário logado (comum ou admin) pode trocar a própria senha pelo
botão "Alterar senha" no menu lateral — pede a senha atual e a nova senha.
Não existe recuperação de senha esquecida nesta versão beta: se alguém
esquecer, um admin precisa recriar o usuário (excluir e criar de novo).

## Excluir vídeos protegidos

Vídeos críticos (modelo divergente, item faltando, gravação interrompida) ou
marcados manualmente como prioridade nunca são excluídos automaticamente.
Só um usuário **ADM** consegue excluir esse tipo de vídeo — e mesmo assim,
precisa ativar o toggle **"Modo Administrador"** em Configurações antes (some
automaticamente para quem não é ADM). Isso é verificado no servidor
(baseado em quem está logado), não só na tela — não dá pra burlar trocando
algo no navegador.

## Nome dos arquivos salvos

Cada vídeo é salvo em disco com o número do pacote no próprio nome do
arquivo — por exemplo, `ORD-163589__rec_1725298123_ab12c.webm`. Isso é
proposital: se o banco de dados falhar ou precisar de recuperação manual,
dá pra achar o vídeo de um pacote específico direto no explorador de
arquivos / busca do sistema operacional, sem depender do SQLite estar
funcionando.

## Expor com cloudflared

Com o servidor rodando em `localhost:9000`, num terminal separado:

```bash
cloudflared tunnel --url http://localhost:9000
# ou, com túnel nomeado configurado:
cloudflared tunnel run <nome-do-tunnel>
```

**Atenção com uploads grandes:** o plano gratuito do Cloudflare Tunnel tem um
limite de ~100MB por upload. Se as gravações passarem disso, prefira acessar
o servidor pelo IP local da rede (ex: `http://192.168.x.x:9000`) na estação
que grava, e deixe o túnel só para acesso remoto de consulta/administração.

## Estrutura de dados

Tabela `users`: `id` (login), `nome`, `setor`, `tipo` (`ADM`/`COMUM`),
`senha_hash` (scrypt, nunca em texto puro), `created_at`.

Tabela `sessions`: token de sessão (válido por 30 dias), vinculado ao usuário.

Tabela `recordings` (colunas principais): `id`, `pkg` (número do pacote),
`created_at`, `duration_sec`, `video_path` (inclui a subpasta do setor e o
pkg no nome do arquivo), `classification`, `severity`, `protected`,
`retention_days`, `setor`, `created_by` (id do usuário que gravou).

Tabela `deletion_log`: histórico de exclusões (quem excluiu, quando e por quê).

## Rotas da API

Autenticação: `Authorization: Bearer <token>` em todas as rotas exceto
`/api/login`, `/api/health` e `/api/time`.

- `POST /api/login` — `{id, senha}` → `{token, user}`
- `POST /api/logout` — invalida a sessão atual
- `GET  /api/me` — dados do usuário logado
- `POST /api/change-password` — `{senhaAtual, novaSenha}` — troca a própria senha
- `GET  /api/users` (ADM) — lista usuários
- `POST /api/users` (ADM) — cria usuário `{id, nome, setor, tipo, senha}`
- `DELETE /api/users/:id` (ADM) — remove usuário
- `POST /api/recordings` — multipart/form-data → cria gravação (setor vem do usuário logado, não do cliente)
- `GET  /api/recordings` — lista (COMUM vê só o próprio setor; ADM vê tudo ou filtra com `?setor=`)
- `PATCH /api/recordings/:id` — atualiza classificação/proteção (só do próprio setor, exceto ADM)
- `DELETE /api/recordings/:id` — exclui (vídeos protegidos exigem ADM)
- `GET  /api/deletion-log` (ADM) — histórico de exclusões
- `GET  /uploads/<setor>/<arquivo>` — arquivo de vídeo/etiqueta

**Nota de segurança (beta):** a listagem (`/api/recordings`) respeita o
setor do usuário, mas o arquivo bruto em `/uploads/...` é servido como
arquivo estático — quem tiver a URL exata consegue abri-la sem checagem de
setor. Suficiente para o teste beta interno; se isso for para produção com
dados sensíveis entre setores, vale trocar por uma rota autenticada de
streaming.

## Retenção automática

A cada hora (e uma vez ao iniciar), o servidor exclui — arquivo e registro —
qualquer vídeo não protegido cujo prazo (`created_at + retention_days`) já
tenha expirado.

## Produção

Este servidor é um ponto de partida para o beta. Para produção, considere:
- Rodar atrás de HTTPS (proxy reverso com Nginx/Caddy)
- Recuperação de senha esquecida (hoje só um admin recriando o usuário)
- Endurecer o acesso a `/uploads` (streaming autenticado por setor)
- Trocar SQLite por Postgres/MySQL se o volume crescer muito
- Backup periódico da pasta `uploads/` e do arquivo `data/packguard.db`
