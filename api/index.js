// api/index.js — versão enxuta do servidor PackGuard para rodar na Vercel.
//
// Objetivo: testar só as funções client-side (leitura de código de barras e
// OCR da etiqueta) sem quebrar o deploy. As partes de GRAVAÇÃO (upload de
// vídeo em disco + SQLite) foram removidas/temporariamente desativadas aqui
// porque a Vercel não tem disco persistente e o server.js completo
// (better-sqlite3 + multer.diskStorage + app.listen) não roda como função
// serverless. O servidor completo pra uso real (self-hosted) continua em
// server.js/db.js — este arquivo não os usa.
//
// Login também virou em memória (sem SQLite): um usuário fixo só pra passar
// da tela de login. Sessões somem a cada cold start — esperado, é só pra
// teste.

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

app.use(cors());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

/* ---------------------------- Login em memória ---------------------------- */

const TEST_USER = { id: 'teste', nome: 'Usuário de Teste', setor: 'Teste', tipo: 'ADM' };
const TEST_PASSWORD = 'teste123';
const sessions = new Map(); // token -> user

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const user = token && sessions.get(token);
  if (!user) return res.status(401).json({ error: 'Não autenticado.' });
  req.user = user;
  next();
}

app.post('/api/login', (req, res) => {
  const { id, senha } = req.body || {};
  if (id !== TEST_USER.id || senha !== TEST_PASSWORD) {
    return res.status(401).json({
      error: 'Usuário ou senha inválidos. (Modo teste Vercel: login "teste" / senha "teste123")'
    });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, TEST_USER);
  res.json({ token, user: TEST_USER });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = (req.headers['authorization'] || '').slice(7);
  sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now(), mode: 'vercel-test-sem-gravacao' }));
app.get('/api/time', (req, res) => res.json({ serverTime: Date.now() }));

/* --------------------- Gravações: desativadas neste modo --------------------- */
// Aceita o multipart (pra não quebrar o fluxo de "salvar" no front-end depois
// de ler o código de barras / OCR), mas não grava vídeo em disco nem em
// banco — fica só na memória da requisição e é descartado.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

app.post(
  '/api/recordings',
  requireAuth,
  upload.fields([{ name: 'video', maxCount: 1 }, { name: 'label', maxCount: 1 }]),
  (req, res) => {
    res.status(201).json({
      id: req.body.id || crypto.randomUUID(),
      pkg: req.body.pkg,
      createdAt: Date.now(),
      severity: req.body.severity || 'pending',
      videoUrl: null,
      labelImageUrl: null,
      note: 'Gravação não persistida — modo de teste na Vercel (só barcode/OCR por enquanto).'
    });
  }
);

app.get('/api/recordings', requireAuth, (req, res) => res.json([]));
app.get('/api/recordings/:id', requireAuth, (req, res) => res.status(404).json({ error: 'Gravações não são persistidas no modo de teste.' }));
app.patch('/api/recordings/:id', requireAuth, (req, res) => res.status(404).json({ error: 'Gravações não são persistidas no modo de teste.' }));
app.delete('/api/recordings/:id', requireAuth, (req, res) => res.status(404).json({ error: 'Gravações não são persistidas no modo de teste.' }));

module.exports = app;
