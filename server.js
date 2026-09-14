// server.js — API do PackGuard
// Recebe o vídeo gravado no navegador (multipart/form-data), salva o arquivo
// no disco do servidor (./uploads/<setor>) e grava o caminho + metadados no
// SQLite. Exige login; cada usuário só vê e grava no seu próprio setor,
// exceto administradores, que veem todos os setores.

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 9000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias

app.use(cors());
app.use(express.json());

// Log de diagnóstico: toda requisição que chega ao servidor fica registrada
// com hora exata de chegada e de conclusão.
app.use((req, res, next) => {
  const start = Date.now();
  const size = req.headers['content-length'] ? `${(req.headers['content-length'] / 1024 / 1024).toFixed(2)}MB` : '?';
  console.log(`[req] ${new Date().toISOString()} chegou: ${req.method} ${req.originalUrl} (${size}) de ${req.ip}`);
  res.on('finish', () => {
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    console.log(`[req] ${new Date().toISOString()} concluída: ${req.method} ${req.originalUrl} — HTTP ${res.statusCode} em ${elapsed}s`);
  });
  next();
});

// Serve os vídeos estaticamente. NOTA DE SEGURANÇA (beta): quem tiver a URL
// exata de um arquivo consegue acessá-lo diretamente, sem checagem de setor
// — o controle de acesso por setor vale para a LISTAGEM (/api/recordings),
// não para o arquivo bruto. Suficiente para o teste beta interno; se isso
// for para produção com dados sensíveis entre setores, vale endurecer com
// uma rota autenticada de streaming em vez de arquivo estático.
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(PUBLIC_DIR));

/* ---------------------------- Senhas e sessões ---------------------------- */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const check = crypto.scryptSync(String(password), salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Não autenticado.' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session || session.expires_at < Date.now()) {
    return res.status(401).json({ error: 'Sessão expirada ou inválida. Faça login novamente.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });
  req.user = { id: user.id, nome: user.nome, setor: user.setor, tipo: user.tipo };
  req.sessionToken = token;
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.tipo !== 'ADM') {
    return res.status(403).json({ error: 'Apenas administradores podem realizar esta ação.' });
  }
  next();
}

/* Cria um usuário administrador padrão no primeiro uso, se ainda não existir
   nenhum usuário — sem isso, ninguém conseguiria logar pra criar o primeiro. */
(function seedDefaultAdmin() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (count === 0) {
    db.prepare(
      'INSERT INTO users (id, nome, setor, tipo, senha_hash, created_at) VALUES (?,?,?,?,?,?)'
    ).run('admin', 'Administrador', 'Geral', 'ADM', hashPassword('admin123'), Date.now());
    console.log('[setup] Usuário administrador padrão criado — login: admin / senha: admin123');
    console.log('[setup] IMPORTANTE: troque essa senha assim que possível (crie um novo ADM e remova este, ou implemente troca de senha).');
  }
})();

/* ---------------------------- Autenticação ---------------------------- */

app.post('/api/login', (req, res) => {
  const { id, senha } = req.body || {};
  if (!id || !senha) return res.status(400).json({ error: 'Informe usuário e senha.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(String(id).trim());
  if (!user || !verifyPassword(senha, user.senha_hash)) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .run(token, user.id, now, now + SESSION_DURATION_MS);
  res.json({ token, user: { id: user.id, nome: user.nome, setor: user.setor, tipo: user.tipo } });
});

app.post('/api/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.sessionToken);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

// Troca a própria senha — qualquer usuário logado pode usar, exige a senha
// atual correta. Diferente da criação de usuários (ADM only): aqui é
// autoatendimento.
app.post('/api/change-password', requireAuth, (req, res) => {
  const { senhaAtual, novaSenha } = req.body || {};
  if (!senhaAtual || !novaSenha) return res.status(400).json({ error: 'Informe a senha atual e a nova senha.' });
  if (String(novaSenha).length < 4) return res.status(400).json({ error: 'A nova senha precisa ter pelo menos 4 caracteres.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user || !verifyPassword(senhaAtual, user.senha_hash)) {
    return res.status(401).json({ error: 'Senha atual incorreta.' });
  }
  db.prepare('UPDATE users SET senha_hash = ? WHERE id = ?').run(hashPassword(novaSenha), req.user.id);
  res.json({ ok: true });
});

/* ---------------------------- Usuários (ADM) ---------------------------- */

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, nome, setor, tipo, created_at FROM users ORDER BY nome').all();
  res.json(rows);
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { id, nome, setor, tipo, senha } = req.body || {};
  if (!id || !nome || !setor || !senha) return res.status(400).json({ error: 'Preencha id, nome, setor e senha.' });
  if (!['ADM', 'COMUM'].includes(tipo)) return res.status(400).json({ error: 'Tipo deve ser ADM ou COMUM.' });
  const cleanId = String(id).trim();
  const existing = db.prepare('SELECT id FROM users WHERE id = ?').get(cleanId);
  if (existing) return res.status(409).json({ error: 'Já existe um usuário com esse ID.' });
  db.prepare('INSERT INTO users (id, nome, setor, tipo, senha_hash, created_at) VALUES (?,?,?,?,?,?)')
    .run(cleanId, nome, setor, tipo, hashPassword(senha), Date.now());
  res.status(201).json({ id: cleanId, nome, setor, tipo });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Você não pode excluir seu próprio usuário.' });
  const existing = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Usuário não encontrado.' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* ---------------------------- Gravações ---------------------------- */

function sanitizeSectorFolder(setor) {
  const clean = String(setor || 'geral').trim().replace(/[^a-zA-Z0-9 _-]/g, '').replace(/\s+/g, '_');
  return clean || 'geral';
}

// Usado no nome do arquivo salvo em disco — permite achar o vídeo de um
// pacote específico direto na pasta, mesmo que o banco de dados esteja
// indisponível ou corrompido.
function sanitizeForFilename(pkg) {
  const clean = String(pkg || 'pacote').trim().replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60);
  return clean || 'pacote';
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = sanitizeSectorFolder(req.user && req.user.setor);
    const dir = path.join(UPLOAD_DIR, folder);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const id = req.body.id || crypto.randomUUID();
    const pkgPart = sanitizeForFilename(req.body.pkg);
    if (file.fieldname === 'label') {
      const ext = file.mimetype && file.mimetype.includes('png') ? 'png' : 'jpg';
      return cb(null, `${pkgPart}__${id}_label.${ext}`);
    }
    const ext = file.mimetype && file.mimetype.includes('webm') ? 'webm' : 'mp4';
    cb(null, `${pkgPart}__${id}.${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 1024 * 1024 * 1024 } }); // 1GB por vídeo

function toApi(row) {
  return {
    id: row.id,
    pkg: row.pkg,
    serial: row.serial,
    createdAt: row.created_at,
    durationSec: row.duration_sec,
    videoUrl: row.video_path,
    mimeType: row.mime_type,
    classification: row.classification,
    severity: row.severity,
    notes: row.notes,
    protected: !!row.protected,
    retentionDays: row.retention_days,
    updatedAt: row.updated_at,
    trackingCode: row.tracking_code,
    senderAddress: row.sender_address,
    recipientAddress: row.recipient_address,
    labelImageUrl: row.label_image_path || null,
    setor: row.setor,
    createdBy: row.created_by
  };
}

function deleteRecordingRow(row, deletedBy, reason) {
  const filePath = path.join(__dirname, row.video_path.replace(/^\//, ''));
  fs.unlink(filePath, () => {});
  if (row.label_image_path) {
    const labelPath = path.join(__dirname, row.label_image_path.replace(/^\//, ''));
    fs.unlink(labelPath, () => {});
  }
  db.prepare('DELETE FROM recordings WHERE id = ?').run(row.id);
  db.prepare(
    `INSERT INTO deletion_log (recording_id, pkg, classification, deleted_at, deleted_by, reason)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(row.id, row.pkg, row.classification, Date.now(), deletedBy, reason || 'não especificado');
}

app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));
app.get('/api/time', (req, res) => res.json({ serverTime: Date.now() }));

// Cria uma gravação — sempre gravada no setor do usuário autenticado (não é
// o cliente quem escolhe o setor, evita que alguém grave "no setor errado"
// de propósito ou por engano).
app.post('/api/recordings', requireAuth, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'label', maxCount: 1 }]), (req, res) => {
  try {
    const id = req.body.id || crypto.randomUUID();
    const pkg = req.body.pkg;
    const videoFile = req.files && req.files.video && req.files.video[0];
    const labelFile = req.files && req.files.label && req.files.label[0];
    if (!pkg) return res.status(400).json({ error: 'Campo "pkg" (número do pacote) é obrigatório.' });
    if (!videoFile) return res.status(400).json({ error: 'Arquivo de vídeo ausente no upload.' });

    const existing = db.prepare('SELECT * FROM recordings WHERE id = ?').get(id);
    if (existing) {
      fs.unlink(videoFile.path, () => {});
      if (labelFile) fs.unlink(labelFile.path, () => {});
      return res.status(200).json(toApi(existing));
    }

    const folder = sanitizeSectorFolder(req.user.setor);
    const record = {
      id,
      pkg,
      serial: req.body.serial || null,
      created_at: parseInt(req.body.createdAt, 10) || Date.now(),
      duration_sec: parseInt(req.body.durationSec, 10) || 0,
      video_path: `/uploads/${folder}/${videoFile.filename}`,
      mime_type: videoFile.mimetype,
      classification: req.body.classification || null,
      severity: req.body.severity || 'pending',
      notes: req.body.notes || '',
      protected: req.body.protected === 'true' || req.body.protected === '1' ? 1 : 0,
      retention_days: parseInt(req.body.retentionDays, 10) || 90,
      updated_at: Date.now(),
      tracking_code: req.body.trackingCode || null,
      sender_address: req.body.senderAddress || null,
      recipient_address: req.body.recipientAddress || null,
      label_image_path: labelFile ? `/uploads/${folder}/${labelFile.filename}` : null,
      setor: req.user.setor,
      created_by: req.user.id
    };

    db.prepare(
      `INSERT INTO recordings
        (id, pkg, serial, created_at, duration_sec, video_path, mime_type, classification, severity, notes, protected, retention_days, updated_at, tracking_code, sender_address, recipient_address, label_image_path, setor, created_by)
       VALUES
        (@id, @pkg, @serial, @created_at, @duration_sec, @video_path, @mime_type, @classification, @severity, @notes, @protected, @retention_days, @updated_at, @tracking_code, @sender_address, @recipient_address, @label_image_path, @setor, @created_by)`
    ).run(record);

    res.status(201).json(toApi(record));
  } catch (err) {
    console.error('[POST /api/recordings]', err);
    res.status(500).json({ error: 'Falha ao salvar a gravação no servidor.' });
  }
});

// Lista gravações — usuário COMUM só vê o próprio setor; ADM vê todos (ou
// filtra por ?setor= se quiser um setor específico).
app.get('/api/recordings', requireAuth, (req, res) => {
  const { pkg, severity, setor } = req.query;
  let sql = 'SELECT * FROM recordings WHERE 1=1';
  const params = [];
  if (req.user.tipo !== 'ADM') {
    sql += ' AND setor = ?';
    params.push(req.user.setor);
  } else if (setor) {
    sql += ' AND setor = ?';
    params.push(setor);
  }
  if (pkg) { sql += ' AND pkg LIKE ?'; params.push(`%${pkg}%`); }
  if (severity) { sql += ' AND severity = ?'; params.push(severity); }
  sql += ' ORDER BY created_at DESC';
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(toApi));
});

app.get('/api/recordings/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Gravação não encontrada.' });
  if (req.user.tipo !== 'ADM' && row.setor !== req.user.setor) {
    return res.status(403).json({ error: 'Você só pode ver gravações do seu setor.' });
  }
  res.json(toApi(row));
});

app.patch('/api/recordings/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Gravação não encontrada.' });
  if (req.user.tipo !== 'ADM' && row.setor !== req.user.setor) {
    return res.status(403).json({ error: 'Você só pode alterar gravações do seu setor.' });
  }

  const fields = {};
  ['classification', 'severity', 'notes'].forEach((f) => {
    if (req.body[f] !== undefined) fields[f] = req.body[f];
  });
  if (req.body.protected !== undefined) fields.protected = req.body.protected ? 1 : 0;
  if (req.body.trackingCode !== undefined) fields.tracking_code = req.body.trackingCode;
  if (req.body.senderAddress !== undefined) fields.sender_address = req.body.senderAddress;
  if (req.body.recipientAddress !== undefined) fields.recipient_address = req.body.recipientAddress;
  if (Object.keys(fields).length === 0) return res.status(400).json({ error: 'Nenhum campo para atualizar.' });

  fields.updated_at = Date.now();
  const setClause = Object.keys(fields).map((k) => `${k}=@${k}`).join(', ');
  db.prepare(`UPDATE recordings SET ${setClause} WHERE id=@id`).run({ ...fields, id: req.params.id });

  const updated = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  res.json(toApi(updated));
});

// Exclui — vídeos protegidos só podem ser excluídos por administradores.
app.delete('/api/recordings/:id', requireAuth, requireAdmin, (req, res) => {
  const row = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Gravação não encontrada.' });
  deleteRecordingRow(row, `admin:${req.user.id}`, req.body && req.body.reason);
  res.json({ ok: true });
});

app.get('/api/deletion-log', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM deletion_log ORDER BY deleted_at DESC LIMIT 300').all();
  res.json(rows);
});

/* ------------------- Varredura de retenção automática ------------------- */
function runRetentionSweep() {
  const now = Date.now();
  const rows = db.prepare('SELECT * FROM recordings WHERE protected = 0').all();
  let deletedCount = 0;
  rows.forEach((row) => {
    const deadline = row.created_at + row.retention_days * 24 * 60 * 60 * 1000;
    if (now >= deadline) {
      deleteRecordingRow(row, 'system-retention', 'Prazo de retenção expirado');
      deletedCount++;
    }
  });
  if (deletedCount > 0) console.log(`[retenção] ${deletedCount} vídeo(s) excluído(s) automaticamente.`);
}
setInterval(runRetentionSweep, 60 * 60 * 1000);
runRetentionSweep();

const server = app.listen(PORT, () => {
  console.log(`PackGuard server rodando em http://localhost:${PORT}`);
  console.log(`Página do app: http://localhost:${PORT}/`);
  console.log(`Vídeos salvos em: ${UPLOAD_DIR} (uma subpasta por setor)`);
  console.log(`Banco SQL em: ${path.join(__dirname, 'data', 'packguard.db')}`);
});

server.requestTimeout = 0;
server.headersTimeout = 0;
server.timeout = 0;
