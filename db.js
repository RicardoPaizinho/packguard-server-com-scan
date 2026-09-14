// db.js — inicializa o banco SQL (SQLite) e cria as tabelas se não existirem.
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'packguard.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS recordings (
  id                TEXT PRIMARY KEY,
  pkg               TEXT NOT NULL,
  serial            TEXT,
  created_at        INTEGER NOT NULL,
  duration_sec      INTEGER NOT NULL,
  video_path        TEXT NOT NULL,   -- caminho relativo no disco do servidor (ex: /uploads/<setor>/<id>.webm)
  mime_type         TEXT,
  classification    TEXT,
  severity          TEXT DEFAULT 'pending',   -- pending | ok | attention | critical
  notes             TEXT,
  protected         INTEGER DEFAULT 0,        -- 1 = nunca excluir automaticamente
  retention_days    INTEGER DEFAULT 90,
  updated_at        INTEGER,
  tracking_code     TEXT,             -- código de rastreio lido da etiqueta (ex: AB012345678BR)
  sender_address    TEXT,             -- bloco "Remetente" lido por OCR da etiqueta
  recipient_address TEXT,             -- bloco "Destinatário" lido por OCR da etiqueta
  label_image_path  TEXT,             -- caminho da foto da etiqueta salva em disco (opcional)
  setor             TEXT,             -- setor do usuário que gravou — define a pasta e a visibilidade
  created_by        TEXT              -- id do usuário que fez a gravação
);
CREATE INDEX IF NOT EXISTS idx_recordings_pkg      ON recordings(pkg);
CREATE INDEX IF NOT EXISTS idx_recordings_severity ON recordings(severity);
CREATE INDEX IF NOT EXISTS idx_recordings_created  ON recordings(created_at);

CREATE TABLE IF NOT EXISTS deletion_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  recording_id    TEXT,
  pkg             TEXT,
  classification  TEXT,
  deleted_at      INTEGER,
  deleted_by      TEXT,   -- 'system-retention' | 'admin:<id>' | 'user:<id>'
  reason          TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,   -- login do usuário
  nome        TEXT NOT NULL,
  setor       TEXT NOT NULL,      -- também define a pasta de armazenamento dos vídeos
  tipo        TEXT NOT NULL DEFAULT 'COMUM',  -- 'ADM' | 'COMUM'
  senha_hash  TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`);

// Migração leve: se o banco já existia antes destas colunas serem criadas
// (ex: de uma versão anterior do PackGuard), adiciona o que estiver
// faltando sem perder dados. Isso PRECISA rodar antes de criar índices
// sobre essas colunas — um banco antigo não tem "setor"/"tracking_code"
// ainda, e tentar indexar uma coluna inexistente derruba o servidor.
const existingCols = db.prepare(`PRAGMA table_info(recordings)`).all().map(c => c.name);
const wantedCols = {
  tracking_code: 'TEXT',
  sender_address: 'TEXT',
  recipient_address: 'TEXT',
  label_image_path: 'TEXT',
  setor: 'TEXT',
  created_by: 'TEXT'
};
Object.entries(wantedCols).forEach(([col, type]) => {
  if (!existingCols.includes(col)) {
    db.exec(`ALTER TABLE recordings ADD COLUMN ${col} ${type}`);
    console.log(`[migração] coluna "${col}" adicionada à tabela recordings.`);
  }
});

// Só agora, com as colunas garantidamente presentes, cria os índices que
// dependem delas.
db.exec(`
CREATE INDEX IF NOT EXISTS idx_recordings_tracking ON recordings(tracking_code);
CREATE INDEX IF NOT EXISTS idx_recordings_setor    ON recordings(setor);
`);

module.exports = db;
