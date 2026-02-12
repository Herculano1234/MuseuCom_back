import express from "express";
import cors from "cors";
import compression from 'compression';
import os from 'os';
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import sharp from 'sharp';
import { fileURLToPath } from "url";
import multer from 'multer';
dotenv.config();
const app = express();
// Habilita CORS explicitamente. Defina ALLOWED_ORIGIN na produção para restringir.
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
// Allow larger JSON bodies for non-file endpoints (safe moderate limit)
app.use(express.json({ limit: '10mb' }));

// Enable HTTP response compression to reduce size of large JSON (e.g., base64 images)
app.use(compression());

// --------------------
// MySQL (Aiven) Pool
// --------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  multipleStatements: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: false },
});

// Helper de tratamento de erros padronizado
function handleError(res, err) {
  console.error('Unhandled error:', err && (err.message || err));
  try {
    return res.status(500).json({ error: err && (err.message || String(err)) || 'Erro interno.' });
  } catch (e) {
    console.error('Falha ao enviar erro:', e);
    // em último caso, apenas encerra
    try { res.status(500).end(); } catch (_) {}
  }
}

// Corrigir __dirname (pois em ES Modules ele não existe direto)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Multer setup for handling multipart/form-data (foto, pdf)
// Use memory storage so files are available as buffers and can be stored in DB
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

async function initDatabase() {
  try {
    // Sobe uma pasta (de /src para /)
    const sqlPath = path.join(__dirname, "../init_db.sql");
    const sql = fs.readFileSync(sqlPath, "utf8");

    console.log("🟢 Inicializando o banco de dados...");
    await pool.query(sql);
    
    // Ensure `foto_thumb` column exists to store generated thumbnails
    try {
      await pool.query("ALTER TABLE materiais ADD COLUMN IF NOT EXISTS foto_thumb LONGTEXT");
      console.log('✅ coluna foto_thumb verificada/criada');
    } catch (e) {
      console.warn('⚠️ Não foi possível criar/verificar coluna foto_thumb automaticamente:', e && e.message ? e.message : e);
    }

    console.log("✅ Banco de dados inicializado com sucesso!");
  } catch (err) {
    console.error("❌ Erro ao inicializar o banco de dados:", err.message);
  }
}

// Helper: parse data-url -> { mime, buffer }
function parseDataURL(dataUrl) {
  if (!dataUrl || typeof dataUrl !== 'string') return null;
  const match = dataUrl.match(/^data:(.+);base64,(.*)$/);
  if (!match) return null;
  const mime = match[1];
  const b64 = match[2];
  const buf = Buffer.from(b64, 'base64');
  return { mime, buffer: buf };
}

// Create thumbnail buffer (JPEG) from image buffer
async function makeThumbnailBuffer(buf, maxWidth = 400) {
  try {
    const thumb = await sharp(buf)
      .resize({ width: maxWidth, fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 72 })
      .toBuffer();
    return thumb;
  } catch (e) {
    console.error('Erro ao gerar thumbnail:', e && e.message ? e.message : e);
    return null;
  }
}

// Generate thumbnail data URI from data URL input
async function generateThumbnailDataURL(dataUrl) {
  const parsed = parseDataURL(dataUrl);
  if (!parsed) return null;
  const thumbBuf = await makeThumbnailBuffer(parsed.buffer, 400);
  if (!thumbBuf) return null;
  const b64 = thumbBuf.toString('base64');
  return `data:image/jpeg;base64,${b64}`;
}

// Scan DB for records with foto and no foto_thumb and generate thumbnails (runs at startup)
async function generateMissingThumbnails() {
  try {
    const [rows] = await pool.query("SELECT id, foto FROM materiais WHERE foto IS NOT NULL AND (foto_thumb IS NULL OR foto_thumb = '') LIMIT 200");
    if (!Array.isArray(rows) || rows.length === 0) return;
    console.log(`🔧 Gerando thumbnails para ${rows.length} materiais...`);
    for (const r of rows) {
      try {
        const thumb = await generateThumbnailDataURL(r.foto);
        if (thumb) {
          await pool.query('UPDATE materiais SET foto_thumb = ? WHERE id = ?', [thumb, r.id]);
        }
      } catch (e) {
        console.warn('Falha ao gerar thumbnail para id=' + r.id, e && e.message ? e.message : e);
      }
    }
    console.log('🔧 Thumbnails gerados (startup pass)');
  } catch (e) {
    console.error('Erro ao gerar thumbnails em lote:', e && e.message ? e.message : e);
  }
}
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'please_change_this_refresh_secret';
// Rota para criar usuários (tabela `usuarios`)
app.post('/usuarios', async (req, res) => {
  try {
    const { nome, email, senha, telefone } = req.body || {};
    if (!nome || !email || !senha) {
      return res.status(400).json({ error: 'Campos obrigatórios ausentes.' });
    }

    // Verifica se já existe usuário com o mesmo email
    const [existing] = await pool.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (Array.isArray(existing) && existing.length > 0) {
      return res.status(409).json({ error: 'Email já cadastrado.' });
    }

    const senha_hash = await bcrypt.hash(senha, 10);
    await pool.query('INSERT INTO usuarios (nome, email, senha_hash, telefone) VALUES (?, ?, ?, ?)', [nome, email, senha_hash, telefone || null]);

    return res.status(201).json({ message: 'Usuário criado com sucesso.' });
  } catch (err) {
    console.error('Erro ao criar usuário:', err);
    return res.status(500).json({ error: 'Erro interno ao criar usuário.' });
  }
});

app.get("/ma", async (req, res) => {
  try {
    // Listamos manualmente todas as colunas que queremos ver
    // Isso ignora 'foto' e 'pdf'
    const query = `
      SELECT 
        id, 
        nome, 
        numero_serie, 
        modelo, 
        fabricante, 
        data_fabrico, 
        infor_ad, 
        perfil_fabricante, 
        created_at 
      FROM materiais 
      ORDER BY id DESC
    `;

    const [rows] = await pool.query(query);
    
    // Retorna os dados (Ex: { "nome": "Router TP-Link", "modelo": "Archer C6", ... })
    res.json(rows);
  } catch (err) {
    handleError(res, err);
  }
});
// Listar usuários (protegido: requer token válido)
app.get('/usuarios', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, nome, email, telefone, created_at FROM usuarios ORDER BY id DESC');
    return res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    return res.status(500).json({ error: 'Erro interno ao listar usuários.' });
  }
});

// Obter usuário por id (protegido)
app.get('/usuarios/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'ID inválido.' });
    const [rows] = await pool.query('SELECT id, nome, email, telefone, created_at FROM usuarios WHERE id = ? LIMIT 1', [id]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
    return res.json(rows[0]);
  } catch (err) {
    console.error('Erro ao obter usuário:', err);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});
app.get("/user", async (req, res) => {
  try { const [rows] = await pool.query("SELECT * FROM usuarios ORDER BY id DESC"); res.json(rows); }
  catch (err) { handleError(res, err); }
});
app.get("/tabelas", async (req, res) => {
  try {
    const query = `
      SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
      ORDER BY TABLE_NAME, ORDINAL_POSITION;
    `;
    
    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    handleError(res, err);
  }
});
// Lista materiais (metadados apenas) - EXCLUI campos grandes para evitar payloads enormes
// Lista materiais (metadados apenas) - EXCLUI campos grandes para evitar payloads enormes
// Suporta paginação via query params: ?page=1&limit=24
app.get('/materiais', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const limit = Math.max(1, Math.min(200, parseInt(String(req.query.limit || '24'), 10) || 24));
    const offset = (page - 1) * limit;

    // Total de registros para paginação
    const [[{ total }]] = await pool.query('SELECT COUNT(*) AS total FROM materiais');

    // Include `foto` in the list as requested. Keep a short description for list view.
    const query = `
      SELECT 
        id,
        nome AS nome_material,
        numero_serie,
        modelo,
        fabricante,
        SUBSTRING(infor_ad, 1, 400) AS descricao,
        perfil_fabricante,
        COALESCE(foto_thumb, foto) AS foto,
        created_at
      FROM materiais
      ORDER BY id DESC
      LIMIT ? OFFSET ?
    `;

    const [rows] = await pool.query(query, [limit, offset]);

    const items = Array.isArray(rows) ? rows : [];
    const totalNum = Number(total || 0);
    const totalPages = Math.max(1, Math.ceil(totalNum / limit));

    return res.json({ items, meta: { total: totalNum, page, limit, totalPages } });
  } catch (err) {
    handleError(res, err);
  }
});

// Busca material pelo número de série (retorna registro completo com foto/pdf)
app.get('/materiais/serie/:numero_serie', async (req, res) => {
  try {
    const numero = String(req.params.numero_serie || '').trim();
    if (!numero) return res.status(400).json({ error: 'Número de série ausente.' });
    const [rows] = await pool.query('SELECT * FROM materiais WHERE numero_serie = ? LIMIT 1', [numero]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(404).json({ error: 'Material não encontrado.' });
    return res.json(rows[0]);
  } catch (err) {
    return handleError(res, err);
  }
});

// Rota para obter um material completo (inclui foto/pdf base64) quando necessário
app.get('/materiais/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID inválido.' });
    const [rows] = await pool.query('SELECT * FROM materiais WHERE id = ? LIMIT 1', [id]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(404).json({ error: 'Material não encontrado.' });
    return res.json(rows[0]);
  } catch (err) {
    handleError(res, err);
  }
});

// Dashboard: retorna contagens/indicadores simples usados pelo frontend
// Rota `/dashboard` pública temporariamente para facilitar testes locais.
app.get('/dashboard', async (req, res) => {
  try {
    // Total de usuários
    const [[{ cnt: total_usuarios }]] = await pool.query("SELECT COUNT(*) AS cnt FROM usuarios");
    // Total de materiais
    const [[{ cnt: total_materiais }]] = await pool.query("SELECT COUNT(*) AS cnt FROM materiais");
    // Empréstimos ativos (tabela pode não existir ainda) - tenta retornar 0 se não existir
    let emprestimos_abertos = 0;
    try {
      const [[{ cnt }]] = await pool.query("SELECT COUNT(*) AS cnt FROM emprestimos WHERE status = 'aberto'");
      emprestimos_abertos = Number(cnt || 0);
    } catch (e) {
      // tabela emprestimos não existe — ignora e deixa 0
      emprestimos_abertos = 0;
    }

    return res.json({ total_usuarios: Number(total_usuarios || 0), total_materiais: Number(total_materiais || 0), emprestimos_abertos });
  } catch (err) {
    return handleError(res, err);
  }
});

// Estatísticas agregadas para dashboard (charts)
app.get('/stats', async (req, res) => {
  try {
    // Materials per month (last 12 months)
    const matsByMonthQuery = `
      SELECT DATE_FORMAT(created_at, '%Y-%m') AS month, COUNT(*) AS cnt
      FROM materiais
      GROUP BY month
      ORDER BY month DESC
      LIMIT 12
    `;
    const [matsByMonthRows] = await pool.query(matsByMonthQuery);

    // Materials by fabricante
    const matsByFabQuery = `
      SELECT COALESCE(fabricante, 'Desconhecido') AS fabricante, COUNT(*) AS cnt
      FROM materiais
      GROUP BY fabricante
      ORDER BY cnt DESC
      LIMIT 12
    `;
    const [matsByFabRows] = await pool.query(matsByFabQuery);

    // Try loans per month (may not exist)
    let loansByMonthRows = [];
    try {
      const loansQuery = `
        SELECT DATE_FORMAT(created_at, '%Y-%m') AS month, COUNT(*) AS cnt
        FROM emprestimos
        GROUP BY month
        ORDER BY month DESC
        LIMIT 12
      `;
      const [rows] = await pool.query(loansQuery);
      loansByMonthRows = rows;
    } catch (e) {
      // ignore if table doesn't exist
      loansByMonthRows = [];
    }

    return res.json({
      materials_by_month: Array.isArray(matsByMonthRows) ? matsByMonthRows : [],
      materials_by_fabricante: Array.isArray(matsByFabRows) ? matsByFabRows : [],
      loans_by_month: Array.isArray(loansByMonthRows) ? loansByMonthRows : [],
    });
  } catch (err) {
    return handleError(res, err);
  }
});

// Rota para cadastrar novo material (com upload de foto e pdf)
app.post('/materiais', authenticateToken, upload.fields([{ name: 'foto', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async (req, res) => {
  try {
    console.log('[POST /materiais] called by user:', req.user ? req.user.sub : 'anonymous');
    console.log('[POST /materiais] body keys:', Object.keys(req.body || {}));
    console.log('[POST /materiais] files keys:', Object.keys(req.files || {}));
    // campos textuais vêm em req.body
    const {
      nome,
      modelo,
      fabricante,
      ano_fabrico,
      numero_serie,
      perfil_fabricante,
      informacoes_adicionais
    } = req.body || {};

    if (!nome || !numero_serie) {
      return res.status(400).json({ error: 'Campos obrigatórios ausentes: nome e numero_serie.' });
    }

    // Trata arquivos enviados (memória) e converte para data:URI base64 para salvar no DB
    const files = req.files || {};
    let fotoData = null;
    let fotoThumb = null;
    let pdfData = null;
    if (files.foto && files.foto[0] && files.foto[0].buffer) {
      const f = files.foto[0];
      const b64 = f.buffer.toString('base64');
      fotoData = `data:${f.mimetype};base64,${b64}`;
      // Gera thumbnail (async)
      try {
        const thumb = await generateThumbnailDataURL(fotoData);
        if (thumb) fotoThumb = thumb;
      } catch (e) {
        console.warn('Não foi possível gerar thumbnail no POST:', e && e.message ? e.message : e);
      }
    }
    if (files.pdf && files.pdf[0] && files.pdf[0].buffer) {
      const p = files.pdf[0];
      const b64 = p.buffer.toString('base64');
      pdfData = `data:${p.mimetype};base64,${b64}`;
    }

    // Converte ano_fabrico para data se necessário (usa 1º jan do ano)
    let data_fabrico = null;
    if (ano_fabrico) {
      // se já for uma data, tenta usar; se for apenas ano, cria uma data YYYY-01-01
      if (/^\d{4}$/.test(String(ano_fabrico))) {
        data_fabrico = `${ano_fabrico}-01-01`;
      } else {
        data_fabrico = ano_fabrico;
      }
    }

    // Insere no banco
    const sql = `INSERT INTO materiais (nome, numero_serie, modelo, fabricante, data_fabrico, infor_ad, perfil_fabricante, foto, foto_thumb, pdf) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [nome, numero_serie, modelo || null, fabricante || null, data_fabrico || null, informacoes_adicionais || null, perfil_fabricante || null, fotoData, fotoThumb, pdfData];
    const [result] = await pool.query(sql, params);

    // Busca o registro criado para retornar
    const [rows] = await pool.query('SELECT * FROM materiais WHERE id = ? LIMIT 1', [result.insertId]);
    const created = Array.isArray(rows) && rows.length ? rows[0] : null;

    // Notificação: resposta clara para o front
    return res.status(201).json({ message: 'Material cadastrado com sucesso.', material: created });
  } catch (err) {
    console.error('Erro ao cadastrar material:', err && err.stack ? err.stack : err);
    // Duplicate key (numero_serie) -> ER_DUP_ENTRY
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Número de série já cadastrado.' });
    }
    return res.status(500).json({ error: err && err.message ? String(err.message) : 'Erro ao cadastrar material.' });
  }
});

// Atualizar material por id (aceita JSON com campos a atualizar)
app.put('/materiais/:id', authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID inválido.' });

    // Aceita payload JSON com quaisquer colunas permitidas
    const allowed = ['nome','numero_serie','modelo','fabricante','data_fabrico','infor_ad','perfil_fabricante','foto','pdf'];
    const updates = [];
    const params = [];
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates.push(`${key} = ?`);
        params.push(req.body[key] === '' ? null : req.body[key]);
      }
    }

    // If foto is provided in the update payload, generate a new thumbnail and include it
    if (Object.prototype.hasOwnProperty.call(req.body, 'foto')) {
      try {
        const newFoto = req.body.foto;
        if (newFoto) {
          const newThumb = await generateThumbnailDataURL(newFoto);
          updates.push('foto_thumb = ?');
          params.push(newThumb);
        } else {
          // clearing foto -> clear thumbnail
          updates.push('foto_thumb = ?');
          params.push(null);
        }
      } catch (e) {
        console.warn('Falha ao gerar thumbnail durante UPDATE:', e && e.message ? e.message : e);
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nenhum campo para atualizar.' });
    }

    params.push(id);
    const sql = `UPDATE materiais SET ${updates.join(', ')} WHERE id = ?`;
    const [result] = await pool.query(sql, params);

    // retorna registro atualizado
    const [rows] = await pool.query('SELECT * FROM materiais WHERE id = ? LIMIT 1', [id]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(404).json({ error: 'Material não encontrado.' });
    return res.json({ message: 'Atualizado com sucesso.', material: rows[0] });
  } catch (err) {
    console.error('Erro ao atualizar material:', err && err.stack ? err.stack : err);
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Número de série já cadastrado.' });
    return handleError(res, err);
  }
});

app.get("/", async (req, res) => {
 res.send("Servidor rodando");
});


// Rota de login: valida email + senha
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Campos obrigatórios ausentes.' });
    }

    const [rows] = await pool.query('SELECT id, nome, email, senha_hash, telefone, created_at FROM usuarios WHERE email = ?', [email]);

    if (!Array.isArray(rows) || rows.length === 0) {
      console.log(`[auth/login] no user found for email=${email}`);
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const user = rows[0];
    // Log detalhado do usuário encontrado (NÃO logar senha)
    console.log(`[auth/login] found user -> id=${user.id} nome=${user.nome} email=${user.email}`);
    const match = await bcrypt.compare(password, user.senha_hash);
    if (!match) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    // Não enviar a hash de volta.
    const safeUser = {
      id: user.id,
      nome: user.nome,
      email: user.email,
      telefone: user.telefone,
      created_at: user.created_at
    };

    // Log de depuração: não incluir senha
    console.log(`[auth/login] success login for email=${email} userId=${user.id} nome=${user.nome}`);

    // Gera JWT de acesso e refresh token; armazena refresh token no banco
    // Normaliza o payload garantindo que o `sub` seja sempre uma string numérica
    const accessPayload = { sub: String(user.id) };
    // Log de depuração: emissão de tokens (remover em produção)
    console.log(`[auth/login] issuing tokens for userId=${user.id} nome=${user.nome}`);
    const token = jwt.sign(accessPayload, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ sub: String(user.id) }, JWT_REFRESH_SECRET, { expiresIn: '30d' });

    // calcula expiry para o refresh (MySQL DATETIME no formato YYYY-MM-DD HH:MM:SS)
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const expiresAtSQL = expiresAt.toISOString().slice(0, 19).replace('T', ' ');
    try {
      await pool.query('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, refreshToken, expiresAtSQL]);
    } catch (dbErr) {
      console.error('Erro ao salvar refresh token:', dbErr);
    }

    // Log payload de resposta (safe) antes de enviar
    console.log('[auth/login] response payload:', { id: safeUser.id, nome: safeUser.nome, email: safeUser.email });
    return res.json({ ...safeUser, token, refreshToken });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ error: 'Erro interno ao autenticar.' });
  }
});

// Endpoint para trocar refresh token por novo access token (rotaciona refresh token)
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token ausente.' });

    // Verifica validade do token assinando com o segredo de refresh
    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Refresh token inválido ou expirado.' });
    }
    // Log payload do refresh token
    console.log('[auth/refresh] refresh payload:', payload);
    const userId = Number(payload.sub);
    const [rows] = await pool.query('SELECT id, user_id, revoked, expires_at FROM refresh_tokens WHERE token = ? LIMIT 1', [refreshToken]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(401).json({ error: 'Refresh token não encontrado.' });
    const row = rows[0];
    if (row.revoked) return res.status(401).json({ error: 'Refresh token revogado.' });
    const now = new Date();
    if (new Date(row.expires_at) < now) return res.status(401).json({ error: 'Refresh token expirado.' });

    // Busca dados do usuário para gerar novo access token
    const [userRows] = await pool.query('SELECT id, nome, email, telefone FROM usuarios WHERE id = ?', [userId]);
    if (!Array.isArray(userRows) || userRows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
    const user = userRows[0];

    // Rotaciona: marca o refresh token atual como revogado e cria um novo
    await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?', [row.id]);
    console.log(`[auth/refresh] rotating refresh for userId=${user.id} (oldTokenId=${row.id})`);
    const newRefreshToken = jwt.sign({ sub: String(user.id) }, JWT_REFRESH_SECRET, { expiresIn: '30d' });
    const newExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0,19).replace('T',' ');
    await pool.query('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, newRefreshToken, newExpiresAt]);

    const newAccessToken = jwt.sign({ sub: String(user.id) }, JWT_SECRET, { expiresIn: '15m' });

    return res.json({ token: newAccessToken, refreshToken: newRefreshToken });
  } catch (err) {
    console.error('Erro em /auth/refresh:', err);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// Logout: revoga um refresh token
app.post('/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token ausente.' });

    await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?', [refreshToken]);
    return res.json({ message: 'Logout realizado.' });
  } catch (err) {
    console.error('Erro em /auth/logout:', err);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// Middleware para rotas protegidas
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: 'Token ausente ou formato inválido.' });
  }

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Log do payload recebido (útil para depuração)
    console.log('[auth] token payload:', payload);
    // Normaliza o conteúdo do req.user para evitar ambiguidades (sempre ter id numérico)
    req.user = {
      sub: Number(payload.sub),
      role: payload.role || null,
    };
    console.log(`[auth] set req.user.sub=${req.user.sub} role=${req.user.role}`);
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

// Rota protegida de exemplo: retorna informações do usuário logado
app.get('/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user && Number(req.user.sub);
    console.log(`[GET /me] requested by userId=${userId}`);
    if (!userId || Number.isNaN(userId)) return res.status(400).json({ error: 'Usuário inválido no token.' });

    const [rows] = await pool.query('SELECT id, nome, email, telefone, created_at FROM usuarios WHERE id = ?', [userId]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });

    const u = rows[0];
    console.log('[GET /me] returning user:', { id: u.id, email: u.email });
    return res.json({ id: u.id, nome: u.nome, email: u.email, telefone: u.telefone, created_at: u.created_at });
  } catch (err) {
    console.error('Erro em /me:', err);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// Inicializa o banco (cria tabelas) e depois sobe o servidor
(async () => {
  try {
    await initDatabase();
    // After DB init, generate missing thumbnails in background (blocking startup until done)
    try {
      await generateMissingThumbnails();
    } catch (e) {
      console.warn('Erro ao gerar thumbnails no startup:', e && e.message ? e.message : e);
    }
  } catch (err) {
    console.warn('Continuando sem bloqueio mesmo se initDatabase falhar.');
  }

  app.listen(PORT, () => console.log(`Smart Lab API rodando na porta ${PORT}`));
})();
