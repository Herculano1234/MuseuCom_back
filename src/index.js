import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
dotenv.config();
const app = express();
app.use(cors());
// Allow larger JSON bodies for non-file endpoints (safe moderate limit)
app.use(express.json({ limit: '10mb' }));

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

// Corrigir __dirname (pois em ES Modules ele não existe direto)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function initDatabase() {
  try {
    // Sobe uma pasta (de /src para /)
    const sqlPath = path.join(__dirname, "../init_db.sql");
    const sql = fs.readFileSync(sqlPath, "utf8");

    console.log("🟢 Inicializando o banco de dados...");
    await pool.query(sql);
    
    console.log("✅ Banco de dados inicializado com sucesso!");
  } catch (err) {
    console.error("❌ Erro ao inicializar o banco de dados:", err.message);
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
  } catch (err) {
    console.warn('Continuando sem bloqueio mesmo se initDatabase falhar.');
  }

  app.listen(PORT, () => console.log(`Smart Lab API rodando na porta ${PORT}`));
})();
