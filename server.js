const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const router = express.Router();

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Configuração do Pool PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  ssl: {
    rejectUnauthorized: false // Isso permite a conexão SSL
  }
});

// Verificação da conexão
pool.connect((err, client, release) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err);
    return;
  }
  console.log('Conectado ao banco de dados!');
  release();
});

// Servir arquivos estáticos das pastas 'paginas' e 'scripts'
app.use('/scripts', express.static(path.join(__dirname, 'scripts')));
app.use(express.static(path.join(__dirname, 'paginas')));

// Rota para servir a página inicial
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'paginas', 'index.html'));
});

// Rota para verificar se o e-mail já está cadastrado
app.post('/check-email', async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      return res.json({ exists: true });
    } else {
      return res.json({ exists: false });
    }
  } catch (err) {
    console.error('Erro ao verificar e-mail:', err);
    return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
  }
});

// Rota para verificar se o telefone já está cadastrado
app.post('/check-phone', async (req, res) => {
  const { phone } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE telefone = $1', [phone]);
    if (result.rows.length > 0) {
      return res.json({ exists: true });
    } else {
      return res.json({ exists: false });
    }
  } catch (err) {
    console.error('Erro ao verificar telefone:', err);
    return res.status(500).json({ message: 'Erro ao verificar telefone.' });
  }
});

// Rota de registro
app.post('/register', async (req, res) => {
  const { name, email, address, password, confirmPassword, phone } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'As senhas não coincidem.' });
  }
  if (!name || name.length < 3) {
    return res.status(400).json({ message: 'Nome completo deve ter mais de 3 caracteres.' });
  }
  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ message: 'E-mail inválido.' });
  }
  if (!address || address.length < 5 || !/\d/.test(address)) {
    return res.status(400).json({ message: 'Endereço deve ter mais de 5 caracteres e conter um número.' });
  }
  if (!phone || !/^\(\d{2}\) \d{5}-\d{4}$/.test(phone)) {
    return res.status(400).json({ message: 'Telefone inválido. Use o formato (XX) XXXXX-XXXX.' });
  }

  try {
    const resultPhone = await pool.query('SELECT * FROM usuarios WHERE telefone = $1', [phone]);
    if (resultPhone.rows.length > 0) {
      return res.status(400).json({ message: 'Número já cadastrado.' });
    }

    const resultEmail = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (resultEmail.rows.length > 0) {
      return res.status(400).json({ message: 'E-mail já cadastrado.' });
    }

    bcrypt.hash(password, 10, async (err, hashedPassword) => {
      if (err) {
        console.error('Erro ao criar hash da senha:', err);
        return res.status(500).json({ message: 'Erro ao criar senha.' });
      }

      try {
        await pool.query(
          'INSERT INTO usuarios (nome_completo, email, endereco, senha, telefone) VALUES ($1, $2, $3, $4, $5)',
          [name, email, address, hashedPassword, phone]
        );
        res.status(201).json({ success: true, message: 'Usuário registrado com sucesso.' });
      } catch (err) {
        console.error('Erro ao cadastrar usuário:', err);
        return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
      }
    });
  } catch (err) {
    console.error('Erro ao verificar e-mail ou telefone:', err);
    return res.status(500).json({ message: 'Erro ao verificar e-mail ou telefone.' });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'E-mail não encontrado.' });
    }

    const user = result.rows[0];

    bcrypt.compare(password, user.senha, (err, isMatch) => {
      if (err) {
        console.error('Erro ao comparar senha:', err);
        return res.status(500).json({ message: 'Erro ao comparar senha.' });
      }

      if (!isMatch) {
        return res.status(400).json({ message: 'Senha incorreta.' });
      }

      try {
        const token = jwt.sign({ id: user.id }, 'segredo', { expiresIn: '1h' });
        res.cookie('auth_token', token, {
          httpOnly: true,
          secure: false,
          sameSite: 'Strict',
          maxAge: 3600000
        });
        res.json({ success: true, message: 'Login bem-sucedido.' });
      } catch (err) {
        console.error('Erro ao gerar token:', err);
        res.status(500).json({ message: 'Erro ao gerar token.' });
      }
    });
  } catch (err) {
    console.error('Erro ao fazer login:', err);
    return res.status(500).json({ message: 'Erro ao fazer login.' });
  }
});

// Rota para verificar autenticação
app.get('/auth-check', (req, res) => {
  const token = req.cookies.auth_token;

  if (!token) {
    return res.json({ authenticated: false });
  }

  try {
    const decoded = jwt.verify(token, 'segredo');
    res.json({ authenticated: true, userId: decoded.id });
  } catch {
    res.json({ authenticated: false });
  }
});

// Rota para logout
app.get('/logout', (req, res) => {
  res.clearCookie('auth_token', { httpOnly: true, secure: true, sameSite: 'Strict' });
  res.json({ success: true, message: 'Logout realizado com sucesso.' });
});

// Rota para retornar os dados do usuário logado
app.get('/user-data', async (req, res) => {
  const token = req.cookies.auth_token;

  if (!token) {
    return res.status(401).json({ message: 'Usuário não autenticado.' });
  }

  try {
    const decoded = jwt.verify(token, 'segredo');
    const userId = decoded.id;

    const result = await pool.query('SELECT nome_completo, email, telefone, endereco FROM usuarios WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao buscar dados do usuário:', err);
    return res.status(500).json({ message: 'Erro ao buscar dados do usuário.' });
  }
});

// Rota para atualizar dados do perfil
app.put('/user-data', authenticateToken, async (req, res) => {
  const { nome_completo, email, endereco, telefone, senha_atual, nova_senha, confirmar_nova_senha } = req.body;

  const errors = {};

  if (!nome_completo || nome_completo.length <= 3) {
    errors.nome_completo = "Nome completo deve ter mais de 3 caracteres";
  }

  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    errors.email = "E-mail inválido";
  }

  if (nova_senha && nova_senha !== confirmar_nova_senha) {
    errors.senha = "As senhas não coincidem";
  }

  if (senha_atual) {
    const result = await pool.query('SELECT senha FROM usuarios WHERE id = $1', [req.user.id]);
    const validPassword = bcrypt.compareSync(senha_atual, result.rows[0].senha);
    if (!validPassword) {
      errors.senha_atual = "Senha atual incorreta";
    }
  }

  if (Object.keys(errors).length > 0) {
    return res.status(400).json(errors);
  }

  // Atualizar perfil
  try {
    const updateQuery = 'UPDATE usuarios SET nome_completo = $1, email = $2, endereco = $3, telefone = $4' +
    (nova_senha ? ', senha = $5' : '') +
    ' WHERE id = $6';

    const params = nova_senha ? [nome_completo, email, endereco, telefone, await bcrypt.hash(nova_senha, 10), req.user.id] :
    [nome_completo, email, endereco, telefone, req.user.id];

    await pool.query(updateQuery, params);

    res.json({ success: true, message: 'Perfil atualizado com sucesso.' });
  } catch (err) {
    console.error('Erro ao atualizar perfil:', err);
    return res.status(500).json({ message: 'Erro ao atualizar perfil.' });
  }
});

// Função para verificar o token
function authenticateToken(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ message: "Token de autenticação não fornecido." });

  jwt.verify(token, 'segredo', (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido" });
    req.user = user;
    next();
  });
}

// Iniciar o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
