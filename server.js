const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const router = express.Router();

const app = express();
const port = process.env.DB_PORT || 5432;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Conexão com o banco de dados PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432,
    ssl: {
      rejectUnauthorized: false // Permitir conexão SSL
    }
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        return;
    }
    console.log('Conectado ao banco de dados PostgreSQL!');
});

// Servir arquivos estáticos das pastas 'paginas' e 'scripts'
app.use('/scripts', express.static(path.join(__dirname, 'scripts')));
app.use(express.static(path.join(__dirname, 'paginas')));

// Rota para servir a página inicial
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'paginas', 'index.html'));
});

// Rota para verificar se o e-mail já está cadastrado
app.post('/check-email', (req, res) => {
    const { email } = req.body;

    pool.query('SELECT * FROM usuarios WHERE email = $1', [email], (err, result) => {
        if (err) {
            console.error('Erro ao verificar e-mail:', err);
            return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
        }

        if (result.rows.length > 0) {
            return res.json({ exists: true });  // E-mail já existe
        } else {
            return res.json({ exists: false });  // E-mail não existe
        }
    });
});

// Rota para verificar se o telefone já está cadastrado
app.post('/check-phone', (req, res) => {
    const { phone } = req.body;

    pool.query('SELECT * FROM usuarios WHERE telefone = $1', [phone], (err, result) => {
        if (err) {
            console.error('Erro ao verificar telefone:', err);
            return res.status(500).json({ message: 'Erro ao verificar telefone.' });
        }

        if (result.rows.length > 0) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    });
});

// Rota de registro
app.post('/register', (req, res) => {
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

    pool.query('SELECT * FROM usuarios WHERE telefone = $1', [phone], (err, result) => {
        if (err) {
            console.error('Erro ao verificar telefone:', err);
            return res.status(500).json({ message: 'Erro ao verificar telefone.' });
        }

        if (result.rows.length > 0) {
            return res.status(400).json({ message: 'Número já cadastrado.' });
        }

        pool.query('SELECT * FROM usuarios WHERE email = $1', [email], (err, result) => {
            if (err) {
                console.error('Erro ao verificar e-mail:', err);
                return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
            }

            if (result.rows.length > 0) {
                return res.status(400).json({ message: 'E-mail já cadastrado.' });
            }

            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Erro ao criar hash da senha:', err);
                    return res.status(500).json({ message: 'Erro ao criar senha.' });
                }

                pool.query(
                    'INSERT INTO usuarios (nome_completo, email, endereco, senha, telefone) VALUES ($1, $2, $3, $4, $5)',
                    [name, email, address, hashedPassword, phone],
                    (err) => {
                        if (err) {
                            console.error('Erro ao cadastrar usuário:', err);
                            return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
                        }

                        res.status(201).json({ success: true, message: 'Usuário registrado com sucesso.' });
                    }
                );
            });
        });
    });
});

// Rota de login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    pool.query('SELECT * FROM usuarios WHERE email = $1', [email], (err, result) => {
        if (err) {
            console.error('Erro ao verificar e-mail:', err);
            return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
        }

        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'E-mail ou senha incorretos.' });
        }

        const user = result.rows[0];

        bcrypt.compare(password, user.senha, (err, isMatch) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).json({ message: 'Erro ao verificar senha.' });
            }

            if (!isMatch) {
                return res.status(400).json({ message: 'E-mail ou senha incorretos.' });
            }

            // Gerar token JWT
            const token = jwt.sign({ userId: user.id }, 'secrettoken', { expiresIn: '1h' });

            res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

            return res.json({ success: true, message: 'Login bem-sucedido.' });
        });
    });
});

// Middleware de autenticação
function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'Token não encontrado. Por favor, faça login.' });
    }

    jwt.verify(token, 'secrettoken', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido.' });
        }

        req.user = user;
        next();
    });
}

// Rota para obter dados do perfil
app.get('/profile', authenticateToken, (req, res) => {
    const userId = req.user.userId;

    pool.query('SELECT * FROM usuarios WHERE id = $1', [userId], (err, result) => {
        if (err) {
            console.error('Erro ao buscar dados do usuário:', err);
            return res.status(500).json({ message: 'Erro ao buscar dados do usuário.' });
        }

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        const user = result.rows[0];
        res.json({
            nome_completo: user.nome_completo,
            email: user.email,
            endereco: user.endereco,
            telefone: user.telefone
        });
    });
});

console.log({
    nome_completo,
    emailAtualizado,
    endereco,
    telefoneAtualizado,
    senhaAtualizada,
    userId: req.user.id
});


// Rota para atualizar dados do perfil
app.put('/user-data', authenticateToken, async (req, res) => {
    const { nome_completo, email, endereco, telefone, senha_atual, nova_senha, confirmar_nova_senha } = req.body;

    // Validações básicas
    const errors = {};

    if (!nome_completo || nome_completo.length <= 3) {
        errors.nome_completo = "Nome completo deve ter mais de 3 caracteres";
    }

    if (!email || !/\S+@\S+\.\S+/.test(email)) {
        errors.email = "Email inválido";
    }

    if (!endereco || endereco.length <= 5 || !/\d/.test(endereco)) {
        errors.endereco = "Endereço deve ter mais de 5 caracteres e conter um número";
    }

    if (!telefone || !/^\(\d{2}\) \d{5}-\d{4}$/.test(telefone)) {
        errors.telefone = "Telefone inválido. Use o formato (XX) XXXXX-XXXX";
    }

    if (!senha_atual) {
        errors.senha_atual = "Senha atual é obrigatória";
    }

    if (nova_senha || confirmar_nova_senha) {
        if (nova_senha !== confirmar_nova_senha) {
            errors.confirmar_nova_senha = "As senhas não correspondem";
        }
        if (nova_senha && nova_senha.length < 8) {
            errors.nova_senha = "A nova senha deve ter pelo menos 8 caracteres";
        }
        if (nova_senha === senha_atual) {
            errors.nova_senha = "A nova senha não pode ser igual à senha atual";
        }
    }

    if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

    try {
        const client = await pool.connect();

        // Consultar o usuário
        const userQuery = 'SELECT telefone, senha, email FROM usuarios WHERE id = $1';
        const userResult = await client.query(userQuery, [req.user.id]);

        if (userResult.rows.length === 0) {
            client.release();
            return res.status(404).json({ message: "Usuário não encontrado" });
        }

        const user = userResult.rows[0];

        const isMatch = await bcrypt.compare(senha_atual, user.senha);
        if (!isMatch) {
            client.release();
            return res.status(400).json({ errors: { senha_atual: "Senha atual incorreta" } });
        }

        let telefoneAtualizado = telefone || user.telefone;
        let emailAtualizado = email || user.email;
        let senhaAtualizada = user.senha;

        // Verificar telefone
        if (telefone && telefone !== user.telefone) {
            const phoneQuery = 'SELECT id FROM usuarios WHERE telefone = $1';
            const phoneResult = await client.query(phoneQuery, [telefone]);

            if (phoneResult.rows.length > 0 && phoneResult.rows[0].id !== req.user.id) {
                client.release();
                return res.status(400).json({ errors: { telefone: "Telefone já cadastrado por outro usuário" } });
            }
            telefoneAtualizado = telefone;
        }

        // Verificar email
        if (email && email !== user.email) {
            const emailQuery = 'SELECT id FROM usuarios WHERE email = $1';
            const emailResult = await client.query(emailQuery, [email]);

            if (emailResult.rows.length > 0 && emailResult.rows[0].id !== req.user.id) {
                client.release();
                return res.status(400).json({ errors: { email: "Email já cadastrado por outro usuário" } });
            }
            emailAtualizado = email;
        }

        if (nova_senha) {
            senhaAtualizada = await bcrypt.hash(nova_senha, 10);
        }

        const updateQuery = `
            UPDATE usuarios 
            SET nome_completo = $1, email = $2, endereco = $3, telefone = $4, senha = $5
            WHERE id = $6
        `;
        await client.query(updateQuery, [nome_completo, emailAtualizado, endereco, telefoneAtualizado, senhaAtualizada, req.user.id]);

        client.release();

        res.json({ message: "Perfil atualizado com sucesso" });
    } catch (err) {
        console.error('Erro ao atualizar perfil:', err);
        res.status(500).json({ message: "Erro ao atualizar perfil" });
    }
});

// Rota para excluir a conta
app.delete('/delete-account', authenticateToken, (req, res) => {
    const userId = req.user.id; // Obtém o ID do usuário a partir do token decodificado

    // Deleta o usuário do banco de dados PostgreSQL
    pool.query('DELETE FROM usuarios WHERE id = $1', [userId], (err, results) => {
        if (err) {
            console.error('Erro ao excluir usuário:', err);
            return res.status(500).send('Erro ao excluir usuário');
        }

        // Se o usuário foi deletado, envia sucesso
        res.status(200).send('Conta excluída com sucesso');
    });
});

