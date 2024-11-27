const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { Client } = require('pg'); // Importando o pacote PostgreSQL
const router = express.Router();

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Configuração do banco de dados PostgreSQL usando variáveis de ambiente
const client = new Client({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Conectar ao banco de dados
client.connect(err => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        return;
    }
    console.log('Conexão com o banco de dados PostgreSQL bem-sucedida!');
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

    client.query('SELECT * FROM usuarios WHERE email = $1', [email], (err, result) => {
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

    client.query('SELECT * FROM usuarios WHERE telefone = $1', [phone], (err, result) => {
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

    client.query('SELECT * FROM usuarios WHERE telefone = $1', [phone], (err, result) => {
        if (err) {
            console.error('Erro ao verificar telefone:', err);
            return res.status(500).json({ message: 'Erro ao verificar telefone.' });
        }

        if (result.rows.length > 0) {
            return res.status(400).json({ message: 'Número já cadastrado.' });
        }

        client.query('SELECT * FROM usuarios WHERE email = $1', [email], (err, result) => {
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

                client.query(
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

    client.query('SELECT * FROM usuarios WHERE email = $1', [email], (err, result) => {
        if (err) {
            console.error('Erro ao fazer login:', err);
            return res.status(500).json({ message: 'Erro ao fazer login.' });
        }

        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'E-mail não encontrado.' });
        }

        const user = result.rows[0];
        const { v4: uuidv4 } = require('uuid');

        bcrypt.compare(password, user.senha, (err, isMatch) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).json({ message: 'Erro ao comparar senha.' });
            }

            if (!isMatch) {
                return res.status(400).json({ message: 'Senha incorreta.' });
            }

            try {
                const token = jwt.sign(
                    { id: user.id, timestamp: Date.now(), unique: uuidv4() },
                    'segredo',
                    { expiresIn: '1h' }
                );
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
    });
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
app.get('/user-data', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) {
        return res.status(401).json({ message: 'Usuário não autenticado.' });
    }

    jwt.verify(token, 'segredo', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido.' });
        }

        const userId = decoded.id;

        client.query('SELECT nome_completo, email, telefone, endereco FROM usuarios WHERE id = $1', [userId], (err, result) => {
            if (err) {
                console.error('Erro ao buscar dados do usuário:', err);
                return res.status(500).json({ message: 'Erro ao buscar dados do usuário.' });
            }

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Usuário não encontrado.' });
            }

            res.json(result.rows[0]);
        });
    });
});

// Rota para editar os dados do usuário
app.post('/edit-profile', (req, res) => {
    const { email, name, phone, address, newPassword, confirmNewPassword } = req.body;
    const token = req.cookies.auth_token;

    if (!token) {
        return res.status(401).json({ message: 'Usuário não autenticado.' });
    }

    jwt.verify(token, 'segredo', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido.' });
        }

        const userId = decoded.id;

        if (!name || name.length < 3) {
            return res.status(400).json({ message: 'Nome completo deve ter mais de 3 caracteres.' });
        }

        if (newPassword && newPassword !== confirmNewPassword) {
            return res.status(400).json({ message: 'As novas senhas não coincidem.' });
        }

        if (newPassword) {
            bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Erro ao criar hash da senha:', err);
                    return res.status(500).json({ message: 'Erro ao criar nova senha.' });
                }

                client.query(
                    'UPDATE usuarios SET nome_completo = $1, email = $2, telefone = $3, endereco = $4, senha = $5 WHERE id = $6',
                    [name, email, phone, address, hashedPassword, userId],
                    (err) => {
                        if (err) {
                            console.error('Erro ao atualizar dados do usuário:', err);
                            return res.status(500).json({ message: 'Erro ao atualizar dados.' });
                        }

                        res.json({ success: true, message: 'Dados atualizados com sucesso.' });
                    }
                );
            });
        } else {
            client.query(
                'UPDATE usuarios SET nome_completo = $1, email = $2, telefone = $3, endereco = $4 WHERE id = $5',
                [name, email, phone, address, userId],
                (err) => {
                    if (err) {
                        console.error('Erro ao atualizar dados do usuário:', err);
                        return res.status(500).json({ message: 'Erro ao atualizar dados.' });
                    }

                    res.json({ success: true, message: 'Dados atualizados com sucesso.' });
                }
            );
        }
    });
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
