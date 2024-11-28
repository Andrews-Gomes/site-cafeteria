const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const router = express.Router();
const { v4: uuidv4 } = require('uuid'); // Para gerar UUIDs únicos

const app = express();
const PORT = process.env.DB_PORT || 5432;

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

// Rota para verificar se o telefone já está cadastrado
app.post('/check-phone', async (req, res) => {
    const { phone } = req.body;

    try {
        // Consulta para verificar se o telefone já está cadastrado
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

    // Validação dos campos
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
        // Verificar se o telefone já está cadastrado
        const phoneCheckResult = await pool.query('SELECT * FROM usuarios WHERE telefone = $1', [phone]);

        if (phoneCheckResult.rows.length > 0) {
            return res.status(400).json({ message: 'Número já cadastrado.' });
        }

        // Verificar se o e-mail já está cadastrado
        const emailCheckResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);

        if (emailCheckResult.rows.length > 0) {
            return res.status(400).json({ message: 'E-mail já cadastrado.' });
        }

        // Criar hash da senha
        bcrypt.hash(password, 10, async (err, hashedPassword) => {
            if (err) {
                console.error('Erro ao criar hash da senha:', err);
                return res.status(500).json({ message: 'Erro ao criar senha.' });
            }

            // Inserir novo usuário no banco de dados
            try {
                await pool.query(
                    'INSERT INTO usuarios (nome_completo, email, endereco, senha, telefone) VALUES ($1, $2, $3, $4, $5)',
                    [name, email, address, hashedPassword, phone]
                );

                return res.status(201).json({ success: true, message: 'Usuário registrado com sucesso.' });
            } catch (err) {
                console.error('Erro ao cadastrar usuário:', err);
                return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
            }
        });
    } catch (err) {
        console.error('Erro ao verificar telefone ou e-mail:', err);
        return res.status(500).json({ message: 'Erro ao verificar telefone ou e-mail.' });
    }
});

// Rota de login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Verificar se o usuário existe no banco de dados
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'E-mail não encontrado.' });
        }

        const user = result.rows[0];

        // Comparar a senha fornecida com a senha armazenada
        bcrypt.compare(password, user.senha, (err, isMatch) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).json({ message: 'Erro ao comparar senha.' });
            }

            if (!isMatch) {
                return res.status(400).json({ message: 'Senha incorreta.' });
            }

            try {
                // Gerar o token JWT
                const token = jwt.sign(
                    { id: user.id, timestamp: Date.now(), unique: uuidv4() },
                    'segredo',
                    { expiresIn: '1h' }
                );

                // Armazenar o token em um cookie
                res.cookie('auth_token', token, {
                    httpOnly: true,
                    secure: false,  // Defina como true se estiver usando HTTPS
                    sameSite: 'Strict',
                    maxAge: 3600000 // 1 hora
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

        // Consultar os dados do usuário no banco de dados PostgreSQL
        pool.query('SELECT nome_completo, email, telefone, endereco FROM usuarios WHERE id = $1', [userId], (err, result) => {
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

const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token; // Obtém o token armazenado nos cookies
    if (!token) {
        return res.status(401).json({ message: 'Usuário não autenticado.' });
    }

    jwt.verify(token, 'segredo', (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido.' });
        }

        req.user = decoded; // Armazena os dados decodificados do token no objeto `req`
        next(); // Continua para a próxima função middleware ou rota
    });
};



// Rota para atualizar dados do perfil
app.put('/user-data', authenticateToken, async (req, res) => {
    console.log('Dados recebidos no backend:', req.body);  // Log dos dados recebidos
    const { nome_completo, email, endereco, telefone, senha_atual, nova_senha, confirmar_nova_senha } = req.body;

    // Validações básicas
    const errors = {};

    // Verificar se os campos obrigatórios estão preenchidos corretamente
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

    // Verificar se a nova senha e a confirmação são iguais e se são diferentes da senha atual
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

    // Se houver erros, retornar os erros imediatamente
    if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

    try {
        // Consultar o usuário para verificar o telefone e a senha
        const [userRows] = await connection.promise().query('SELECT telefone, senha, email FROM usuarios WHERE id = ?', [req.user.id]);
        const user = userRows[0]; // Certifique-se de acessar o primeiro registro corretamente
        if (!user) return res.status(404).json({ message: "Usuário não encontrado" });

        // Verificar se a senha atual está correta
        if (!senha_atual || senha_atual === "") {
            return res.status(400).json({ errors: { senha_atual: "Senha atual não fornecida" } });
        }

        const isMatch = await bcrypt.compare(senha_atual, user.senha);
        if (!isMatch) {
            return res.status(400).json({ errors: { senha_atual: "Senha atual incorreta" } });
        }

        // Variáveis para salvar os valores atualizados
        let telefoneAtualizado = telefone || user.telefone;
        let emailAtualizado = email || user.email;
        let senhaAtualizada = user.senha; // Inicializa com a senha atual do banco

        // Verificar se o telefone foi alterado
        if (telefone && telefone !== user.telefone) {
            const [existingPhone] = await connection.promise().query('SELECT id FROM usuarios WHERE telefone = ?', [telefone]);
            if (existingPhone.length > 0 && existingPhone[0].id !== req.user.id) {
                return res.status(400).json({ errors: { telefone: "Telefone já cadastrado por outro usuário" } });
            }
            telefoneAtualizado = telefone;
        }

        // Verificar se o email foi alterado
        if (email && email !== user.email) {
            const [existingEmail] = await connection.promise().query('SELECT id FROM usuarios WHERE email = ?', [email]);
            if (existingEmail.length > 0 && existingEmail[0].id !== req.user.id) {
                return res.status(400).json({ errors: { email: "Email já cadastrado por outro usuário" } });
            }
            emailAtualizado = email;
        }

        // Se a nova senha foi fornecida, atualizar a senha
        if (nova_senha) {
            senhaAtualizada = await bcrypt.hash(nova_senha, 10);
        }

        // Atualizar os dados no banco de dados
        await connection.promise().query(
            'UPDATE usuarios SET nome_completo = ?, email = ?, endereco = ?, telefone = ?, senha = ? WHERE id = ?',
            [nome_completo, emailAtualizado, endereco, telefoneAtualizado, senhaAtualizada, req.user.id]
        );

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
    pool.query('DELETE FROM usuarios WHERE id = $1', [userId], (err, result) => {
        if (err) {
            console.error('Erro ao excluir usuário:', err);
            return res.status(500).send('Erro ao excluir usuário');
        }

        // Verifica se alguma linha foi afetada (usuário deletado)
        if (result.rowCount === 0) {
            return res.status(404).send('Usuário não encontrado');
        }

        // Exclui o cookie de autenticação
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: false, // Se estiver em produção, ajuste para true (HTTPS necessário)
            sameSite: 'Strict',
        });

        // Se o usuário foi deletado e o cookie foi removido, envia sucesso
        res.status(200).send('Conta excluída com sucesso');
    });
});




// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
