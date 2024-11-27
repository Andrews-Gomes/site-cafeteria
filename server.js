const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const router = express.Router();

const app = express();
const PORT = process.env.PORT || 3306; // Use a porta definida pelo Railway
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

const connection = mysql.createConnection({
    host: process.env.DB_HOST,       // Usando a variável de ambiente para o host
    user: process.env.DB_USER,       // Usando a variável de ambiente para o usuário
    password: process.env.DB_PASSWORD, // Usando a variável de ambiente para a senha
    database: process.env.DB_NAME    // Usando a variável de ambiente para o nome do banco
});

connection.connect((err) => {
    if (err) {
      console.error('Erro ao conectar ao banco de dados:', err);
    } else {
      console.log('Conexão com o banco de dados bem-sucedida!');
    }
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

    connection.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Erro ao verificar e-mail:', err);
            return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
        }

        if (result.length > 0) {
            return res.json({ exists: true });  // E-mail já existe
        } else {
            return res.json({ exists: false });  // E-mail não existe
        }
    });
});



// Rota para verificar se o telefone já está cadastrado
app.post('/check-phone', (req, res) => {
    const { phone } = req.body;

    connection.query('SELECT * FROM usuarios WHERE telefone = ?', [phone], (err, result) => {
        if (err) {
            console.error('Erro ao verificar telefone:', err);
            return res.status(500).json({ message: 'Erro ao verificar telefone.' });
        }

        if (result.length > 0) {
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

    connection.query('SELECT * FROM usuarios WHERE telefone = ?', [phone], (err, result) => {
        if (err) {
            console.error('Erro ao verificar telefone:', err);
            return res.status(500).json({ message: 'Erro ao verificar telefone.' });
        }

        if (result.length > 0) {
            return res.status(400).json({ message: 'Número já cadastrado.' });
        }

        connection.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
            if (err) {
                console.error('Erro ao verificar e-mail:', err);
                return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
            }

            if (result.length > 0) {
                return res.status(400).json({ message: 'E-mail já cadastrado.' });
            }

            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Erro ao criar hash da senha:', err);
                    return res.status(500).json({ message: 'Erro ao criar senha.' });
                }

                connection.query(
                    'INSERT INTO usuarios (nome_completo, email, endereco, senha, telefone) VALUES (?, ?, ?, ?, ?)',
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

    connection.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Erro ao fazer login:', err);
            return res.status(500).json({ message: 'Erro ao fazer login.' });
        }

        if (result.length === 0) {
            return res.status(400).json({ message: 'E-mail não encontrado.' });
        }

        const user = result[0];
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

        connection.query('SELECT nome_completo, email, telefone, endereco FROM usuarios WHERE id = ?', [userId], (err, results) => {
            if (err) {
                console.error('Erro ao buscar dados do usuário:', err);
                return res.status(500).json({ message: 'Erro ao buscar dados do usuário.' });
            }

            if (results.length === 0) {
                return res.status(404).json({ message: 'Usuário não encontrado.' });
            }

            res.json(results[0]);
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
    //console.log('Dados recebidos no backend:', req.body);  // Log dos dados recebidos
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

    // Deleta o usuário do banco de dados
    connection.query('DELETE FROM usuarios WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Erro ao excluir usuário:', err);
            return res.status(500).send('Erro ao excluir usuário');
        }

        // Se o usuário foi deletado, envia sucesso
        res.status(200).send('Conta excluída com sucesso');
    });
});




// Iniciar o servidor
//app.listen(port, () => {
  //  console.log(`Servidor rodando em http://localhost:${port}`);
//});

