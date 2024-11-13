const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // Importar o módulo path
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

// Configuração do banco de dados MySQL
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',  // Altere com seu usuário
    password: 'Salmo91@123',  // Altere com sua senha
    database: 'cafeteria'  // Altere com o nome do seu banco de dados
});

// Conectar ao banco de dados
connection.connect(err => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        return;
    }
    console.log('Conexão com o banco de dados MySQL bem-sucedida!');
});

// Middleware para processar os dados JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir arquivos estáticos das pastas 'paginas' e 'scripts'
app.use('/scripts', express.static(path.join(__dirname, 'scripts')));
app.use(express.static(path.join(__dirname, 'paginas')));

// Rota para servir a página inicial (index.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'paginas', 'index.html'));  // Caminho correto para o arquivo index.html
});

// Rota de registro
app.post('/register', (req, res) => {
    const { name, email, address, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'As senhas não coincidem.' });
    }
    if (!name || name.length < 3) {
        return res.status(400).json({ message: 'Nome completo deve ter mais de 3 caracteres.' });
    }
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
        return res.status(400).json({ message: 'E-mail inválido.' });
    }
    if (!address || address.length < 5) {
        return res.status(400).json({ message: 'Endereço deve ter mais de 5 caracteres.' });
    }
    if (password.length < 8) {
        return res.status(400).json({ message: 'A senha deve ter mais de 8 caracteres.' });
    }

    // Verificar se o e-mail já está cadastrado
    connection.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Erro ao verificar e-mail:', err);
            return res.status(500).json({ message: 'Erro ao verificar e-mail.' });
        }

        if (result.length > 0) {
            return res.status(400).json({ message: 'E-mail já cadastrado.' });
        }

        // Hash da senha
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Erro ao criar hash da senha:', err);
                return res.status(500).json({ message: 'Erro ao criar senha.' });
            }

            // Inserir no banco de dados
            connection.query('INSERT INTO usuarios (nome_completo, email, endereco, senha) VALUES (?, ?, ?, ?)', 
                [name, email, address, hashedPassword], (err, result) => {
                    if (err) {
                        console.error('Erro ao cadastrar usuário:', err);
                        return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
                    }

                    res.status(201).json({ success: true, message: 'Usuário registrado com sucesso.' });
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

        bcrypt.compare(password, user.senha, (err, isMatch) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).json({ message: 'Erro ao comparar senha.' });
            }

            if (!isMatch) {
                return res.status(400).json({ message: 'Senha incorreta.' });
            }

            // Gerar o token JWT
            const token = jwt.sign({ id: user.id }, 'segredo', { expiresIn: '1h' });
            res.json({ token });
        });
    });
});

// Inicializar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando na porta http://localhost:${port}`);
});
