document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginFormData');
    const registerForm = document.getElementById('registerFormData');
    const loginFormContainer = document.getElementById('loginForm');
    const registerFormContainer = document.getElementById('registerForm');
    const registerLink = document.getElementById('registerLink');
    const loginLink = document.getElementById('loginLink');

    // Alternância entre login e registro
    registerLink.addEventListener('click', function (e) {
        e.preventDefault();
        loginFormContainer.style.display = 'none';
        registerFormContainer.style.display = 'block';
    });

    loginLink.addEventListener('click', function (e) {
        e.preventDefault();
        loginFormContainer.style.display = 'block';
        registerFormContainer.style.display = 'none';
    });

    // Função para validar e exibir mensagens de erro
    function setError(element, message) {
        const errorElement = document.getElementById(element + 'Error');
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        document.getElementById(element).style.borderColor = 'red';
    }

    function clearError(element) {
        const errorElement = document.getElementById(element + 'Error');
        errorElement.style.display = 'none';
        document.getElementById(element).style.borderColor = '';
    }

    // Função de validação de formulário de login
    function validateLoginForm(email, password) {
        let valid = true;
        clearError('loginEmail');
        clearError('loginPassword');

        // Verificação de email
        if (!/\S+@\S+\.\S+/.test(email)) {
            setError('loginEmail', 'E-mail inválido');
            valid = false;
        }

        // Verificação de senha
        if (password.length < 8) {
            setError('loginPassword', 'Senha inválida');
            valid = false;
        }

        return valid;
    }

    // Função para login
    loginForm.addEventListener('submit', function (e) {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        if (validateLoginForm(email, password)) {
            fetch('/login', {  // Corrigido para a URL correta no servidor
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.token) {
                    localStorage.setItem('token', data.token);
                    window.location.href = '/';
                } else {
                    // Exibir mensagem de erro quando o login falhar
                    if (data.message === 'E-mail não encontrado.') {
                        setError('loginEmail', 'E-mail inválido');
                    } else if (data.message === 'Senha incorreta.') {
                        setError('loginPassword', 'Senha incorreta');
                    } else {
                        alert(data.message || 'Erro inesperado');
                    }
                }
            })
            .catch(error => {
                alert('Erro ao fazer login: ' + error.message);
            });
        }
    });

    // Função de validação de registro
    function validateRegisterForm(name, email, address, password, confirmPassword) {
        let valid = true;
        clearError('registerName');
        clearError('registerEmail');
        clearError('registerAddress');
        clearError('registerPassword');
        clearError('confirmPassword');

        if (name.length <= 3) {
            setError('registerName', 'Nome deve ter mais de 3 caracteres');
            valid = false;
        }
        if (!/\S+@\S+\.\S+/.test(email)) {
            setError('registerEmail', 'E-mail inválido');
            valid = false;
        }
        if (address.length <= 5) {
            setError('registerAddress', 'Endereço deve ter mais de 5 caracteres');
            valid = false;
        }
        if (password.length < 8) {
            setError('registerPassword', 'A senha deve ter mais de 8 caracteres');
            valid = false;
        }
        if (password !== confirmPassword) {
            setError('confirmPassword', 'As senhas não coincidem');
            valid = false;
        }

        return valid;
    }

    // Função para registrar
    registerForm.addEventListener('submit', function (e) {
        e.preventDefault();
        const name = document.getElementById('registerName').value;
        const email = document.getElementById('registerEmail').value;
        const address = document.getElementById('registerAddress').value;
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (validateRegisterForm(name, email, address, password, confirmPassword)) {
            fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, email, address, password, confirmPassword })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Usuário registrado com sucesso!');

                    // Alternar para o formulário de login automaticamente
                    loginFormContainer.style.display = 'block';
                    registerFormContainer.style.display = 'none';
                } else {
                    if (data.message === 'E-mail já cadastrado.') {
                        setError('registerEmail', data.message); // Mostrar erro embaixo do campo de e-mail
                    } else {
                        alert(data.message || 'Erro ao registrar');
                    }
                }
            })
            .catch(error => {
                alert('Erro ao registrar: ' + error.message);
            });
        }
    });
});
