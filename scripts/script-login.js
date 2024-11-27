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
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password })
            })
                .then(response => {
                    if (response.ok) {
                        // Redirecionar para a página inicial após login bem-sucedido
                        window.location.href = '/';
                    } else {
                        return response.json().then(data => {
                            if (data.message === 'E-mail não encontrado.') {
                                setError('loginEmail', 'E-mail inválido');
                            } else if (data.message === 'Senha incorreta.') {
                                setError('loginPassword', 'Senha incorreta');
                            } else {
                                setError('loginEmail', data.message || 'Erro inesperado');
                            }
                        });
                    }
                })
                .catch(error => {
                    setError('loginEmail', 'Erro ao fazer login: ' + error.message);
                });
        }
    });

    // Função para aplicar a máscara de telefone
    function applyPhoneMask(event) {
        let phone = event.target.value;
        phone = phone.replace(/\D/g, ''); // Remove qualquer caractere que não seja número
        if (phone.length <= 2) {
            phone = `(${phone}`;
        } else if (phone.length <= 7) {
            phone = `(${phone.slice(0, 2)}) ${phone.slice(2)}`;
        } else {
            phone = `(${phone.slice(0, 2)}) ${phone.slice(2, 7)}-${phone.slice(7, 11)}`;
        }
        event.target.value = phone;
    }

    // Adicionando a máscara de telefone no campo
    const phoneField = document.getElementById('registerPhone');
    phoneField.addEventListener('input', applyPhoneMask);

    // Função de validação de registro (assíncrona)
    async function validateRegisterForm(name, email, address, phone, password, confirmPassword) {
        let valid = true;
        clearError('registerName');
        clearError('registerEmail');
        clearError('registerAddress');
        clearError('registerPhone');
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

        // Validação do endereço (deve conter pelo menos um número)
        if (address.length <= 5 || !/\d/.test(address)) {
            setError('registerAddress', 'Endereço deve ter mais de 5 caracteres e conter um número');
            valid = false;
        }

        // Validação do telefone
        if (!/^\(\d{2}\) \d{5}-\d{4}$/.test(phone)) {
            setError('registerPhone', 'Formato inválido. Use: (99) 99999-9999');
            valid = false;
        }

        // Verificar se o número de telefone já está cadastrado
        const phoneCheckResponse = await fetch('/check-phone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ phone }),
        });
        const phoneData = await phoneCheckResponse.json();
        if (phoneData.exists) {
            setError('registerPhone', 'Número já cadastrado');
            valid = false;
        }

        // Verificar se o e-mail já está cadastrado
        const emailCheckResponse = await fetch('/check-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        const emailData = await emailCheckResponse.json();
        if (emailData.exists) {
            setError('registerEmail', 'E-mail já cadastrado');
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
    registerForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        const name = document.getElementById('registerName').value;
        const email = document.getElementById('registerEmail').value;
        const address = document.getElementById('registerAddress').value;
        const phone = document.getElementById('registerPhone').value;
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        const isValid = await validateRegisterForm(name, email, address, phone, password, confirmPassword);
        if (isValid) {
            fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, email, address, phone, password, confirmPassword })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const successAlert = document.getElementById('registerSuccessAlert');
                        successAlert.style.display = 'block';
    
                        // Limpar os campos do formulário de registro
                        registerForm.reset();
    
                        // Alternar para o formulário de login automaticamente após alguns segundos
                        setTimeout(() => {
                            successAlert.style.display = 'none'; // Esconde o alerta
                            loginFormContainer.style.display = 'block';
                            registerFormContainer.style.display = 'none';
                        }, 3000); // Tempo em milissegundos (3 segundos)
                    } else {
                        if (data.message === 'E-mail já cadastrado.') {
                            setError('registerEmail', data.message);
                        } else if (data.message === 'Número já cadastrado') {
                            setError('registerPhone', 'Número já cadastrado');
                        } else {
                            setError('registerEmail', 'Erro ao registrar');
                        }
                    }
                })
                .catch(error => {
                    setError('registerEmail', 'Erro ao registrar: ' + error.message);
                });
        }
    });
});

