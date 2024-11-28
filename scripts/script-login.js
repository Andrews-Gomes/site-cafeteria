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
                                alert(data.message || 'Erro inesperado');
                            }
                        });
                    }
                })
                .catch(error => {
                    alert('Erro ao fazer login: ' + error.message);
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

    // Função de validação de registro
    function validateRegisterForm(name, email, address, phone, password, confirmPassword) {
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
        fetch('/check-phone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ phone })
        })
            .then(response => response.json())
            .then(data => {
                if (data.exists) {
                    setError('registerPhone', 'Número já cadastrado');
                    valid = false;
                }
            });

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
        const phone = document.getElementById('registerPhone').value;
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (validateRegisterForm(name, email, address, phone, password, confirmPassword)) {
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
                        successAlert.style.display = 'block'; // Exibe a mensagem de sucesso
                        registerForm.reset();  // Reseta o formulário de registro

                        // Esconder a mensagem de sucesso após 3 segundos e então alternar os formulários
                        setTimeout(() => {
                            successAlert.style.display = 'none'; // Esconde a mensagem de sucesso

                            // Alternar para o formulário de login
                            loginFormContainer.style.display = 'block';
                            registerFormContainer.style.display = 'none';
                        }, 3000); // A mensagem desaparecerá após 3 segundos

                    } else {
                        if (data.message === 'E-mail já cadastrado.') {
                            setError('registerEmail', data.message); // Mostrar erro embaixo do campo de e-mail
                        } else if (data.message === 'Número já cadastrado') {
                            setError('registerPhone', 'Número já cadastrado');
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
