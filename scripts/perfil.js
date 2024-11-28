document.addEventListener('DOMContentLoaded', () => {
    fetch('/user-data', { credentials: 'include' }) // Inclui cookies na requisição
        .then(response => {
            if (!response.ok) throw new Error('Erro ao carregar dados do perfil');
            return response.json();
        })
        .then(data => {
            document.getElementById('nome_completo').value = data.nome_completo;
            document.getElementById('email').value = data.email;
            document.getElementById('endereco').value = data.endereco;
            document.getElementById('telefone').value = data.telefone;
            document.getElementById('userName').textContent = `Olá, ${data.nome_completo}`;
        })
        .catch(err => console.error(err.message));

    // Inicializa o botão "Salvar Alterações" como desabilitado
    document.getElementById('saveChangesBtn').disabled = true;
});

document.getElementById('perfil-form').addEventListener('submit', (event) => {
    event.preventDefault();

    const formData = new FormData(event.target);

    // Verifique os valores antes de enviar
    console.log('Dados do formulário:', Object.fromEntries(formData.entries()));

    // Verificar se a senha atual está vazia e adicionar o valor vazio se necessário
    if (!formData.get('senha_atual')) {
        formData.set('senha_atual', '');  // Garante que um valor vazio seja enviado, não undefined
    }

    const data = Object.fromEntries(formData.entries());

    fetch('/user-data', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(data)
    })
        .then(response => response.json())
        .then(result => {
            if (result.errors) {
                Object.keys(result.errors).forEach(key => {
                    const errorField = document.getElementById(`error-${key}`);
                    const inputField = document.getElementById(key);
                    errorField.textContent = result.errors[key];
                    errorField.classList.remove('d-none');
                    inputField.classList.add('is-invalid');
                });
            } else {
                // Exibir a mensagem de sucesso
                const successAlert = document.getElementById('successAlert');
                successAlert.style.display = 'block';  // Mostrar a div de sucesso

                // Ocultar a mensagem de sucesso após 3 segundos
                setTimeout(() => {
                    successAlert.style.display = 'none';
                    window.location.reload();  // Recarregar a página após mostrar a mensagem de sucesso
                }, 2000);
            }
        })
        .catch(err => console.error('Erro ao atualizar perfil:', err));
});


// Lógica para editar dados
document.getElementById('editDataBtn').addEventListener('click', () => {
    document.querySelectorAll('#perfil-form input').forEach(input => input.disabled = false);
    document.getElementById('editDataBtn').style.display = 'none';
    document.getElementById('cancelEditBtn').style.display = 'block';

    // Habilita o botão "Salvar Alterações" ao editar
    document.getElementById('saveChangesBtn').disabled = false;
});

// Função para buscar os dados do usuário
function fetchUserData() {
    fetch('/user-data', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + getCookie('token') // Enviar token para autenticação
        }
    })
        .then(response => response.json())
        .then(data => {
            // Preencher os campos com os dados obtidos do banco
            document.getElementById('nome_completo').value = data.nome_completo;
            document.getElementById('email').value = data.email;
            document.getElementById('endereco').value = data.endereco;
            document.getElementById('telefone').value = data.telefone;
        })
        .catch(error => console.error('Erro ao carregar os dados:', error));
}

// Função para formatar o telefone enquanto o usuário digita
document.getElementById('telefone').addEventListener('input', function (event) {
    let telefone = event.target.value.replace(/\D/g, ''); // Remove tudo que não for número

    // Aplica a formatação (XX) XXXXX-XXXX
    if (telefone.length <= 2) {
        telefone = `(${telefone}`;
    } else if (telefone.length <= 7) {
        telefone = `(${telefone.slice(0, 2)}) ${telefone.slice(2)}`;
    } else {
        telefone = `(${telefone.slice(0, 2)}) ${telefone.slice(2, 7)}-${telefone.slice(7, 11)}`;
    }

    event.target.value = telefone;
});


// Lógica para cancelar edição
document.getElementById('cancelEditBtn').addEventListener('click', () => {
    // Desabilitar os campos de input
    document.querySelectorAll('#perfil-form input').forEach(input => input.disabled = true);

    // Limpar mensagens de erro e resetar os estilos
    document.querySelectorAll('.form-group small').forEach(msg => {
        msg.textContent = '';  // Limpar conteúdo das mensagens de erro
        msg.classList.add('d-none');  // Adicionar a classe d-none para esconder as mensagens
    });

    // Remover a classe 'is-invalid' dos inputs
    document.querySelectorAll('#perfil-form input').forEach(input => {
        input.classList.remove('is-invalid');
    });

    // Fazer uma requisição para pegar os dados originais do banco de dados
    fetchUserData();

    // Alterar visibilidade dos botões
    document.getElementById('editDataBtn').style.display = 'block';
    document.getElementById('cancelEditBtn').style.display = 'none';

    // Desabilitar o botão "Salvar Alterações" ao cancelar
    document.getElementById('saveChangesBtn').disabled = true;

});



function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}


// Lógica para abrir o modal de confirmação
document.getElementById('deleteAccountBtn').addEventListener('click', function () {
    // Exibe o modal
    const deleteModal = new bootstrap.Modal(document.getElementById('confirmDeleteModal'));
    deleteModal.show();
});

// Lógica para excluir a conta quando confirmar no modal
document.getElementById('confirmDeleteBtn').addEventListener('click', function () {
    // Fecha o modal
    const deleteModal = bootstrap.Modal.getInstance(document.getElementById('confirmDeleteModal'));
    deleteModal.hide();

    // Realiza a requisição de exclusão
    fetch('/delete-account', {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + getCookie('auth_token') // Envia o token de autenticação
        }
    })
        .then(response => {
            if (response.ok) {
                // Chama a rota de logout para garantir que o cookie seja removido
                fetch('/logout', {
                    method: 'GET',
                    credentials: 'same-origin' // Para garantir que os cookies da mesma origem sejam enviados
                })
                    .then(logoutResponse => {
                        if (logoutResponse.ok) {
                            // Redireciona para a página inicial após o logout
                            window.location.href = '/index.html';
                        } else {
                            alert('Erro ao realizar logout. Tente novamente mais tarde.');
                        }
                    })
                    .catch(error => {
                        console.error('Erro na requisição de logout:', error);
                        alert('Erro na requisição de logout. Tente novamente mais tarde.');
                    });
            } else {
                alert('Erro ao excluir a conta. Tente novamente mais tarde.');
            }
        })
        .catch(error => {
            console.error('Erro na requisição de exclusão de conta:', error);
            alert('Erro na requisição. Tente novamente mais tarde.');
        });
});


// Função para obter o valor do cookie
function getCookie(name) {
    const cookieArr = document.cookie.split(';');
    for (let i = 0; i < cookieArr.length; i++) {
        const cookie = cookieArr[i].trim();
        if (cookie.startsWith(name + '=')) {
            return cookie.substring(name.length + 1);
        }
    }
    return null;
}




