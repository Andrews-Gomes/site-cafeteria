// payment.js

// Função para buscar os dados do usuário logado
function fetchUserData() {
    // Fazer uma requisição à API para obter os dados do usuário
    fetch('/user-data', {
        method: 'GET',
        credentials: 'same-origin', // Garantir que os cookies (como o token) sejam enviados junto com a requisição
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Não foi possível obter os dados do usuário.');
        }
        return response.json();
    })
    .then(data => {
        // Preencher os campos do formulário com os dados recebidos
        document.getElementById('name').value = data.nome_completo || '';
        document.getElementById('email').value = data.email || '';
        document.getElementById('phone').value = data.telefone || '';
        document.getElementById('address').value = data.endereco || '';
    })
    .catch(error => {
        console.error('Erro ao buscar os dados do usuário:', error);
        alert('Erro ao carregar os dados do usuário. Tente novamente mais tarde.');
    });
}

// Chamar a função para preencher os dados do usuário assim que a página carregar
document.addEventListener('DOMContentLoaded', fetchUserData);
