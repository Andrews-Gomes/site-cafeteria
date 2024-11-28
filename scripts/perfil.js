// Função para obter o token do cookie
function getTokenFromCookie() {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; token=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }
  
  // Função para preencher os campos do formulário
  function preencherCamposPerfil(userData) {
    document.getElementById('nome_completo').value = userData.nome_completo;
    document.getElementById('email').value = userData.email;
    document.getElementById('endereco').value = userData.endereco;
    document.getElementById('telefone').value = userData.telefone;
    document.getElementById('userName').innerText = `Olá, ${userData.nome_completo}`;
  }
  
  // Requisição para obter os dados do usuário
  async function carregarDadosUsuario() {
    const token = getTokenFromCookie();
    if (token) {
      try {
        const response = await fetch('/api/usuario', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
  
        if (response.ok) {
          const userData = await response.json();
          preencherCamposPerfil(userData);
        } else {
          console.error('Erro ao obter dados do usuário');
        }
      } catch (error) {
        console.error('Erro na requisição', error);
      }
    } else {
      console.log('Token não encontrado');
    }
  }
  
  // Carregar os dados ao carregar a página
  document.addEventListener('DOMContentLoaded', carregarDadosUsuario);
  