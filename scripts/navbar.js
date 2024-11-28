// navbar.js
document.addEventListener('DOMContentLoaded', function () {
    const linkLogin = document.getElementById('linkLogin');
    const profileLink = document.getElementById('profileLink');
    const logoutLink = document.getElementById('logoutLink');
    
    // Função para verificar se o usuário está autenticado
    function checkAuth() {
        fetch('/auth-check')
            .then(response => response.json())
            .then(data => {
                if (data.authenticated) {
                    // Exibir "Perfil" e ocultar "Login"
                    linkLogin.style.display = 'none';
                    profileLink.style.display = 'block';
                    logoutLink.style.display = 'block';
                } else {
                    // Exibir "Login" e ocultar "Perfil"
                    linkLogin.style.display = 'block';
                    profileLink.style.display = 'none';
                    logoutLink.style.display = 'none';
                }
            })
            .catch(error => console.log('Erro ao verificar autenticação:', error));
    }

    // Verificar autenticação ao carregar a página
    checkAuth();

    // Adicionar funcionalidade de logout
    logoutLink.addEventListener('click', function (e) {
        e.preventDefault();
        fetch('/logout')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Redirecionar para a página inicial após logout
                    window.location.href = '/';
                }
            })
            .catch(error => console.log('Erro ao realizar logout:', error));
    });
});
