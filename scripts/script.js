const inputCheck = document.querySelector('#modo-noturno');
const elemento = document.querySelector('body');

// Função para verificar se o modo noturno estava ativado na última visita
function verificarModoNoturno() {
    const modo = localStorage.getItem('modo-noturno'); // Verifica o valor salvo no localStorage
    if (modo) {
        // Se existir, aplica o tema correspondente
        elemento.setAttribute("data-bs-theme", modo);
        inputCheck.checked = modo === 'dark'; // Atualiza o checkbox conforme a preferência
    }
}

// Evento de clique para alternar entre modo claro e escuro
inputCheck.addEventListener('click', () => {
    const modo = inputCheck.checked ? 'dark' : 'light';
    elemento.setAttribute("data-bs-theme", modo);
    localStorage.setItem('modo-noturno', modo); // Salva a preferência no localStorage
});

// Verifica o modo noturno ao carregar a página
verificarModoNoturno();
