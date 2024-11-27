// Função para obter o valor de um cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

// Função para verificar se o usuário está logado
function isLoggedIn() {
    const token = getCookie('auth_token');  // Verifica se o token está presente nos cookies
    return token !== null;  // Se o token existir, o usuário está logado
}

// Função para verificar a autenticação via servidor
function checkAuthentication() {
    return fetch('/auth-check', {
        method: 'GET',
        credentials: 'same-origin',  // Garante que o cookie será enviado
    })
        .then(response => response.json())
        .then(data => {
            return data.authenticated; // Retorna se o usuário está autenticado
        })
        .catch(error => {
            console.log('Erro ao verificar autenticação', error);
            return false;
        });
}

// Seleciona elementos do DOM
const cartItemsList = document.getElementById("cart-items");
const cartTotalElement = document.getElementById("cart-total");
const clearCartButton = document.getElementById("clear-cart-btn");

// Função para obter o carrinho do localStorage
function getCart() {
    return JSON.parse(localStorage.getItem("cart")) || [];
}

// Função para salvar o carrinho no localStorage
function saveCart(cart) {
    localStorage.setItem("cart", JSON.stringify(cart));
}

// Função para calcular o total
function calculateTotal() {
    const cart = getCart();
    const total = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
    cartTotalElement.textContent = `Total: R$ ${total.toFixed(2)}`;
}

// Função para renderizar os itens do carrinho
function renderCart() {
    const cart = getCart();
    cartItemsList.innerHTML = ""; // Limpa a lista

    if (cart.length === 0) {
        cartItemsList.innerHTML = "<p>O carrinho está vazio.</p>";
        cartTotalElement.textContent = "Total: R$ 0,00";
        return;
    }

    cart.forEach((item) => {
        const listItem = document.createElement("li");
        listItem.className = "d-flex justify-content-between align-items-center mb-2";
        listItem.innerHTML = `
            <span>${item.name} (x${item.quantity})</span>
            <span>R$ ${(item.price * item.quantity).toFixed(2)}</span>
            <button class="btn btn-sm btn-danger" data-id="${item.id}">Remover</button>
        `;
        cartItemsList.appendChild(listItem);
    });

    // Adiciona funcionalidade de remoção
    const removeButtons = cartItemsList.querySelectorAll(".btn-danger");
    removeButtons.forEach((button) => {
        button.addEventListener("click", (e) => {
            removeItemFromCart(e.target.dataset.id);
        });
    });

    calculateTotal(); // Atualiza o total
}

// Função para adicionar um item ao carrinho
function addToCart(item) {
    checkAuthentication().then(isAuthenticated => {
        if (!isAuthenticated) {
            showAlert("Você precisa estar logado para adicionar itens ao carrinho.", 'danger', 3000);
            setTimeout(() => {
                window.location.href = "tela-login.html"; // Redireciona após exibir o alerta
            }, 3000); // Aguarda o tempo do alerta
            return;
        }

        const cart = getCart();
        const existingItem = cart.find((cartItem) => cartItem.id === item.id);

        if (existingItem) {
            existingItem.quantity += 1;
        } else {
            cart.push({ ...item, quantity: 1 });
        }

        saveCart(cart);
        renderCart();

        // Abrir o offcanvas automaticamente
        const cartOffcanvas = new bootstrap.Offcanvas(document.getElementById('cartOffcanvas'));
        cartOffcanvas.show();
    });
}

function showAlert(message, type = 'danger', duration = 3000) {
    const alert = document.getElementById('alertMessage');
    const alertText = document.getElementById('alertText');

    // Atualiza o texto e a classe do alerta
    alertText.textContent = message;

    // Remove classes antigas e adiciona a nova classe de estilo
    alert.className = `alert alert-${type} fade show`;
    alert.style.display = 'block';

    // Oculta automaticamente após a duração especificada
    setTimeout(() => {
        alert.style.display = 'none';
    }, duration);
}


// Função para remover um item do carrinho
function removeItemFromCart(itemId) {
    let cart = getCart();
    cart = cart.filter((item) => item.id !== parseInt(itemId));
    saveCart(cart);
    renderCart();
}

// Função para limpar o carrinho
function clearCart() {
    localStorage.removeItem("cart");
    renderCart();
    calculateTotal();
}

// Adiciona o evento de limpar carrinho
clearCartButton.addEventListener("click", clearCart);

// Adiciona itens ao carrinho ao clicar nos botões "Adicionar ao Carrinho"
document.querySelectorAll(".add-to-cart-btn").forEach((button) => {
    button.addEventListener("click", () => {
        const item = {
            id: parseInt(button.dataset.id),
            name: button.dataset.name,
            price: parseFloat(button.dataset.price)
        };
        addToCart(item);  // Só adiciona ao carrinho se o usuário estiver logado
    });
});

// Seleciona o botão de checkout
const checkoutButton = document.getElementById("checkout-btn");

// Função para verificar se o carrinho está vazio
function isCartEmpty() {
    const cart = getCart();
    return cart.length === 0;
}


function redirectToCheckout() {
    checkAuthentication().then(isAuthenticated => {
        if (!isAuthenticated) {
            showAlert("Você precisa estar logado para realizar o checkout.", "danger"); // Alerta de erro
            setTimeout(() => {
                window.location.href = "tela-login.html";  // Redireciona para o login se não estiver logado
            }, 3000); // Redireciona após 3 segundos para dar tempo de ler o alerta
        } else {
            if (isCartEmpty()) {
                showAlert("Seu carrinho está vazio. Adicione itens antes de prosseguir para o pagamento.", "warning"); // Alerta de aviso
            } else {
                window.location.href = "pagina-pagamento.html";  // Redireciona para o pagamento
            }
        }
    });
}


// Adiciona o evento de clique no botão de checkout
checkoutButton.addEventListener("click", redirectToCheckout);

// Função para verificar se o token foi apagado e limpar o carrinho
function checkLogoutAndClearCart() {
    const token = getCookie('auth_token');
    if (!token) {
        localStorage.removeItem("cart");  // Limpa o carrinho se não houver token
        renderCart();  // Atualiza a interface
        calculateTotal();
    }
}

// Adiciona evento de logout
document.querySelector("a.nav-link[href='#']").addEventListener("click", (event) => {
    event.preventDefault();  // Impede o link de redirecionar
    // Simulação de logout: Remover o token
    document.cookie = "auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
    checkLogoutAndClearCart();  // Verifica se o token foi removido e limpa o carrinho
});

// Função para carregar os itens do carrinho na página de pagamento
function loadCartOnCheckout() {
    const cartContainer = document.getElementById("checkout-cart-items");
    const totalElement = document.getElementById("checkout-cart-total");
    const cart = getCart();

    if (!cartContainer || !totalElement) return;

    cartContainer.innerHTML = "";

    if (cart.length === 0) {
        cartContainer.innerHTML = "<p>Seu carrinho está vazio.</p>";
        totalElement.textContent = "Total: R$ 0,00";
        return;
    }

    let total = 0;

    cart.forEach((item) => {
        const listItem = document.createElement("li");
        listItem.className = "d-flex justify-content-between align-items-center mb-2";
        listItem.innerHTML = `
            <span>${item.name} (x${item.quantity})</span>
            <span>R$ ${(item.price * item.quantity).toFixed(2)}</span>
        `;
        cartContainer.appendChild(listItem);
        total += item.price * item.quantity;
    });

    totalElement.textContent = `Total: R$ ${total.toFixed(2)}`;
}

// Executa a função ao carregar a página
document.addEventListener("DOMContentLoaded", () => {
    if (window.location.pathname.includes("pagina-pagamento.html")) {
        loadCartOnCheckout();
    }
});

// Inicializa o carrinho ao carregar a página
renderCart();
