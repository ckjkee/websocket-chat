// 1. Получаем элементы DOM
const messagesList = document.getElementById("messages");
const messageInput = document.getElementById("messageInput");
const loginForm = document.getElementById("loginFormElement");
const registerForm = document.getElementById("registerFormElement");

let socket;
let sessionManager;

// Функции для переключения между формами
function showRegisterForm() {
    document.getElementById("loginForm").style.display = "none";
    document.getElementById("registerForm").style.display = "block";
    clearMessages();
}

function showLoginForm() {
    document.getElementById("loginForm").style.display = "block";
    document.getElementById("registerForm").style.display = "none";
    clearMessages();
}

function clearMessages() {
    document.getElementById("loginError").style.display = "none";
    document.getElementById("registerError").style.display = "none";
    document.getElementById("registerSuccess").style.display = "none";
}

// Класс для управления сессией
class SessionManager {
    constructor() {
        this.checkInterval = null;
        this.expiryTimer = null;
        this.timerUpdateInterval = null;
        this.sessionExpiryTime = null;
        this.init();
    }
    
    async init() {
        try {
            // Получаем информацию о сессии
            const response = await fetch('/check-auth');
            if (response.ok) {
                const sessionInfo = await response.json();
                this.setupSessionTimers(sessionInfo);
                this.updateUserInfo(sessionInfo);
            }
        } catch (error) {
            console.error("Failed to get session info:", error);
        }
    }
    
    updateUserInfo(sessionInfo) {
        // Обновляем имя пользователя
        const currentUserElement = document.getElementById('currentUser');
        if (currentUserElement) {
            currentUserElement.textContent = sessionInfo.username;
        }
        
        // Проверяем наличие элемента sessionTimer
        const sessionTimerElement = document.getElementById('sessionTimer');
        if (sessionTimerElement) {
            // Инициализируем таймер начальным значением
            const expiresIn = sessionInfo.expires_in;
            if (expiresIn > 0) {
                const minutes = Math.floor(expiresIn / 60);
                const seconds = expiresIn % 60;
                const timerText = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                sessionTimerElement.textContent = timerText;
                
                // Устанавливаем начальный цвет
                if (expiresIn <= 300) { // 5 минут
                    sessionTimerElement.style.color = '#ff4444';
                    sessionTimerElement.style.fontWeight = 'bold';
                } else if (expiresIn <= 600) { // 10 минут
                    sessionTimerElement.style.color = '#ff8800';
                } else {
                    sessionTimerElement.style.color = '#00aa00';
                }
            }
        }
        
        // Сохраняем время истечения для таймера
        if (sessionInfo.expires_at) {
            this.sessionExpiryTime = new Date(sessionInfo.expires_at);
        }
    }
    
    setupSessionTimers(sessionInfo) {
        const expiresIn = sessionInfo.expires_in;
        
        if (expiresIn > 0) {
            // Устанавливаем таймер на точное время истечения
            this.expiryTimer = setTimeout(() => {
                this.redirectToLogin("Сессия истекла");
            }, expiresIn * 1000);
            
            // Дополнительная проверка каждые 30 секунд
            this.checkInterval = setInterval(() => {
                this.checkSession();
            }, 30000);
            
            // Обновление таймера каждую секунду
            this.timerUpdateInterval = setInterval(() => {
                this.updateSessionTimer();
            }, 1000);
        }
    }
    
    updateSessionTimer() {
        if (this.sessionExpiryTime) {
            const now = new Date();
            const timeLeft = Math.max(0, Math.floor((this.sessionExpiryTime - now) / 1000));
            
            if (timeLeft <= 0) {
                this.redirectToLogin("Сессия истекла");
                return;
            }
            
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            const timerText = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            const sessionTimerElement = document.getElementById('sessionTimer');
            if (sessionTimerElement) {
                sessionTimerElement.textContent = timerText;
                
                // Меняем цвет при приближении истечения
                if (timeLeft <= 300) { // 5 минут
                    sessionTimerElement.style.color = '#ff4444';
                    sessionTimerElement.style.fontWeight = 'bold';
                } else if (timeLeft <= 600) { // 10 минут
                    sessionTimerElement.style.color = '#ff8800';
                } else {
                    sessionTimerElement.style.color = '#00aa00';
                }
            }
        }
    }
    
    async checkSession() {
        try {
            const response = await fetch('/check-auth');
            if (response.status === 401) {
                this.redirectToLogin("Сессия истекла");
            }
        } catch (error) {
            console.error("Session check failed:", error);
            this.redirectToLogin("Ошибка проверки сессии");
        }
    }
    
    redirectToLogin(message) {
        // Очищаем таймеры
        if (this.expiryTimer) {
            clearTimeout(this.expiryTimer);
            this.expiryTimer = null;
        }
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
        if (this.timerUpdateInterval) {
            clearInterval(this.timerUpdateInterval);
            this.timerUpdateInterval = null;
        }
        
        // Закрываем WebSocket если открыт
        if (socket) {
            socket.close();
        }
        
        // Показываем сообщение и перенаправляем на логин
        alert(message);
        document.getElementById("chat").style.display = "none";
        document.getElementById("login").style.display = "block";
        document.getElementById("usernameInput").value = "";
        
        // Сбрасываем информацию о пользователе
        const currentUserElement = document.getElementById('currentUser');
        if (currentUserElement) {
            currentUserElement.textContent = '-';
        }
        const sessionTimerElement = document.getElementById('sessionTimer');
        if (sessionTimerElement) {
            sessionTimerElement.textContent = '--:--';
            sessionTimerElement.style.color = '';
            sessionTimerElement.style.fontWeight = '';
        }
    }
    
    destroy() {
        if (this.expiryTimer) {
            clearTimeout(this.expiryTimer);
            this.expiryTimer = null;
        }
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
        if (this.timerUpdateInterval) {
            clearInterval(this.timerUpdateInterval);
            this.timerUpdateInterval = null;
        }
    }
}

// --- Silent refresh helper ---
async function tryRefreshToken() {
    try {
        const response = await fetch('/refresh', { method: 'POST' });
        if (response.ok) {
            return true;
        }
    } catch (e) {}
    return false;
}

// --- Переопределяем checkSession для silent refresh ---
SessionManager.prototype.checkSession = async function() {
    try {
        const response = await fetch('/check-auth');
        if (response.status === 401) {
            // Пробуем silent refresh
            const refreshed = await tryRefreshToken();
            if (refreshed) {
                // После успешного refresh повторяем check-auth
                const retry = await fetch('/check-auth');
                if (retry.ok) return;
            }
            this.redirectToLogin("Сессия истекла");
        }
    } catch (error) {
        console.error("Session check failed:", error);
        this.redirectToLogin("Ошибка проверки сессии");
    }
}

// --- Обертка для fetch с автоматическим refresh ---
async function fetchWithRefresh(url, options) {
    let response = await fetch(url, options);
    if (response.status === 401) {
        const refreshed = await tryRefreshToken();
        if (refreshed) {
            response = await fetch(url, options);
        }
    }
    return response;
}

// 2. Функция входа (получение JWT в куке)
async function login(username, password) {
    try {
        const response = await fetchWithRefresh('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username: username, password: password })
        });
        
        if (!response.ok) {
            const errorData = await response.text();
            showLoginError(errorData);
            return;
        }
        
        // Токен теперь в куке, не нужно его сохранять в переменной
        connectWebSocket();
    } catch (error) {
        console.error('Login error:', error);
        showLoginError("Ошибка входа!");
    }
}

// Функция регистрации
async function register(username, password) {
    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username: username, password: password })
        });
        
        if (!response.ok) {
            const errorData = await response.text();
            showRegisterError(errorData);
            return;
        }
        
        // Показываем успешное сообщение
        showRegisterSuccess("Пользователь успешно зарегистрирован!");
        
        // Переключаемся на форму входа через 2 секунды
        setTimeout(() => {
            showLoginForm();
        }, 2000);
        
    } catch (error) {
        console.error('Register error:', error);
        showRegisterError("Ошибка регистрации!");
    }
}

// Функции для отображения сообщений
function showLoginError(message) {
    const errorElement = document.getElementById("loginError");
    errorElement.textContent = message;
    errorElement.style.display = "block";
}

function showRegisterError(message) {
    const errorElement = document.getElementById("registerError");
    errorElement.textContent = message;
    errorElement.style.display = "block";
}

function showRegisterSuccess(message) {
    const successElement = document.getElementById("registerSuccess");
    successElement.textContent = message;
    successElement.style.display = "block";
}

// 3. Подключение к WebSocket (токен автоматически в куке)
function connectWebSocket() {
    const wsProto = location.protocol === "https:" ? "wss" : "ws";
    const host = location.host || "192.168.0.172:8000";
    
    // Не передаем токен в URL - он автоматически в куке
    socket = new WebSocket(`${wsProto}://${host}/ws`);

    socket.onmessage = (event) => {
        const msg = document.createElement("li");
        if (event.data.startsWith("[HISTORY]")) {
            msg.style.color = "#888"; // Стиль для истории
            msg.textContent = event.data.replace("[HISTORY] ", "");
        } else {
            msg.textContent = event.data;
        }
        messagesList.appendChild(msg);
    };

    socket.onerror = (error) => {
        console.error("WebSocket error:", error);
        if (error.message && error.message.includes("401")) {
            alert("Ошибка авторизации! Попробуйте войти снова.");
            logout();
        }
    };

    socket.onopen = () => {
        document.getElementById("login").style.display = "none";
        document.getElementById("chat").style.display = "block";
        
        // SessionManager уже создан при загрузке страницы
        // Просто обновляем информацию о сессии
        if (sessionManager) {
            sessionManager.init();
        }
    };

    socket.onclose = () => {
        document.getElementById("chat").style.display = "none";
        document.getElementById("login").style.display = "block";
    };
}

// 4. Отправка сообщения
function sendMessage() {
    if (messageInput.value && socket) {
        socket.send(messageInput.value);
        messageInput.value = "";
    }
}

// 5. Логаут
async function logout() {
    try {
        await fetch('/logout');
        if (socket) {
            socket.close();
        }
        if (sessionManager) {
            sessionManager.destroy();
        }
        document.getElementById("chat").style.display = "none";
        document.getElementById("login").style.display = "block";
        document.getElementById("usernameInput").value = "";
        
        // Сбрасываем информацию о пользователе
        const currentUserElement = document.getElementById('currentUser');
        if (currentUserElement) {
            currentUserElement.textContent = '-';
        }
        const sessionTimerElement = document.getElementById('sessionTimer');
        if (sessionTimerElement) {
            sessionTimerElement.textContent = '--:--';
            sessionTimerElement.style.color = '';
            sessionTimerElement.style.fontWeight = '';
        }
    } catch (error) {
        console.error("Logout error:", error);
    }
}

// 6. Проверка авторизации при загрузке страницы
async function checkAuth() {
    try {
        const response = await fetch('/check-auth');
        if (response.ok) {
            // Пользователь уже авторизован
            connectWebSocket();
            
            // Инициализируем менеджер сессии для уже авторизованного пользователя
            if (sessionManager) {
                sessionManager.destroy();
            }
            sessionManager = new SessionManager();
        }
    } catch (error) {
        console.log("User not authorized");
    }
}

// 7. Обработчики событий
document.getElementById("sendButton").addEventListener("click", sendMessage);
messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendMessage();
});

loginForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const username = document.getElementById("usernameInput").value;
    const password = document.getElementById("passwordInput").value; // Добавляем пароль
    if (username) login(username, password);
});

registerForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const username = document.getElementById("regUsernameInput").value;
    const password = document.getElementById("regPasswordInput").value;
    const passwordConfirm = document.getElementById("regPasswordConfirmInput").value;
    
    if (!username || !password || !passwordConfirm) {
        showRegisterError("Все поля обязательны для заполнения");
        return;
    }
    
    if (password !== passwordConfirm) {
        showRegisterError("Пароли не совпадают");
        return;
    }
    
    if (password.length < 6) {
        showRegisterError("Пароль должен содержать минимум 6 символов");
        return;
    }
    
    register(username, password);
});

// 8. Проверяем авторизацию при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    // Создаем SessionManager сразу при загрузке страницы
    sessionManager = new SessionManager();
    checkAuth();
});