// ================= SECURITY UTILITIES =================

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simple XSS sanitizer (basic but effective for demo apps)
function sanitize(input) {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ================= MOCK BACKEND =================

class MockBackend {
    constructor() {
        this.usersKey = 'users';
    }

    getUsers() {
        const users = localStorage.getItem(this.usersKey);
        return users ? JSON.parse(users) : [];
    }

    saveUser(user) {
        const users = this.getUsers();
        users.push(user);
        localStorage.setItem(this.usersKey, JSON.stringify(users));
    }

    findUser(email) {
        return this.getUsers().find(u => u.email === email);
    }

    async validateCredentials(email, password) {
        const user = this.findUser(email);
        if (!user) return null;

        const hashedPassword = await sha256(password);
        return user.password === hashedPassword ? user : null;
    }

    generateToken() {
        return crypto.randomUUID();
    }

    checkPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 8) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/\d/.test(password)) strength++;
        if (/[^a-zA-Z\d]/.test(password)) strength++;
        return strength;
    }
}

const backend = new MockBackend();

// ================= SESSION MANAGER =================

const SESSION_DURATION = 60 * 60 * 1000; // 1 hour

const SessionManager = {
    setSession: (user) => {
        const expiresAt = Date.now() + SESSION_DURATION;

        const sessionData = {
            id: user.id,
            username: user.username,
            email: user.email,
            token: user.token,
            expiresAt
        };

        sessionStorage.setItem('currentUser', JSON.stringify(sessionData));
        document.cookie = `authToken=${user.token}; max-age=3600; path=/; SameSite=Strict`;
    },

    getSession: () => {
        const session = sessionStorage.getItem('currentUser');
        if (!session) return null;

        const parsed = JSON.parse(session);
        if (Date.now() > parsed.expiresAt) {
            SessionManager.clearSession();
            return null;
        }
        return parsed;
    },

    clearSession: () => {
        sessionStorage.removeItem('currentUser');
        document.cookie = 'authToken=; max-age=0; path=/';
    },

    isLoggedIn: () => !!SessionManager.getSession()
};

// ================= ROUTE PROTECTION =================

function handleRedirects() {
    const file = window.location.pathname.split('/').pop() || 'index.html';
    const isDashboard = file === 'dashboard.html';

    if (SessionManager.isLoggedIn()) {
        if (!isDashboard) window.location.replace('dashboard.html');
    } else {
        if (isDashboard) window.location.replace('login.html');
    }
}

handleRedirects();
window.addEventListener('pageshow', handleRedirects);

// ================= PASSWORD STRENGTH =================

function updatePasswordStrength(password) {
    const strength = backend.checkPasswordStrength(password);
    const meter = document.getElementById('password-strength');
    const text = document.getElementById('strength-text');
    if (!meter || !text) return;

    meter.className = 'password-strength';

    if (!password) {
        meter.style.width = '0%';
        text.textContent = '';
        return;
    }

    if (strength <= 1) {
        meter.classList.add('weak');
        meter.style.width = '33%';
        text.textContent = 'Weak';
        text.style.color = '#ef4444';
    } else if (strength <= 3) {
        meter.classList.add('medium');
        meter.style.width = '66%';
        text.textContent = 'Medium';
        text.style.color = '#eab308';
    } else {
        meter.classList.add('strong');
        meter.style.width = '100%';
        text.textContent = 'Strong';
        text.style.color = '#22c55e';
    }
}

// ================= AUTH FLOWS =================

async function signup(event) {
    event.preventDefault();

    const username = sanitize(document.getElementById('username').value.trim());
    const email = sanitize(document.getElementById('email').value.trim());
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('error');

    if (!username || !email || !password)
        return showError(errorEl, 'All fields required');

    if (backend.findUser(email))
        return showError(errorEl, 'User already exists');

    if (backend.checkPasswordStrength(password) < 2)
        return showError(errorEl, 'Password too weak');

    const hashedPassword = await sha256(password);
    const token = await sha256(backend.generateToken());

    backend.saveUser({
        id: Date.now().toString(),
        username,
        email,
        password: hashedPassword,
        token
    });

    window.location.replace('login.html');
}

async function login(event) {
    event.preventDefault();

    const email = sanitize(document.getElementById('email').value.trim());
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('error');

    const user = await backend.validateCredentials(email, password);

    if (!user) return showError(errorEl, 'Invalid credentials');

    SessionManager.setSession(user);
    window.location.replace('dashboard.html');
}

function logout() {
    SessionManager.clearSession();
    window.location.replace('login.html');
}

function loadDashboard() {
    const user = SessionManager.getSession();
    if (!user) {
        logout();
        return;
    }

    const validUser = backend.findUser(user.email);

    // Initial backend validation
    if (!validUser || validUser.token !== user.token) {
        logout();
        return;
    }

    // Render data safely
    document.getElementById('user-name').textContent = user.username;
    document.getElementById('user-email').textContent = user.email;
    document.getElementById('user-id').textContent = user.id;
    document.getElementById('user-token').textContent = user.token;

    // 🔐 SNAPSHOT (original state)
    const originalSession = JSON.stringify(user);

    // 🕵️ REAL-TIME TAMPER WATCHER
    setInterval(() => {
        const currentSession = SessionManager.getSession();

        // Session removed or expired
        if (!currentSession) {
            logout();
            return;
        }

        // Client-side tamper detection
        if (JSON.stringify(currentSession) !== originalSession) {
            logout();
            return;
        }

        // Backend token validation (extra safety)
        const backendUser = backend.findUser(currentSession.email);
        if (!backendUser || backendUser.token !== currentSession.token) {
            logout();
        }

    }, 1000);
}



function showError(el, msg) {
    el.textContent = msg;
    el.classList.add('shake');
    setTimeout(() => el.classList.remove('shake'), 400);
}

// ================= GLOBAL EXPORTS =================

window.signup = signup;
window.login = login;
window.logout = logout;
window.loadDashboard = loadDashboard;
window.updatePasswordStrength = updatePasswordStrength;
