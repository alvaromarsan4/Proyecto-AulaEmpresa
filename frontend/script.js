const API_URL = 'http://localhost:3000/api';
let token = localStorage.getItem('token');
let currentUser = localStorage.getItem('username');

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    if (token) {
        showApp();
    } else {
        showAuth();
    }
});

// --- Auth Functions ---

document.getElementById('login-form').onsubmit = async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) {
            login(data.token, data.username);
        } else {
            alert(data.error);
        }
    } catch (err) {
        alert('Error conectando con el servidor');
    }
};

document.getElementById('register-form').onsubmit = async (e) => {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;

    try {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) {
            alert('¡Cuenta creada! Ya puedes iniciar sesión.');
            document.getElementById('register-form').reset();
        } else {
            alert(data.error);
        }
    } catch (err) {
        alert('Error conectando con el servidor');
    }
};

function login(newToken, username) {
    token = newToken;
    currentUser = username;
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
    showApp();
}

function logout() {
    token = null;
    currentUser = null;
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    showAuth();
}

// --- View Toggles ---

function showAuth() {
    document.getElementById('auth-section').style.display = 'block';
    document.getElementById('app-section').style.display = 'none';
    document.getElementById('nav-user').style.display = 'none';
}

function showApp() {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('app-section').style.display = 'block';
    document.getElementById('nav-user').style.display = 'flex';
    document.getElementById('display-username').innerText = currentUser;
    loadNotes();
}

// --- Note Functions ---

async function loadNotes() {
    const res = await fetch(`${API_URL}/notes`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const notes = await res.json();
    const container = document.getElementById('notes-container');
    container.innerHTML = '';

    notes.forEach(note => {
        const article = document.createElement('article');
        article.className = 'note-card';
        article.innerHTML = `
            <header>
                <strong>${escapeHTML(note.title)}</strong>
            </header>
            <p>${escapeHTML(note.content)}</p>
            <div class="note-actions">
                <button class="outline" onclick="editNote('${note.id}', '${encodeURIComponent(note.title)}', '${encodeURIComponent(note.content)}')">Editar</button>
                <button class="outline contrast" onclick="deleteNote('${note.id}')">Borrar</button>
            </div>
        `;
        container.appendChild(article);
    });
}

document.getElementById('note-form').onsubmit = async (e) => {
    e.preventDefault();
    const id = document.getElementById('note-id').value;
    const title = document.getElementById('title').value;
    const content = document.getElementById('content').value;

    const method = id ? 'PUT' : 'POST';
    const url = id ? `${API_URL}/notes/${id}` : `${API_URL}/notes`;

    const res = await fetch(url, {
        method,
        headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ title, content })
    });

    if (res.ok) {
        closeModal();
        loadNotes();
    } else {
        const data = await res.json();
        alert(data.error);
    }
};

async function deleteNote(id) {
    if (!confirm('¿Seguro que quieres borrar esta nota?')) return;
    const res = await fetch(`${API_URL}/notes/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) loadNotes();
}

// --- Modal Helpers ---

function showCreateModal() {
    document.getElementById('modal-title').innerText = 'Nueva Nota';
    document.getElementById('note-id').value = '';
    document.getElementById('note-form').reset();
    document.getElementById('note-modal').setAttribute('open', '');
}

function editNote(id, title, content) {
    document.getElementById('modal-title').innerText = 'Editar Nota';
    document.getElementById('note-id').value = id;
    document.getElementById('title').value = decodeURIComponent(title);
    document.getElementById('content').value = decodeURIComponent(content);
    document.getElementById('note-modal').setAttribute('open', '');
}

function closeModal() {
    document.getElementById('note-modal').removeAttribute('open');
}

// XSS Protection Helper
function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
