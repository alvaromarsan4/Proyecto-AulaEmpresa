const express = require('express');
const cors = require('cors');
const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'db.json');
const SECRET_KEY = 'super-secret-key-change-this-in-production'; // Vulnerabilidad: Hardcoded secret

app.use(cors());
app.use(express.json());

// Helper to read/write DB
const getData = async () => fs.readJson(DB_PATH);
const saveData = async (data) => fs.writeJson(DB_PATH, data, { spaces: 2 });

// --- Middlewares ---

const authenticate = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acceso denegado. No hay token.' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Token inválido o expirado.' });
    }
};

// --- AUTH ENDPOINTS ---

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son obligatorios.' });
    }

    const db = await getData();
    if (db.users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'El usuario ya existe.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: nanoid(),
        username,
        password: hashedPassword,
        created_at: new Date().toISOString()
    };

    db.users.push(newUser);
    await saveData(db);

    res.status(201).json({ message: 'Usuario registrado con éxito.' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    const db = await getData();
    const user = db.users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Credenciales inválidas.' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, username: user.username });
});

// --- NOTES ENDPOINTS ---

app.get('/api/notes', authenticate, async (req, res) => {
    const db = await getData();
    const userNotes = db.notes.filter(n => n.user_id === req.user.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json(userNotes);
});

app.post('/api/notes', authenticate, async (req, res) => {
    const { title, content } = req.body;

    if (!title || !content) {
        return res.status(400).json({ error: 'Título y contenido son obligatorios.' });
    }

    const db = await getData();
    const newNote = {
        id: nanoid(),
        user_id: req.user.id,
        title,
        content,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
    };

    db.notes.push(newNote);
    await saveData(db);

    res.status(201).json(newNote);
});

app.put('/api/notes/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { title, content } = req.body;

    const db = await getData();
    const noteIndex = db.notes.findIndex(n => n.id === id && n.user_id === req.user.id);

    if (noteIndex === -1) {
        return res.status(404).json({ error: 'Nota no encontrada o no tienes permiso.' });
    }

    db.notes[noteIndex] = {
        ...db.notes[noteIndex],
        title: title || db.notes[noteIndex].title,
        content: content || db.notes[noteIndex].content,
        updated_at: new Date().toISOString()
    };

    await saveData(db);
    res.json(db.notes[noteIndex]);
});

app.delete('/api/notes/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    const db = await getData();
    const originalLength = db.notes.length;
    db.notes = db.notes.filter(n => !(n.id === id && n.user_id === req.user.id));

    if (db.notes.length === originalLength) {
        return res.status(404).json({ error: 'Nota no encontrada o no tienes permiso.' });
    }

    await saveData(db);
    res.status(204).send();
});

app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
