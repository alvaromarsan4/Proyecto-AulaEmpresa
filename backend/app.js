const express = require('express');
const cors = require('cors');
const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'db.json');
const SECRET_KEY = 'super-secret-key-change-this-in-production';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// --- Configuración de Encriptación ---
const ALGO = 'aes-256-cbc';
const KEY = crypto.scryptSync(SECRET_KEY, 'salt-notes', 32);

const encrypt = (text) => {
    if (!text) return text;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGO, KEY, iv);
    let encrypted = cipher.update(String(text), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
};

const decrypt = (text) => {
    if (!text || !text.includes(':')) return text;
    try {
        const [ivHex, encryptedHex] = text.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return text;
    }
};

// --- Helpers para DB ---
const getData = async () => {
    try {
        if (!await fs.pathExists(DB_PATH)) return { users: [], notes: [] };
        return await fs.readJson(DB_PATH);
    } catch (e) {
        return { users: [], notes: [] };
    }
};

const saveData = async (data) => {
    await fs.writeJson(DB_PATH, data, { spaces: 2 });
};

// --- AUTH ENDPOINTS ---

app.post('/api/register', async (req, res, next) => {
    try {
        let { username, password } = req.body;
        const db = await getData();

        // Para buscar si el usuario existe, tenemos que desencriptar los nombres guardados
        if (db.users.find(u => decrypt(u.username) === username)) {
            return res.status(400).json({ error: 'El usuario ya existe.' });
        }

        const newUser = {
            id: encrypt(nanoid()), // ID Encriptado
            username: encrypt(username), // Username Encriptado
            password: encrypt(await bcrypt.hash(password, 10)), // Password (Hash + Encriptado)
            created_at: new Date().toISOString() // Fecha Legible
        };

        db.users.push(newUser);
        await saveData(db);

        const token = jwt.sign({ id: decrypt(newUser.id), username: username }, SECRET_KEY);
        res.status(201).json({ token, username });
    } catch (err) { next(err); }
});

app.post('/api/login', async (req, res, next) => {
    try {
        let { username, password } = req.body;
        const db = await getData();

        // Buscamos desencriptando en caliente
        const user = db.users.find(u => decrypt(u.username) === username);

        if (!user || !(await bcrypt.compare(password, decrypt(user.password)))) {
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const token = jwt.sign({ id: decrypt(user.id), username: username }, SECRET_KEY);
        res.json({ token, username });
    } catch (err) { next(err); }
});

// --- NOTES ENDPOINTS ---

app.get('/api/notes', async (req, res, next) => {
    // Nota: Aquí asumo que pasas el token por el middleware authenticate
    // que decodifica el req.user.id original
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);

        const db = await getData();
        const userNotes = db.notes
            .filter(n => decrypt(n.user_id) === decoded.id) // Comparamos ID real vs ID guardado (desencriptado)
            .map(n => ({
                id: decrypt(n.id),
                title: decrypt(n.title),
                content: decrypt(n.content),
                created_at: n.created_at, // Se mantiene legible
                updated_at: n.updated_at
            }))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json(userNotes);
    } catch (err) { res.status(401).send(); }
});

app.post('/api/notes', async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);

        let { title, content } = req.body;
        const db = await getData();

        const newNote = {
            id: encrypt(nanoid()),      // ID cifrado
            user_id: encrypt(decoded.id), // Relación de usuario cifrada
            title: encrypt(title),       // Título cifrado
            content: encrypt(content),   // Contenido cifrado
            created_at: new Date().toISOString(), // Legible
            updated_at: new Date().toISOString()
        };

        db.notes.push(newNote);
        await saveData(db);

        res.status(201).json({
            ...newNote,
            id: decrypt(newNote.id),
            title: decrypt(newNote.title),
            content: decrypt(newNote.content)
        });
    } catch (err) { next(err); }
});

app.put('/api/notes/:id', async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);

        const { id } = req.params;
        const { title, content } = req.body;
        const db = await getData();

        const noteIndex = db.notes.findIndex(n => decrypt(n.id) === id && decrypt(n.user_id) === decoded.id);

        if (noteIndex === -1) {
            return res.status(404).json({ error: 'Nota no encontrada.' });
        }

        if (title !== undefined) db.notes[noteIndex].title = encrypt(title);
        if (content !== undefined) db.notes[noteIndex].content = encrypt(content);
        db.notes[noteIndex].updated_at = new Date().toISOString();

        await saveData(db);

        res.json({
            id: decrypt(db.notes[noteIndex].id),
            user_id: decrypt(db.notes[noteIndex].user_id),
            title: decrypt(db.notes[noteIndex].title),
            content: decrypt(db.notes[noteIndex].content),
            created_at: db.notes[noteIndex].created_at,
            updated_at: db.notes[noteIndex].updated_at
        });
    } catch (err) { res.status(401).send(); }
});

app.delete('/api/notes/:id', async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);

        const { id } = req.params;
        const db = await getData();

        const originalLength = db.notes.length;
        db.notes = db.notes.filter(n => !(decrypt(n.id) === id && decrypt(n.user_id) === decoded.id));

        if (db.notes.length === originalLength) {
            return res.status(404).json({ error: 'Nota no encontrada.' });
        }

        await saveData(db);
        res.status(204).send();
    } catch (err) { res.status(401).send(); }
});

app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));