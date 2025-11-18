// server.js — HOUSE full backend
// Node.js + Express + SQLite + Nodemailer + bcrypt
// Endpoints:
// POST /api/register {username,email,password}
// POST /api/login {username,password}
// POST /api/item { owner, type, name, data, mime, ... }
// GET  /api/items/:owner
// GET  /api/item/:id
// DELETE /api/item/:id
// POST /api/forgot { usernameOrEmail } -> sends token by email
// POST /api/reset { username, token, newPassword }
// GET  /api/export/:owner
// Health: /api/health

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || 'house.sqlite';
const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

const app = express();
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// DB init
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  // users: salt + bcrypt(salt+password)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    salt TEXT,
    passhash TEXT,
    created_at INTEGER
  )`);
  // items: owner may be username OR use user_id; keep owner TEXT for compatibility
  db.run(`CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT,
    type TEXT,
    name TEXT,
    data TEXT,
    mime TEXT,
    created_at INTEGER
  )`);
  // tokens for reset
  db.run(`CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    tokenHash TEXT,
    expires_at INTEGER
  )`);
});

// util
function now(){ return Date.now(); }
function hashToken(token){ return crypto.createHash('sha256').update(token).digest('hex'); }

// mailer
let transporter = null;
if(process.env.GMAIL_USER && process.env.GMAIL_APP_PASS){
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASS }
  });
} else {
  console.warn('GMAIL_USER / GMAIL_APP_PASS not set — forgot/reset emails will fail.');
}

// Create user
async function createUser(username, email, password){
  const salt = crypto.randomBytes(12).toString('hex');
  const passhash = await bcrypt.hash(salt + password, 10);
  return new Promise((res, rej)=>{
    const stmt = db.prepare(`INSERT INTO users (username,email,salt,passhash,created_at) VALUES (?,?,?,?,?)`);
    stmt.run(username,email,salt,passhash,now(), function(err){
      if(err) return rej(err);
      res({ id:this.lastID, username, email });
    });
  });
}

// verify user
async function verifyUser(username, password){
  return new Promise((res, rej)=>{
    db.get(`SELECT username,email,salt,passhash FROM users WHERE username = ?`, [username], async (err,row)=>{
      if(err) return rej(err);
      if(!row) return res(null);
      const ok = await bcrypt.compare(row.salt + password, row.passhash);
      if(!ok) return res(null);
      res({ username: row.username, email: row.email });
    });
  });
}

/* ---------- ROUTES ---------- */

// health
app.get('/api/health', (req,res) => res.json({ ok:true, ts: now() }));

// register
app.post('/api/register', async (req,res) => {
  try {
    const { username, email, password } = req.body;
    if(!username || !email || !password) return res.status(400).json({ error: 'username,email,password required' });
    db.get(`SELECT 1 FROM users WHERE username = ? OR email = ?`, [username,email], async (err,row)=>{
      if(err) return res.status(500).json({ error: err.message });
      if(row) return res.status(409).json({ error: 'username or email already exists' });
      try{
        const u = await createUser(username,email,password);
        res.json({ success:true, user_id: u.id, username:u.username, email:u.email });
      }catch(e){ res.status(500).json({ error: e.message }); }
    });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// login
app.post('/api/login', async (req,res) => {
  try{
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({ error: 'username and password required' });
    const ok = await verifyUser(username,password);
    if(!ok) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ success:true, username: ok.username, email: ok.email });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// create item
app.post('/api/item', (req,res) => {
  try{
    const { owner, type, name, data, mime } = req.body;
    if(!owner || !type || !name) return res.status(400).json({ error: 'owner,type,name required' });
    const stmt = db.prepare(`INSERT INTO items (owner,type,name,data,mime,created_at) VALUES (?,?,?,?,?,?)`);
    stmt.run(owner,type,name,data||null,mime||null, now(), function(err){
      if(err) return res.status(500).json({ error: err.message });
      res.json({ success:true, id: this.lastID });
    });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// list items for owner
app.get('/api/items/:owner', (req,res) => {
  const owner = req.params.owner;
  db.all(`SELECT id,owner,type,name,mime,created_at FROM items WHERE owner = ? ORDER BY created_at DESC`, [owner], (err,rows)=>{
    if(err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// get item full
app.get('/api/item/:id', (req,res) => {
  const id = req.params.id;
  db.get(`SELECT * FROM items WHERE id = ?`, [id], (err,row)=>{
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(404).json({ error: 'not found' });
    res.json(row);
  });
});

// delete item
app.delete('/api/item/:id', (req,res) => {
  const id = req.params.id;
  db.run(`DELETE FROM items WHERE id = ?`, [id], function(err){
    if(err) return res.status(500).json({ error: err.message });
    res.json({ success:true });
  });
});

// forgot (send token)
app.post('/api/forgot', (req,res) => {
  const { usernameOrEmail } = req.body;
  if(!usernameOrEmail) return res.status(400).json({ error: 'usernameOrEmail required' });
  db.get(`SELECT username,email FROM users WHERE username = ? OR email = ?`, [usernameOrEmail, usernameOrEmail], (err,row)=>{
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(404).json({ error: 'user not found' });
    const token = crypto.randomBytes(4).toString('hex');
    const tokenHash = hashToken(token);
    const expires = now() + TOKEN_TTL_MS;
    db.run(`INSERT INTO tokens (username, tokenHash, expires_at) VALUES (?,?,?)`, [row.username, tokenHash, expires], function(err2){
      if(err2) return res.status(500).json({ error: err2.message });
      if(!transporter) return res.status(500).json({ error: 'email not configured on server' });
      const mail = {
        from: process.env.GMAIL_USER,
        to: row.email,
        subject: `HOUSE - Token de recuperación para ${row.username}`,
        text: `Se generó un token de recuperación para la cuenta ${row.username}.\n\nToken: ${token}\n\nEste token expira en 1 hora.\n\nSi no pediste esto, ignora el mensaje.`
      };
      transporter.sendMail(mail, (errMail, info) => {
        if(errMail) return res.status(500).json({ error: 'failed sending mail', detail: errMail.message });
        res.json({ success:true, message: `Token enviado al correo ${row.email}` });
      });
    });
  });
});

// reset (apply token)
app.post('/api/reset', (req,res) => {
  const { username, token, newPassword } = req.body;
  if(!username || !token || !newPassword) return res.status(400).json({ error: 'username,token,newPassword required' });
  const tokenHash = hashToken(token);
  db.get(`SELECT id,expires_at FROM tokens WHERE username = ? AND tokenHash = ? ORDER BY id DESC LIMIT 1`, [username, tokenHash], async (err,row)=>{
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(404).json({ error: 'token not found' });
    if(Date.now() > row.expires_at) return res.status(400).json({ error: 'token expired' });
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err2,urow)=>{
      if(err2) return res.status(500).json({ error: err2.message });
      if(!urow) return res.status(404).json({ error: 'user not found' });
      const newSalt = crypto.randomBytes(12).toString('hex');
      const newHash = await bcrypt.hash(newSalt + newPassword, 10);
      db.run(`UPDATE users SET salt = ?, passhash = ? WHERE username = ?`, [newSalt, newHash, username], function(err3){
        if(err3) return res.status(500).json({ error: err3.message });
        res.json({ success:true, message: 'password reset' });
      });
    });
  });
});

// export all items for owner (for client-side backup)
app.get('/api/export/:owner', (req,res) => {
  const owner = req.params.owner;
  db.all(`SELECT * FROM items WHERE owner = ? ORDER BY created_at DESC`, [owner], (err,rows)=>{
    if(err) return res.status(500).json({ error: err.message });
    res.json({ meta:{ user: owner, exported_at: now() }, items: rows });
  });
});

app.use(express.static(path.join(__dirname,'public')));

app.listen(PORT, ()=> console.log(`HOUSE server listening on ${PORT}`));