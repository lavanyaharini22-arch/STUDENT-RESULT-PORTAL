// Zero-dependency Node.js server (no npm install needed). Data is saved in data/db.json
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const PUB = path.join(__dirname, 'public');
const DB = path.join(__dirname, 'data', 'db.json');
fs.mkdirSync(path.dirname(DB), { recursive: true });
let db = { users: [], items: [], contacts: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB, 'utf8'))); } catch (e) {}
const save = () => fs.writeFileSync(DB, JSON.stringify(db, null, 2));
const sessions = new Map();
const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const send = (res, code, obj, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(resolve => {
  let d = '';
  req.on('data', c => { d += c; if (d.length > 1e6) req.destroy(); });
  req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
  req.on('error', () => resolve({}));
});
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');
const sid = req => { const c = (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(x => x[0] === 'sid'); return c && c[1]; };
const userOf = req => { const id = sessions.get(sid(req)); return db.users.find(u => u.id === id); };

http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://localhost').pathname;
  if (p.startsWith('/api/')) {
    const b = req.method === 'POST' ? await readBody(req) : {};
    const u = userOf(req);
    if (p === '/api/register' && req.method === 'POST') {
      const { name, email, password } = b;
      if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || !password || password.length < 6)
        return send(res, 400, { error: 'Enter name, a valid email and a password (min 6 characters).' });
      if (db.users.some(x => x.email === email.toLowerCase())) return send(res, 409, { error: 'Email is already registered.' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users.push({ id: crypto.randomUUID(), name: String(name).trim(), email: email.toLowerCase(), salt, hash: hash(password, salt) });
      save();
      return send(res, 201, { ok: true });
    }
    if (p === '/api/login' && req.method === 'POST') {
      const user = db.users.find(x => x.email === String(b.email || '').toLowerCase());
      if (!user || hash(String(b.password || ''), user.salt) !== user.hash) return send(res, 401, { error: 'Invalid email or password.' });
      const t = crypto.randomBytes(24).toString('hex');
      sessions.set(t, user.id);
      return send(res, 200, { ok: true }, { 'Set-Cookie': `sid=${t}; HttpOnly; Path=/; SameSite=Lax` });
    }
    if (p === '/api/logout' && req.method === 'POST') {
      sessions.delete(sid(req));
      return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
    }
    if (p === '/api/contact' && req.method === 'POST') {
      if (!b.name || !b.email || !b.message) return send(res, 400, { error: 'All fields are required.' });
      db.contacts.push({ name: b.name, email: b.email, message: b.message, createdAt: new Date().toISOString() });
      save();
      return send(res, 201, { ok: true });
    }
    if (!u) return send(res, 401, { error: 'Please log in.' });
    if (p === '/api/me') return send(res, 200, { user: { name: u.name, email: u.email } });
    if (p === '/api/items' && req.method === 'GET') return send(res, 200, { items: db.items.filter(i => i.userId === u.id) });
    if (p === '/api/items' && req.method === 'POST') {
      if (!Object.keys(b).length) return send(res, 400, { error: 'No data received.' });
      const item = { id: crypto.randomUUID(), userId: u.id, createdAt: new Date().toISOString(), data: b };
      db.items.push(item); save();
      return send(res, 201, { item });
    }
    if (p.startsWith('/api/items/') && req.method === 'DELETE') {
      const id = p.split('/').pop();
      db.items = db.items.filter(i => !(i.id === id && i.userId === u.id)); save();
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: 'Not found.' });
  }
  const fp = path.join(PUB, path.normalize(p === '/' ? '/index.html' : p));
  if (!fp.startsWith(PUB)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('404 Not Found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
