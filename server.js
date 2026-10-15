'use strict';
const path = require('path'), crypto = require('crypto'), http = require('http');
const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ADMIN = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') { console.error('JWT_SECRET is required'); process.exit(1); }
const KEY = process.env.JWT_SECRET || 'dev-only-secret';
const FIELDS = ['phil', 'rel', 'eco', 'cus', 'sci'], MODES = ['حوار هادئ', 'مناظرة', 'عصف ذهني'];

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'nashed.db'));
db.pragma('journal_mode = WAL');
db.exec(`
create table if not exists users(id text primary key, email text unique not null, name text not null, hash text not null, admin integer default 0, banned integer default 0, created integer);
create table if not exists topics(id text primary key, title text, secs text, f text, mode text, owner text, at integer, closed integer default 0, sum text);
create table if not exists reqs(topic text, uid text, note text, st text, primary key(topic, uid));
create table if not exists msgs(id text primary key, topic text, uid text, x text, at integer);
create index if not exists msgs_topic on msgs(topic, at);`);

const uid = () => crypto.randomUUID();
const str = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
const json = s => { try { return JSON.parse(s); } catch (e) { return null; } };
const getUser = id => db.prepare('select * from users where id=?').get(id);
const getTopic = id => db.prepare('select * from topics where id=?').get(id);
const isMember = (u, t) => !!t && (t.owner === u.id || !!u.admin ||
  !!db.prepare("select 1 from reqs where topic=? and uid=? and st='ok'").get(t.id, u.id));

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const hits = new Map();
setInterval(() => hits.clear(), 60000).unref();
const limit = (req, res, next) => {
  const n = (hits.get(req.ip) || 0) + 1; hits.set(req.ip, n);
  if (n > 15) return res.status(429).json({ error: 'محاولات كثيرة، انتظر دقيقة.' });
  next();
};
const sign = u => jwt.sign({ id: u.id }, KEY, { expiresIn: '30d' });
const auth = (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    let u = getUser(jwt.verify(t, KEY).id);
    if (!u) throw new Error('no user');
    if (ADMIN && u.email === ADMIN && !u.admin) { db.prepare('update users set admin=1 where id=?').run(u.id); u = getUser(u.id); }
    req.u = u; next();
  } catch (e) { res.status(401).json({ error: 'سجّل الدخول من جديد.' }); }
};
const writer = (req, res, next) => req.u.banned ? res.status(403).json({ error: 'تم حظر حسابك.' }) : next();
const adminOnly = (req, res, next) => req.u.admin ? next() : res.status(403).json({ error: 'للأدمن فقط.' });
const bad = (res, m, c = 400) => res.status(c).json({ error: m });

app.post('/api/register', limit, (req, res) => {
  const email = str(req.body.email, 120).toLowerCase(), name = str(req.body.name, 30), pw = String(req.body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad(res, 'البريد الإلكتروني غير صحيح.');
  if (name.length < 2) return bad(res, 'اكتب اسماً من حرفين على الأقل.');
  if (pw.length < 8) return bad(res, 'كلمة المرور أقل من 8 أحرف.');
  if (db.prepare('select 1 from users where email=?').get(email)) return bad(res, 'هذا البريد مسجّل من قبل.', 409);
  const count = db.prepare('select count(*) c from users').get().c;
  const admin = ADMIN ? (email === ADMIN ? 1 : 0) : (count === 0 ? 1 : 0);
  const u = { id: uid(), email, name, hash: bcrypt.hashSync(pw, 10), admin };
  db.prepare('insert into users(id,email,name,hash,admin,created) values(?,?,?,?,?,?)').run(u.id, email, name, u.hash, admin, Date.now());
  res.json({ token: sign(u) });
});
app.post('/api/login', limit, (req, res) => {
  const u = db.prepare('select * from users where email=?').get(str(req.body.email, 120).toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) return bad(res, 'البريد أو كلمة المرور غير صحيحة.', 401);
  res.json({ token: sign(u) });
});

app.get('/api/state', auth, (req, res) => {
  const u = req.u;
  const topics = db.prepare('select * from topics').all().map(t => ({
    id: t.id, title: t.title, secs: json(t.secs) || [], f: t.f, mode: t.mode, owner: t.owner, at: t.at, closed: !!t.closed, sum: t.sum ? json(t.sum) : null }));
  const own = new Set(topics.filter(t => t.owner === u.id).map(t => t.id));
  const see = r => r.uid === u.id || u.admin || own.has(r.topic);
  const reqs = db.prepare('select * from reqs').all().filter(r => r.st === 'ok' || see(r))
    .map(r => ({ topic: r.topic, uid: r.uid, st: r.st, note: see(r) ? r.note : '' }));
  const bans = u.admin ? db.prepare('select id from users where banned=1').all() : (u.banned ? [{ id: u.id }] : []);
  const names = {};
  new Set([...topics.map(t => t.owner), ...reqs.map(r => r.uid), ...bans.map(b => b.id)]).forEach(i => { const r = getUser(i); if (r) names[i] = r.name; });
  res.json({ me: { id: u.id, name: u.name, admin: !!u.admin }, topics, reqs, bans, names });
});

function clean(b) {
  const title = str(b.title, 200); if (!title) return null;
  let secs = (Array.isArray(b.secs) ? b.secs : []).slice(0, 12).map(s => ({ h: str(s && s.h, 60), t: str(s && s.t, 1500) }));
  if (!secs.length) secs = [{ h: 'السؤال', t: title }];
  secs[0].t = title;
  return { title, secs: JSON.stringify(secs), f: FIELDS.includes(b.f) ? b.f : 'phil', mode: MODES.includes(b.mode) ? b.mode : MODES[0] };
}
app.post('/api/topics', auth, writer, (req, res) => {
  const c = clean(req.body); if (!c) return bad(res, 'اكتب سؤال النقاش.');
  db.prepare('insert into topics(id,title,secs,f,mode,owner,at) values(?,?,?,?,?,?,?)').run(uid(), c.title, c.secs, c.f, c.mode, req.u.id, Date.now());
  dirty(); res.json({ ok: true });
});
app.put('/api/topics/:id', auth, writer, (req, res) => {
  const t = getTopic(req.params.id); if (!t) return bad(res, 'الغرفة غير موجودة.', 404);
  if (t.owner !== req.u.id) return bad(res, 'التعديل لصاحب الغرفة فقط.', 403);
  const c = clean(req.body); if (!c) return bad(res, 'اكتب سؤال النقاش.');
  db.prepare('update topics set title=?,secs=?,f=?,mode=? where id=?').run(c.title, c.secs, c.f, c.mode, t.id);
  dirty(); res.json({ ok: true });
});
app.delete('/api/topics/:id', auth, (req, res) => {
  const t = getTopic(req.params.id); if (!t) return bad(res, 'الغرفة غير موجودة.', 404);
  if (t.owner !== req.u.id && !req.u.admin) return bad(res, 'الحذف لصاحب الغرفة أو الأدمن.', 403);
  db.transaction(() => { db.prepare('delete from msgs where topic=?').run(t.id); db.prepare('delete from reqs where topic=?').run(t.id); db.prepare('delete from topics where id=?').run(t.id); })();
  dirty(); res.json({ ok: true });
});
app.post('/api/topics/:id/join', auth, writer, (req, res) => {
  const t = getTopic(req.params.id); if (!t) return bad(res, 'الغرفة غير موجودة.', 404);
  if (t.owner === req.u.id) return bad(res, 'أنت صاحب الغرفة.');
  db.prepare('insert or ignore into reqs(topic,uid,note,st) values(?,?,?,?)').run(t.id, req.u.id, str(req.body.note, 500) || '—', 'p');
  dirty(); res.json({ ok: true });
});
app.post('/api/topics/:id/decide', auth, writer, (req, res) => {
  const t = getTopic(req.params.id); if (!t) return bad(res, 'الغرفة غير موجودة.', 404);
  if (t.owner !== req.u.id && !req.u.admin) return bad(res, 'القرار لصاحب الغرفة.', 403);
  const st = req.body.st === 'ok' ? 'ok' : 'no';
  db.prepare('update reqs set st=? where topic=? and uid=?').run(st, t.id, String(req.body.uid));
  dirty(); res.json({ ok: true });
});
app.post('/api/topics/:id/close', auth, writer, (req, res) => {
  const t = getTopic(req.params.id); if (!t) return bad(res, 'الغرفة غير موجودة.', 404);
  if (t.owner !== req.u.id) return bad(res, 'الإنهاء لصاحب الغرفة.', 403);
  db.prepare('update topics set closed=1,sum=? where id=?').run(JSON.stringify({ a: str(req.body.a, 3000), d: str(req.body.d, 3000) }), t.id);
  dirty(); res.json({ ok: true });
});
app.get('/api/topics/:id/msgs', auth, (req, res) => {
  const t = getTopic(req.params.id);
  if (!isMember(req.u, t)) return bad(res, 'ليست لديك صلاحية دخول الغرفة.', 403);
  res.json({ msgs: db.prepare('select m.id,m.topic,m.uid,m.x,m.at,u.name from msgs m join users u on u.id=m.uid where m.topic=? order by m.at limit 500').all(t.id) });
});
app.delete('/api/msgs/:id', auth, adminOnly, (req, res) => {
  const m = db.prepare('select * from msgs where id=?').get(req.params.id); if (!m) return bad(res, 'الرسالة غير موجودة.', 404);
  db.prepare('delete from msgs where id=?').run(m.id);
  wss.clients.forEach(c => c.topic === m.topic && send(c, { t: 'delmsg', id: m.id }));
  res.json({ ok: true });
});
app.post('/api/bans/:id', auth, adminOnly, (req, res) => {
  const u = getUser(req.params.id); if (!u) return bad(res, 'المستخدم غير موجود.', 404);
  if (u.admin) return bad(res, 'لا يمكن حظر أدمن.');
  db.prepare('update users set banned=1 where id=?').run(u.id); dirty(); res.json({ ok: true });
});
app.delete('/api/bans/:id', auth, adminOnly, (req, res) => {
  db.prepare('update users set banned=0 where id=?').run(req.params.id); dirty(); res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });
const send = (c, o) => { if (c.readyState === 1) c.send(JSON.stringify(o)); };
const dirty = () => wss.clients.forEach(c => send(c, { t: 'dirty' }));
const peers = c => [...wss.clients].filter(x => x !== c && x.readyState === 1 && x.topic && x.topic === c.topic);

wss.on('connection', (ws, req) => {
  let u;
  try { u = getUser(jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), KEY).id); if (!u) throw new Error('no user'); }
  catch (e) { return ws.close(4001); }
  ws.uid = u.id; ws.topic = null; ws.alive = true;
  ws.on('pong', () => { ws.alive = true; });
  const bye = () => { if (ws.topic) peers(ws).forEach(c => send(c, { t: 'bye', uid: u.id })); ws.topic = null; };
  ws.on('message', raw => {
    const m = json(String(raw)); if (!m) return;
    const cur = getUser(u.id); if (!cur) return;
    if (m.t === 'join') { bye(); const t = getTopic(String(m.topic)); if (isMember(cur, t)) ws.topic = t.id; }
    else if (m.t === 'leave') bye();
    else if (!ws.topic) return;
    else if (m.t === 'msg') {
      if (cur.banned) return;
      const x = str(m.x, 2000); if (!x) return;
      const row = { id: uid(), topic: ws.topic, uid: cur.id, x, at: Date.now() };
      db.prepare('insert into msgs(id,topic,uid,x,at) values(?,?,?,?,?)').run(row.id, row.topic, row.uid, row.x, row.at);
      const out = { t: 'msg', topic: ws.topic, m: { ...row, name: cur.name } };
      send(ws, out); peers(ws).forEach(c => send(c, out));
    } else if (m.t === 'sig' && !cur.banned) {
      peers(ws).forEach(c => { if (m.to && c.uid !== m.to) return; send(c, { t: 'sig', d: m.d }); });
    }
  });
  ws.on('close', bye);
});
setInterval(() => wss.clients.forEach(c => { if (!c.alive) return c.terminate(); c.alive = false; c.ping(); }), 30000).unref();

server.listen(PORT, () => console.log('ناقش يعمل على المنفذ ' + PORT));
