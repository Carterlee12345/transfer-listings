const crypto = require('crypto');

const MASTER_EMAIL = 'lee@homesinkor.com';
const MASTER_PW = 'homesinkoreaadmin';

async function redis(cmd) {
  const res = await fetch(process.env.UPSTASH_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${process.env.UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  return (await res.json()).result;
}

function makeToken(email) {
  const payload = Buffer.from(email).toString('base64');
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(`${payload}.${ts}`).digest('hex');
  return `${payload}.${ts}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [payload, ts, sig] = parts;
  const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(`${payload}.${ts}`).digest('hex');
  if (sig !== expected || Date.now() - parseInt(ts) > 7 * 24 * 60 * 60 * 1000) return null;
  return Buffer.from(payload, 'base64').toString();
}

async function getUser(email) {
  const raw = await redis(['GET', `transfer:user:${email}`]);
  return raw ? JSON.parse(raw) : null;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action } = req.query;

  if (action === 'login') {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: '이메일과 비밀번호를 입력하세요.' });

    if (email === MASTER_EMAIL && password === MASTER_PW) {
      return res.status(200).json({ token: makeToken(email), isMaster: true, approved: true });
    }

    const user = await getUser(email);
    if (!user) return res.status(401).json({ error: '계정이 없습니다.' });

    const hash = crypto.createHash('sha256').update(password + user.salt).digest('hex');
    if (hash !== user.passwordHash) return res.status(401).json({ error: '비밀번호가 틀렸습니다.' });
    if (!user.approved) return res.status(403).json({ error: '관리자 승인 대기 중입니다.' });

    return res.status(200).json({ token: makeToken(email), isMaster: false, approved: true });
  }

  if (action === 'register') {
    const { email, password, name } = req.body || {};
    if (!email || !password || !name) return res.status(400).json({ error: '모든 항목을 입력하세요.' });
    if (email === MASTER_EMAIL) return res.status(400).json({ error: '이미 사용 중인 이메일입니다.' });

    const existing = await getUser(email);
    if (existing) return res.status(400).json({ error: '이미 사용 중인 이메일입니다.' });

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(password + salt).digest('hex');
    const user = { email, name, salt, passwordHash, approved: false, createdAt: new Date().toISOString() };

    await redis(['SET', `transfer:user:${email}`, JSON.stringify(user)]);
    await redis(['SADD', 'transfer:users', email]);

    return res.status(200).json({ message: '가입 신청이 완료됐습니다. 관리자 승인 후 로그인 가능합니다.' });
  }

  if (action === 'verify') {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const email = verifyToken(token);
    if (!email) return res.status(401).json({ error: 'Unauthorized' });
    const isMaster = email === MASTER_EMAIL;
    if (!isMaster) {
      const user = await getUser(email);
      if (!user || !user.approved) return res.status(403).json({ error: 'Not approved' });
    }
    return res.status(200).json({ email, isMaster });
  }

  if (action === 'users') {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const email = verifyToken(token);
    if (email !== MASTER_EMAIL) return res.status(403).json({ error: 'Forbidden' });

    const emails = await redis(['SMEMBERS', 'transfer:users']) || [];
    const users = await Promise.all(emails.map(e => getUser(e)));
    return res.status(200).json({ users: users.filter(Boolean) });
  }

  if (action === 'approve') {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const email = verifyToken(token);
    if (email !== MASTER_EMAIL) return res.status(403).json({ error: 'Forbidden' });

    const { targetEmail, approved } = req.body || {};
    const user = await getUser(targetEmail);
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

    user.approved = approved;
    await redis(['SET', `transfer:user:${targetEmail}`, JSON.stringify(user)]);
    return res.status(200).json({ message: approved ? '승인됐습니다.' : '거부됐습니다.' });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
