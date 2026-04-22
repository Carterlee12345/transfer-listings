const crypto = require('crypto');

async function redis(cmd) {
  const res = await fetch(process.env.UPSTASH_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${process.env.UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  return (await res.json()).result;
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

const DEFAULT_LOCATIONS = ['고려대', '홍대', '신촌', '이대', '합정', '건대입구'];

async function getLocations() {
  const raw = await redis(['GET', 'transfer:locations']);
  if (raw) return JSON.parse(raw);
  await redis(['SET', 'transfer:locations', JSON.stringify(DEFAULT_LOCATIONS)]);
  return DEFAULT_LOCATIONS;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    const locations = await getLocations();
    return res.status(200).json({ locations });
  }

  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const email = verifyToken(token);
  if (!email) return res.status(401).json({ error: 'Unauthorized' });

  if (req.method === 'POST') {
    const { locations } = req.body || {};
    if (!Array.isArray(locations)) return res.status(400).json({ error: '잘못된 형식입니다.' });
    await redis(['SET', 'transfer:locations', JSON.stringify(locations)]);
    return res.status(200).json({ locations });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
