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

async function sendSlack(visit) {
  const webhook = process.env.SLACK_VISIT_WEBHOOK;
  if (!webhook) return;
  await fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: `📅 *방문 예약이 접수됐습니다!*\n\n*매물:* ${visit.listingAddress}\n*위치:* ${visit.locationTag}\n*방문 날짜:* ${visit.date}\n*방문 시간:* ${visit.time}\n*고객명:* ${visit.name}\n*연락처:* ${visit.phone}`
    })
  }).catch(() => {});
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'POST') {
    const { listingId, listingAddress, locationTag, date, time, name, phone } = req.body || {};
    if (!listingId || !date || !time || !name || !phone) {
      return res.status(400).json({ error: '모든 항목을 입력해주세요.' });
    }

    const visit = {
      id: crypto.randomUUID(),
      listingId,
      listingAddress,
      locationTag,
      date,
      time,
      name,
      phone,
      createdAt: new Date().toISOString()
    };

    await redis(['LPUSH', 'transfer:visits', JSON.stringify(visit)]);
    await sendSlack(visit);

    return res.status(200).json({ message: '예약이 완료됐습니다.' });
  }

  if (req.method === 'GET') {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const email = verifyToken(token);
    if (!email) return res.status(401).json({ error: 'Unauthorized' });

    const raw = await redis(['LRANGE', 'transfer:visits', 0, 99]) || [];
    const visits = raw.map(r => JSON.parse(r)).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return res.status(200).json({ visits });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
