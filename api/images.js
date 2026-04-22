const { put } = require('@vercel/blob');
const crypto = require('crypto');

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [payload, ts, sig] = parts;
  const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(`${payload}.${ts}`).digest('hex');
  if (sig !== expected || Date.now() - parseInt(ts) > 7 * 24 * 60 * 60 * 1000) return null;
  return Buffer.from(payload, 'base64').toString();
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const email = verifyToken(token);
  if (!email) return res.status(401).json({ error: 'Unauthorized' });

  const { filename, contentType, data } = req.body || {};
  if (!filename || !data) return res.status(400).json({ error: '파일 정보가 없습니다.' });

  const buffer = Buffer.from(data, 'base64');
  const blob = await put(`transfer/${Date.now()}-${filename}`, buffer, {
    access: 'public',
    contentType: contentType || 'image/jpeg'
  });

  return res.status(200).json({ url: blob.url });
};
