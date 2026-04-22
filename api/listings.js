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

async function getOrder() {
  const raw = await redis(['GET', 'transfer:listingOrder']);
  return raw ? JSON.parse(raw) : [];
}

async function sortByOrder(listings) {
  const order = await getOrder();
  if (!order.length) return listings.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return listings.sort((a, b) => {
    const ai = order.indexOf(a.id);
    const bi = order.indexOf(b.id);
    if (ai === -1 && bi === -1) return new Date(b.createdAt) - new Date(a.createdAt);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action, id, location } = req.query;

  // Public: get all listings or by location
  if (req.method === 'GET' && (!action || action === 'list')) {
    const ids = await redis(['SMEMBERS', 'transfer:listings']) || [];
    const all = await Promise.all(ids.map(async i => {
      const raw = await redis(['GET', `transfer:listing:${i}`]);
      return raw ? JSON.parse(raw) : null;
    }));
    let listings = all.filter(Boolean).filter(l => l.active !== false);
    if (location && location !== '전체') listings = listings.filter(l => l.locationTag === location);
    listings = await sortByOrder(listings);
    return res.status(200).json({ listings });
  }

  // Public: get single listing
  if (req.method === 'GET' && action === 'get' && id) {
    const raw = await redis(['GET', `transfer:listing:${id}`]);
    if (!raw) return res.status(404).json({ error: '매물을 찾을 수 없습니다.' });
    return res.status(200).json({ listing: JSON.parse(raw) });
  }

  // Admin only below
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const email = verifyToken(token);
  if (!email) return res.status(401).json({ error: 'Unauthorized' });

  // Create listing
  if (req.method === 'POST' && action === 'create') {
    const { address, locationTag, deposit, monthlyRent, maintenanceFee, facilityFee, annualRevenue, images } = req.body || {};
    if (!address || !locationTag) return res.status(400).json({ error: '주소와 위치 태그는 필수입니다.' });

    const listing = {
      id: crypto.randomUUID(),
      address,
      locationTag,
      deposit: Number(deposit) || 0,
      monthlyRent: Number(monthlyRent) || 0,
      maintenanceFee: Number(maintenanceFee) || 0,
      facilityFee: Number(facilityFee) || 0,
      annualRevenue: Number(annualRevenue) || 0,
      images: images || [],
      active: true,
      featured: false,
      createdAt: new Date().toISOString(),
      createdBy: email
    };

    await redis(['SET', `transfer:listing:${listing.id}`, JSON.stringify(listing)]);
    await redis(['SADD', 'transfer:listings', listing.id]);

    // Append to order list
    const order = await getOrder();
    order.push(listing.id);
    await redis(['SET', 'transfer:listingOrder', JSON.stringify(order)]);

    return res.status(200).json({ listing });
  }

  // Update listing (includes featured toggle)
  if (req.method === 'PUT' && action === 'update' && id) {
    const raw = await redis(['GET', `transfer:listing:${id}`]);
    if (!raw) return res.status(404).json({ error: '매물을 찾을 수 없습니다.' });

    const existing = JSON.parse(raw);
    const { address, locationTag, deposit, monthlyRent, maintenanceFee, facilityFee, annualRevenue, images, active, featured } = req.body || {};

    const updated = {
      ...existing,
      ...(address !== undefined && { address }),
      ...(locationTag !== undefined && { locationTag }),
      ...(deposit !== undefined && { deposit: Number(deposit) }),
      ...(monthlyRent !== undefined && { monthlyRent: Number(monthlyRent) }),
      ...(maintenanceFee !== undefined && { maintenanceFee: Number(maintenanceFee) }),
      ...(facilityFee !== undefined && { facilityFee: Number(facilityFee) }),
      ...(annualRevenue !== undefined && { annualRevenue: Number(annualRevenue) }),
      ...(images !== undefined && { images }),
      ...(active !== undefined && { active }),
      ...(featured !== undefined && { featured }),
      updatedAt: new Date().toISOString()
    };

    await redis(['SET', `transfer:listing:${id}`, JSON.stringify(updated)]);
    return res.status(200).json({ listing: updated });
  }

  // Reorder listings
  if (req.method === 'POST' && action === 'reorder') {
    const { order } = req.body || {};
    if (!Array.isArray(order)) return res.status(400).json({ error: '잘못된 형식입니다.' });
    await redis(['SET', 'transfer:listingOrder', JSON.stringify(order)]);
    return res.status(200).json({ message: '순서가 저장됐습니다.' });
  }

  // Get order (admin)
  if (req.method === 'GET' && action === 'order') {
    const order = await getOrder();
    return res.status(200).json({ order });
  }

  // Delete listing
  if (req.method === 'DELETE' && action === 'delete' && id) {
    await redis(['DEL', `transfer:listing:${id}`]);
    await redis(['SREM', 'transfer:listings', id]);
    const order = await getOrder();
    await redis(['SET', 'transfer:listingOrder', JSON.stringify(order.filter(i => i !== id))]);
    return res.status(200).json({ message: '삭제됐습니다.' });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
