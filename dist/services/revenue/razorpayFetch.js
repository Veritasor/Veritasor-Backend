/**
 * Fetch revenue entries from Razorpay between two ISO dates (inclusive).
 * Expects `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` in env.
 */
export async function fetchRazorpayRevenue(startDate, endDate) {
    const key = process.env.RAZORPAY_KEY_ID;
    const secret = process.env.RAZORPAY_KEY_SECRET;
    if (!key || !secret) {
        throw new Error('Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET environment variables');
    }
    const from = Math.floor(new Date(startDate).getTime() / 1000);
    const to = Math.floor(new Date(endDate).getTime() / 1000);
    const auth = Buffer.from(`${key}:${secret}`).toString('base64');
    const results = [];
    const pageSize = 100;
    let skip = 0;
    while (true) {
        const url = new URL('https://api.razorpay.com/v1/payments');
        url.searchParams.set('from', String(from));
        url.searchParams.set('to', String(to));
        url.searchParams.set('count', String(pageSize));
        url.searchParams.set('skip', String(skip));
        const resp = await fetch(url.toString(), {
            headers: {
                Authorization: `Basic ${auth}`,
                Accept: 'application/json',
            },
        });
        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(`Razorpay API error: ${resp.status} ${text}`);
        }
        const body = await resp.json();
        const items = Array.isArray(body.items) ? body.items : [];
        for (const it of items) {
            // Razorpay amounts are provided in the smallest currency unit (e.g. paise for INR)
            const amount = typeof it.amount === 'number' ? it.amount / 100 : NaN;
            const createdAt = typeof it.created_at === 'number' ? it.created_at : it.created_at;
            const date = createdAt ? new Date(createdAt * 1000).toISOString() : new Date().toISOString();
            // Only include captured payments as realized revenue
            if (it.status !== 'captured')
                continue;
            results.push({
                id: it.id,
                amount,
                currency: it.currency || 'INR',
                date,
                source: 'razorpay',
                raw: it,
            });
        }
        if (items.length < pageSize)
            break;
        skip += pageSize;
    }
    return results;
}
export default fetchRazorpayRevenue;
