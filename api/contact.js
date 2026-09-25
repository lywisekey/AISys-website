// Contact form endpoint.
//
// Plain CommonJS with global fetch, so the project stays dependency-free: no
// package.json, no node_modules, nothing to keep patched. Vercel picks up any
// file under api/ as a function on its own.
//
// Configuration, all from Vercel environment variables:
//   RESEND_API_KEY  required. Never inlined anywhere in the client bundle.
//   CONTACT_TO      where leads land.        default greenlabs80@gmail.com
//   CONTACT_FROM    envelope sender.         default no-reply@aisys.vn
//
// CONTACT_FROM has to sit on a domain verified with Resend. Sending "from" a
// gmail.com address over an API fails SPF and DKIM and lands in spam, which is
// why the default is the site's own domain rather than the inbox it forwards
// to. Before aisys.vn is verified, set CONTACT_FROM to onboarding@resend.dev -
// that address works unverified but only delivers to the Resend account owner.

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// CONTACT_TO takes one address or several separated by commas. Everyone listed
// lands in the same To: header, so each of them sees the others and Reply All
// keeps the whole group in the thread - which is the point for a shared inbox.
// Capped so that a mistyped variable cannot quietly turn this into a relay.
const TO = (process.env.CONTACT_TO || 'greenlabs80@gmail.com')
  .split(',')
  .map(function (a) { return a.trim(); })
  .filter(function (a) { return EMAIL.test(a); })
  .slice(0, 20);

const FROM = process.env.CONTACT_FROM || 'AISys <no-reply@aisys.vn>';

const LIMITS = { name: 120, company: 160, email: 200, line: 5000 };

// Best-effort throttle. Serverless instances are recycled, so this only slows
// a burst that happens to reuse one warm instance - the honeypot does the real
// work. Anything heavier belongs in front of the function, not inside it.
const hits = new Map();
function throttled(ip) {
  const now = Date.now();
  const rec = hits.get(ip) || { n: 0, t: now };
  if (now - rec.t > 60000) { rec.n = 0; rec.t = now; }
  rec.n += 1;
  hits.set(ip, rec);
  if (hits.size > 500) hits.clear();
  return rec.n > 5;
}

function clean(v, max) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'method_not_allowed' });
  }

  const body = typeof req.body === 'string' ? safeParse(req.body) : (req.body || {});

  // Honeypot: a field kept out of sight for people and irresistible to bots.
  // Answer 200 so a bot cannot tell it was caught and start probing variations.
  if (clean(body.website, 200)) return res.status(200).json({ ok: true });

  const name    = clean(body.name,    LIMITS.name);
  const company = clean(body.company, LIMITS.company);
  const email   = clean(body.email,   LIMITS.email);
  const line    = clean(body.line,    LIMITS.line);

  if (!name || !company || !line || !EMAIL.test(email)) {
    return res.status(400).json({ ok: false, error: 'invalid_input' });
  }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (throttled(ip)) return res.status(429).json({ ok: false, error: 'rate_limited' });

  if (!process.env.RESEND_API_KEY) {
    console.error('contact: RESEND_API_KEY is not set');
    return res.status(500).json({ ok: false, error: 'not_configured' });
  }

  // Every address in CONTACT_TO was rejected by the filter above, so there is
  // nowhere to deliver. Fail loudly in the log rather than silently dropping
  // a lead on the floor.
  if (!TO.length) {
    console.error('contact: CONTACT_TO has no valid address');
    return res.status(500).json({ ok: false, error: 'not_configured' });
  }

  const text =
    `${name} — ${company}\n${email}\n\n${line}\n\n— gửi từ biểu mẫu aisys.vn`;

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: FROM,
        to: TO,
        // so hitting Reply in the inbox answers the person, not the robot
        reply_to: email,
        subject: `[${company}] ${name}`,
        text: text,
      }),
    });

    if (!r.ok) {
      // Surface Resend's own words in the log - an unverified sending domain
      // reports itself here and nowhere else.
      const detail = await r.text().catch(() => '');
      console.error('contact: resend rejected', r.status, detail.slice(0, 500));
      return res.status(502).json({ ok: false, error: 'send_failed' });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('contact: send threw', err && err.message);
    return res.status(502).json({ ok: false, error: 'send_failed' });
  }
};

function safeParse(s) { try { return JSON.parse(s); } catch (e) { return {}; } }
