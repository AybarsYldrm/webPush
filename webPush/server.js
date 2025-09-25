// webpush-server.js
// Node built-ins only. Node >=12+
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const path = require('path');

class WebPushServer {
  constructor(opts = {}) {
    this.PORT = opts.port || process.env.PORT || 80;
    this.DATA_DIR = path.resolve(opts.dataDir || __dirname, 'data');
    if (!fs.existsSync(this.DATA_DIR)) fs.mkdirSync(this.DATA_DIR);

    this.VAPID_PRIV_PATH = path.join(this.DATA_DIR, 'vapid_priv.pem');
    this.VAPID_PUB_JWK_PATH = path.join(this.DATA_DIR, 'vapid_pub.jwk.json');
    this.SUBSCRIPTIONS_PATH = path.join(this.DATA_DIR, 'subscriptions.json');

    // Rate limiter defaults
    this.RATE_LIMIT_WINDOW_MS = opts.rateLimitWindowMs || 60 * 1000;
    this.RATE_LIMIT_MAX = opts.rateLimitMax || 30;
    this.rateMap = new Map();

    // subscriptions
    this.subscriptions = [];
    this.loadSubs();

    // ensure vapid exists
    this.VAPID = null;
    this.ensureVapid();
  }

  // ----------------------
  // helpers: base64url
  // ----------------------
  base64url(buf) {
    return Buffer.from(buf).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  base64urlToBuffer(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64');
  }
  parseKeyFlex(str) {
    if (typeof str !== 'string') throw new Error('key not a string');
    if (str.indexOf('-') !== -1 || str.indexOf('_') !== -1) {
      return this.base64urlToBuffer(str);
    } else {
      return Buffer.from(str, 'base64');
    }
  }

  // ----------------------
  // VAPID key management
  // ----------------------
  ensureVapid() {
    if (this.VAPID) return this.VAPID;
    if (fs.existsSync(this.VAPID_PRIV_PATH) && fs.existsSync(this.VAPID_PUB_JWK_PATH)) {
      const privPem = fs.readFileSync(this.VAPID_PRIV_PATH, 'utf8');
      const publicKeyJwk = JSON.parse(fs.readFileSync(this.VAPID_PUB_JWK_PATH, 'utf8'));
      this.VAPID = { privPem, publicKeyJwk };
      return this.VAPID;
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyJwk = publicKey.export({ format: 'jwk' });
    fs.writeFileSync(this.VAPID_PRIV_PATH, privPem, 'utf8');
    fs.writeFileSync(this.VAPID_PUB_JWK_PATH, JSON.stringify(publicKeyJwk, null, 2), 'utf8');
    this.VAPID = { privPem, publicKeyJwk };
    return this.VAPID;
  }
  jwkToPublicKeyUint8(jwk) {
    const x = this.base64urlToBuffer(jwk.x);
    const y = this.base64urlToBuffer(jwk.y);
    return Buffer.concat([Buffer.from([0x04]), x, y]);
  }

  // ----------------------
  // Create VAPID JWT
  // ----------------------
  createVapidJwt(aud, subject = 'mailto:network@fitfak.net', ttlSeconds = 12 * 60 * 60) {
    const { privPem, publicKeyJwk } = this.ensureVapid();
    const header = { alg: 'ES256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = { aud, exp: now + ttlSeconds, sub: subject };
    const enc = (obj) => this.base64url(Buffer.from(JSON.stringify(obj)));
    const signingInput = enc(header) + '.' + enc(payload);
    const signer = crypto.createSign('SHA256');
    signer.update(signingInput);
    signer.end();
    const signature = signer.sign({ key: privPem, dsaEncoding: 'ieee-p1363' });
    const jwt = signingInput + '.' + this.base64url(signature);
    return { jwt, publicKeyJwk };
  }

  // ----------------------
  // Subscriptions store
  // ----------------------
  loadSubs() {
    try {
      if (fs.existsSync(this.SUBSCRIPTIONS_PATH)) {
        this.subscriptions = JSON.parse(fs.readFileSync(this.SUBSCRIPTIONS_PATH, 'utf8'));
      }
    } catch (e) {
      this.subscriptions = [];
    }
  }
  saveSubs() {
    fs.writeFileSync(this.SUBSCRIPTIONS_PATH, JSON.stringify(this.subscriptions, null, 2), 'utf8');
  }

  // ----------------------
  // HKDF helpers
  // ----------------------
  hmacSha256(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest();
  }
  hkdfExtract(salt, ikm) {
    return this.hmacSha256(salt, ikm);
  }
  hkdfExpandOne(prk, info) {
    const infoPlus = Buffer.concat([info, Buffer.from([0x01])]);
    return this.hmacSha256(prk, infoPlus);
  }

  // ----------------------
  // ensure uncompressed P-256 point
  // ----------------------
  ensureUncompressedPoint(buf) {
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
    if (buf.length === 65 && buf[0] === 0x04) return buf;
    if (buf.length === 64) return Buffer.concat([Buffer.from([0x04]), buf]);
    throw new Error('public key is not a valid P-256 uncompressed/XY (len=' + buf.length + ')');
  }

  padPayload(buf) {
    const minLen = 32;
    if (buf.length >= minLen) return buf;
    const padLen = minLen - buf.length;
    return Buffer.concat([buf, Buffer.alloc(padLen, 0x02)]);
  }

  // ----------------------
  // Rate limiter
  // ----------------------
  checkRateLimit(ip) {
    const now = Date.now();
    const entry = this.rateMap.get(ip) || { t0: now, count: 0 };
    if (now - entry.t0 > this.RATE_LIMIT_WINDOW_MS) {
      entry.t0 = now; entry.count = 0;
    }
    entry.count++;
    this.rateMap.set(ip, entry);
    return entry.count <= this.RATE_LIMIT_MAX;
  }

  // ----------------------
  // Core: encrypt payload (RFC8291/8188) and send
  // ----------------------
  async encryptAndSendPush(subscription, payloadBuf, options = {}) {
    const u = url.parse(subscription.endpoint);
    const isHttps = u.protocol === 'https:';
    const host = u.hostname;
    const port = u.port ? parseInt(u.port, 10) : (isHttps ? 443 : 80);
    const pathstr = u.path;

    if (!subscription.keys || !subscription.keys.p256dh || !subscription.keys.auth) {
      throw new Error('subscription missing keys');
    }

    // 1) salt + ephemeral ECDH
    const salt = crypto.randomBytes(16);
    const ecdh = crypto.createECDH('prime256v1');
    const as_public_raw = ecdh.generateKeys(); // may be 65 or 64
    const as_public = this.ensureUncompressedPoint(as_public_raw);

    // 2) client pub + auth
    const ua_public_raw = this.parseKeyFlex(subscription.keys.p256dh);
    const ua_public = this.ensureUncompressedPoint(ua_public_raw);
    const auth_secret = this.parseKeyFlex(subscription.keys.auth);

    console.log('[push] ua_public.len=', ua_public.length, 'as_public.len=', as_public.length, 'auth.len=', auth_secret.length);

    // 3) ECDH shared secret
    const ecdh_secret = ecdh.computeSecret(ua_public);

    // 4) PRK_key = HMAC-SHA256(auth_secret, ecdh_secret)
    const PRK_key = this.hkdfExtract(auth_secret, ecdh_secret);

    // 5) key_info = "WebPush: info" || 0x00 || ua_public || as_public
    const keyInfoPrefix = Buffer.from('WebPush: info', 'ascii');
    const key_info = Buffer.concat([keyInfoPrefix, Buffer.from([0x00]), ua_public, as_public]);

    // IKM = HMAC-SHA256(PRK_key, key_info || 0x01)
    const IKM = this.hkdfExpandOne(PRK_key, key_info); // 32

    // 6) PRK = HMAC-SHA256(salt, IKM)
    const PRK = this.hkdfExtract(salt, IKM); // 32

    // 7) CEK + NONCE
    const cek_info = Buffer.concat([Buffer.from('Content-Encoding: aes128gcm', 'ascii'), Buffer.from([0x00])]);
    const nonce_info = Buffer.concat([Buffer.from('Content-Encoding: nonce', 'ascii'), Buffer.from([0x00])]);

    const cek_full = this.hkdfExpandOne(PRK, cek_info); // 32
    const CEK = cek_full.slice(0, 16);
    const nonce_full = this.hkdfExpandOne(PRK, nonce_info);
    const NONCE = nonce_full.slice(0, 12);

    // 8) plaintext: payload + 0x02 delimiter (single record)
    const paddedPlain = Buffer.concat([payloadBuf, Buffer.from([0x02])]);

    // 9) AES-128-GCM
    const cipher = crypto.createCipheriv('aes-128-gcm', CEK, NONCE);
    const encrypted = Buffer.concat([cipher.update(paddedPlain), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const bodyCipher = Buffer.concat([encrypted, authTag]); // ciphertext + tag

    // 10) Build RFC8188 header-block (salt(16) || rs(4) || idlen(1) || keyid(keyidlen))
    const rs = 4096;
    const rsBuf = Buffer.alloc(4);
    rsBuf.writeUInt32BE(rs, 0);
    const idlenBuf = Buffer.from([as_public.length]);
    const headerBlock = Buffer.concat([salt, rsBuf, idlenBuf, as_public]); // 86 bytes

    // Final body to be sent (header-block + ciphertext+tag)
    const bodyToSend = Buffer.concat([headerBlock, bodyCipher]);

    // 11) VAPID JWT + vapid pub bytes
    const aud = `${u.protocol}//${u.host}`;
    const { jwt, publicKeyJwk } = this.createVapidJwt(aud, options.subject || 'mailto:network@fitfak.net');
    const vapidPubBytes = this.jwkToPublicKeyUint8(publicKeyJwk);
    const vapidPub65 = this.ensureUncompressedPoint(vapidPubBytes);

    const commonHeadersBase = {
      'Content-Encoding': 'aes128gcm',
      'Content-Length': String(bodyToSend.length),
      'TTL': String(options.ttl || 2419200),
      'Encryption': `salt=${this.base64url(salt)}`,
      'Crypto-Key': `dh=${this.base64url(as_public)}; p256ecdsa=${this.base64url(vapidPub65)}`
    };

    const headersCandidates = [
      Object.assign({}, commonHeadersBase, { 'Authorization': `WebPush ${jwt}` }),
      Object.assign({}, commonHeadersBase, { 'Authorization': `vapid t=${jwt}, k=${this.base64url(vapidPub65)}` }),
      Object.assign({}, commonHeadersBase, { 'Authorization': `vapid t=${jwt}, k=${vapidPub65.toString('base64')}` }),
      Object.assign({}, commonHeadersBase, { 'Authorization': `t=${jwt}; k=${vapidPub65.toString('base64')}` }),
      Object.assign({}, commonHeadersBase, { 'Authorization': `t=${jwt}; k=${this.base64url(vapidPub65)}` })
    ];

    const attempts = [];
    for (const headers of headersCandidates) {
      const reqOptions = {
        method: 'POST',
        hostname: host,
        port,
        path: pathstr,
        headers,
        protocol: u.protocol
      };

      try {
        const r = await new Promise((resolve, reject) => {
          const req = (isHttps ? https : http).request(reqOptions, (res) => {
            const bufs = [];
            res.on('data', c => bufs.push(c));
            res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(bufs).toString(), usedAuth: headers.Authorization }));
          });
          req.on('error', (err) => reject(err));
          req.write(bodyToSend);
          req.end();
        });

        attempts.push(r);
        console.log('[push] attempt', (headers.Authorization||'').slice(0, 40) + '...', '->', r.statusCode);

        if (r.statusCode >= 200 && r.statusCode < 300) {
          return { statusCode: r.statusCode, body: r.body, usedAuth: headers.Authorization, attempts };
        }

        if (r.statusCode === 401 || r.statusCode === 403) {
          continue;
        }

        return { statusCode: r.statusCode, body: r.body, usedAuth: headers.Authorization, attempts };
      } catch (err) {
        console.error('[push] network error for auth=', headers.Authorization, err);
        return { error: String(err), usedAuth: headers.Authorization, attempts };
      }
    }

    return { statusCode: 401, body: 'all auth formats tried and failed', attempts };
  }

  // ----------------------
  // send to all wrapper
  // ----------------------
  async sendToAll(messageObj = {}, options = {}) {
    const payloadBuf = Buffer.from(JSON.stringify(messageObj), 'utf8');
    const results = [];
    for (let i = this.subscriptions.length - 1; i >= 0; --i) {
      const sub = this.subscriptions[i];
      try {
        const r = await this.encryptAndSendPush(sub, payloadBuf, options);
        results.push(Object.assign({ endpoint: sub.endpoint }, r));
        if (r && (r.statusCode === 410 || r.statusCode === 404)) {
          this.subscriptions.splice(i, 1);
        }
      } catch (err) {
        results.push({ endpoint: sub.endpoint, error: String(err) });
      }
    }
    this.saveSubs();
    return results;
  }

  // ----------------------
  // HTTP server endpoints
  // ----------------------
  start() {
    if (this.server) return;
    this.server = http.createServer(this._onRequest.bind(this));
    this.server.listen(this.PORT, () => {
      this.ensureVapid();
      console.log(`Server listening on ${this.PORT}`);
      const { publicKeyJwk } = this.ensureVapid();
      console.log('VAPID public key (applicationServerKey):', this.base64url(this.jwkToPublicKeyUint8(publicKeyJwk)));
    });
  }

  async _onRequest(req, res) {
    const u = url.parse(req.url, true);
    const ip = req.socket.remoteAddress || req.connection.remoteAddress || 'unknown';

    // GET /vapidPublicKey
    if (req.method === 'GET' && u.pathname === '/vapidPublicKey') {
      try {
        const { publicKeyJwk } = this.ensureVapid();
        const publicKeyUint8 = this.jwkToPublicKeyUint8(publicKeyJwk);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ publicKey: this.base64url(publicKeyUint8) }));
      } catch (e) {
        res.writeHead(500); res.end('vapid error');
      }
      return;
    }

    // POST /subscribe
    if (req.method === 'POST' && u.pathname === '/subscribe') {
      let body = '';
      req.on('data', (c) => body += c.toString());
      req.on('end', () => {
        try {
          const sub = JSON.parse(body);
          if (!sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
            res.writeHead(400); res.end('invalid subscription');
            return;
          }
          if (!this.subscriptions.find(s => s.endpoint === sub.endpoint)) {
            this.subscriptions.push(sub);
            this.saveSubs();
            res.writeHead(201, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, info: 'already exists' }));
          }
        } catch (e) {
          res.writeHead(400); res.end('invalid json');
        }
      });
      return;
    }

    // POST /send
    if (req.method === 'POST' && u.pathname === '/send') {
      if (!this.checkRateLimit(ip)) {
        res.writeHead(429); res.end('rate limit');
        return;
      }
      let body = '';
      req.on('data', (c) => body += c.toString());
      req.on('end', async () => {
        try {
          const payload = body ? JSON.parse(body) : {};
          if (!payload.title && !payload.body) {
            res.writeHead(400); res.end('payload must include title or body');
            return;
          }
          const messageObj = {
            title: String(payload.title || 'Bildirim'),
            body: String(payload.body || '')
          };
          if (payload.icon) messageObj.icon = String(payload.icon);
          const ttl = Number.isInteger(payload.ttl) ? payload.ttl : 2419200;
          const subject = payload.subject || 'mailto:network@fitfak.net';
          const results = await this.sendToAll(messageObj, { ttl, subject });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ results }, null, 2));
        } catch (e) {
          console.error('send error', e);
          res.writeHead(500); res.end(String(e));
        }
      });
      return;
    }

    // Serve client pages
    if (req.method === 'GET' && u.pathname === '/') {
      const p = path.join(__dirname, 'client.html');
      if (fs.existsSync(p)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(fs.readFileSync(p, 'utf8'));
        return;
      }
    }
    if (req.method === 'GET' && u.pathname === '/sw.js') {
  const p = path.join(__dirname, 'sw.js');
  if (fs.existsSync(p)) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
    res.setHeader('Expires', '0');
    res.setHeader('Pragma', 'no-cache');
    // opsiyonel: service worker scope yetkisi
    // res.setHeader('Service-Worker-Allowed', '/');
    res.end(fs.readFileSync(p, 'utf8'));
    return;
  }
}

    res.writeHead(404); res.end('not found');
  }
}

// If run directly, start server
if (require.main === module) {
  const s = new WebPushServer({ port: process.env.PORT || 80 });
  s.start();
}

// Export class
module.exports = WebPushServer;
