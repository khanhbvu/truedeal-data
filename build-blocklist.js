#!/usr/bin/env node
// Builds TrueDeal's privacy-preserving blocklist from Phishing.Database (MIT license).
//
// Output (a static site, served from GitHub Pages):
//   shards/000.txt … shards/fff.txt   4,096 files; each line is the first 16 hex chars of
//                                      SHA-256(hostname). Shard = first 3 hex chars.
//   meta.json                          version, counts, sources
//   LICENSE.txt                        upstream MIT notice
//
// The extension hashes the site you visit and downloads only the one matching shard,
// so the server never sees which site you're on.
//
//   node build-blocklist.js --in phishing-domains-ACTIVE.txt [--tranco top.csv] --out site
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const argv = process.argv.slice(2);
const opt = (n, d) => {
  const i = argv.indexOf(n);
  return i >= 0 ? argv[i + 1] : d;
};
const IN = opt('--in');
const OUT = opt('--out', 'site');
const TRANCO = opt('--tranco');
const MIN_ENTRIES = Number(opt('--min', 1000)); // refuse to publish a suspiciously small list

// Hosting platforms whose *subdomains* belong to different people. A listed subdomain
// (evil.weebly.com) is kept; the platform itself (weebly.com) is never blocked.
const USER_CONTENT_PLATFORMS = [
  'weebly.com', 'weeblysite.com', 'wixsite.com', 'wix.com', 'github.io', 'gitbook.io', 'firebaseapp.com',
  'web.app', 'blogspot.com', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'glitch.me',
  'herokuapp.com', 'square.site', 'myshopify.com', 'godaddysites.com', 'webflow.io', 'wordpress.com',
  'sites.google.com', 'carrd.co', 'notion.site', 'framer.website', 'framer.app', 'squarespace.com',
  'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'appspot.com', 'repl.co', 'replit.app',
  'surge.sh', 'onrender.com', 'fly.dev', 'translate.goog', 'ipfs.io', 'dweb.link', 'jimdosite.com',
  'yolasite.com', 'strikingly.com', 'mystrikingly.com', 'ueniweb.com', 'business.site', 'linktr.ee'
];

// Never blocked even if they appear in the feed (big sites, US retailers, payment providers).
const BUILTIN_ALLOW = [
  'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'microsoft.com', 'live.com',
  'office.com', 'microsoftonline.com', 'apple.com', 'icloud.com', 'amazon.com', 'paypal.com', 'ebay.com',
  'walmart.com', 'target.com', 'bestbuy.com', 'costco.com', 'homedepot.com', 'lowes.com', 'etsy.com',
  'shopify.com', 'stripe.com', 'squareup.com', 'venmo.com', 'cash.app', 'zellepay.com', 'chase.com',
  'bankofamerica.com', 'wellsfargo.com', 'capitalone.com', 'usps.com', 'ups.com', 'fedex.com', 'dhl.com',
  'netflix.com', 'x.com', 'twitter.com', 'linkedin.com', 'tiktok.com', 'reddit.com', 'wikipedia.org',
  'github.com', 'dropbox.com', 'adobe.com', 'zoom.us', 'yahoo.com', 'aol.com', 'outlook.com', 'bing.com',
  'cloudflare.com', 'docusign.com', 'docusign.net', 'irs.gov', 'ssa.gov', 'usa.gov'
].concat(USER_CONTENT_PLATFORMS);

const MULTI_SUFFIXES = [
  'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'co.nz', 'co.jp', 'com.br', 'com.mx', 'co.in',
  'com.cn', 'com.hk', 'com.sg', 'co.za', 'com.tr', 'com.ar'
];

function registrable(h) {
  for (const p of USER_CONTENT_PLATFORMS) if (h === p || h.endsWith('.' + p)) {
    // Treat the platform like a public suffix: registrable = one label below it.
    if (h === p) return p;
    const rest = h.slice(0, -p.length - 1).split('.');
    return rest[rest.length - 1] + '.' + p;
  }
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join('.');
  return MULTI_SUFFIXES.includes(last2) ? parts.slice(-3).join('.') : last2;
}

function normalize(line) {
  let h = String(line).trim().toLowerCase();
  if (!h || h.startsWith('#') || h.startsWith('!')) return null;
  h = h.replace(/^[a-z]+:\/\//, '').split(/[\/?#:\s]/)[0].replace(/\.$/, '').replace(/^www\./, '');
  if (!/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(h)) return null; // also rejects IPs
  return h;
}

function hash16(host) {
  return crypto.createHash('sha256').update(host).digest('hex').slice(0, 16);
}

function underAny(host, list) {
  return list.some((d) => host === d || host.endsWith('.' + d));
}

function build(lines, trancoDomains) {
  const allow = new Set(BUILTIN_ALLOW.concat(trancoDomains || []));
  const stats = { input: lines.length, invalid: 0, duplicate: 0, allowlisted: 0, platformRoot: 0, kept: 0 };
  const kept = new Set();
  for (const line of lines) {
    const h = normalize(line);
    if (!h) {
      if (String(line).trim() && !/^[#!]/.test(String(line).trim())) stats.invalid++;
      continue;
    }
    if (kept.has(h)) {
      stats.duplicate++;
      continue;
    }
    // The platform itself, or a direct listing of a platform root: drop.
    if (USER_CONTENT_PLATFORMS.includes(h)) {
      stats.platformRoot++;
      continue;
    }
    const reg = registrable(h);
    const onPlatform = underAny(h, USER_CONTENT_PLATFORMS);
    // A popular/allowlisted site (or any subdomain of one) is never blocked, except
    // user-owned subdomains on hosting platforms (evil.weebly.com).
    if (!onPlatform && (allow.has(reg) || underAny(h, [...BUILTIN_ALLOW]))) {
      stats.allowlisted++;
      continue;
    }
    kept.add(h);
  }
  stats.kept = kept.size;
  const shards = new Map();
  for (const h of kept) {
    const x = hash16(h);
    const k = x.slice(0, 3);
    if (!shards.has(k)) shards.set(k, []);
    shards.get(k).push(x);
  }
  return { stats, shards, kept };
}

function readTranco(file) {
  if (!file || !fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .map((l) => (l.includes(',') ? l.split(',')[1] : l).trim().toLowerCase())
    .filter(Boolean)
    .map((d) => registrable(d.replace(/^www\./, '')));
}

function writeSite(out, result, sources) {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(path.join(out, 'shards'), { recursive: true });
  for (let i = 0; i < 4096; i++) {
    const k = i.toString(16).padStart(3, '0');
    const list = (result.shards.get(k) || []).sort();
    fs.writeFileSync(path.join(out, 'shards', k + '.txt'), list.join('\n') + (list.length ? '\n' : ''));
  }
  const meta = {
    version: new Date().toISOString(),
    entries: result.stats.kept,
    stats: result.stats,
    format: 'sha256(hostname).hex[0:16], sharded by first 3 hex chars; hostname lowercased, no www.',
    sources
  };
  fs.writeFileSync(path.join(out, 'meta.json'), JSON.stringify(meta, null, 2));
  fs.writeFileSync(
    path.join(out, 'LICENSE.txt'),
    'Derived from Phishing.Database (https://github.com/Phishing-Database/Phishing.Database)\n\n' +
      'MIT License\n\nCopyright (c) 2018-2025 Mitchell Krog, Nissar Chababy, and the Phishing.Database Contributors\n\n' +
      'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated ' +
      'documentation files (the "Software"), to deal in the Software without restriction, including without limitation ' +
      'the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to ' +
      'permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\n' +
      'The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\n' +
      'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE ' +
      'WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR ' +
      'COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR ' +
      'OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n'
  );
  fs.writeFileSync(
    path.join(out, 'index.html'),
    `<!doctype html><meta charset="utf-8"><title>TrueDeal data</title><body style="font:15px system-ui;max-width:640px;margin:40px auto;padding:0 16px">` +
      `<h1>TrueDeal blocklist data</h1><p>${result.stats.kept.toLocaleString('en-US')} hashed hostnames, updated ${meta.version.slice(0, 10)}.</p>` +
      `<p>Hashed, sharded data used by the TrueDeal browser extension. Derived from ` +
      `<a href="https://github.com/Phishing-Database/Phishing.Database">Phishing.Database</a> (MIT). See <a href="LICENSE.txt">LICENSE.txt</a> and <a href="meta.json">meta.json</a>.</p>`
  );
  fs.writeFileSync(path.join(out, '.nojekyll'), '');
  return meta;
}

module.exports = { normalize, registrable, hash16, build, writeSite };

if (require.main === module) {
  if (!IN || !fs.existsSync(IN)) {
    console.error('Usage: node build-blocklist.js --in phishing-domains-ACTIVE.txt [--tranco top.csv] --out site');
    process.exit(1);
  }
  const lines = fs.readFileSync(IN, 'utf8').split(/\r?\n/);
  const tranco = readTranco(TRANCO);
  const result = build(lines, tranco);
  console.log(`Tranco allowlist: ${tranco.length ? tranco.length + ' domains' : 'not provided (built-in list only)'}`);
  console.log('Stats:', JSON.stringify(result.stats));
  if (result.stats.kept < MIN_ENTRIES) {
    console.error(`Only ${result.stats.kept} entries kept (< ${MIN_ENTRIES}). Not publishing; the live list stays as it was.`);
    process.exit(1);
  }
  const meta = writeSite(OUT, result, {
    phishingDatabase: 'https://github.com/Phishing-Database/Phishing.Database (phishing-domains-ACTIVE.txt)',
    allowlist: tranco.length ? 'Tranco top sites + built-in list' : 'built-in list'
  });
  console.log(`Wrote ${OUT}/ (4096 shards, ${meta.entries} entries)`);
}
