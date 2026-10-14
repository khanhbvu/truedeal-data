# truedeal-data

Daily, privacy-preserving scam/phishing blocklist for the TrueDeal extension.

- Source: [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) active domains (MIT).
- Safety filters: never lists big sites (built-in list + Tranco top 10,000) or hosting platforms themselves
  (weebly.com, github.io, …); only specific user subdomains on those platforms.
- Output: 4,096 files `shards/000.txt … fff.txt`, each holding SHA-256 fingerprints (first 16 hex chars)
  of hostnames. The extension fetches only the shard matching the site's fingerprint, so this server
  never learns which site a user visits.
- If a download fails or the list looks too small (< 1,000 entries), the build stops and the previous
  list stays live.

Files: `build-blocklist.js` (builder), `.github/workflows/build.yml` (daily job → GitHub Pages).
