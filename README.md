## Security Header Audit (OWASP-aligned)

The crawler performs a passive analysis of HTTP response headers for each page and assigns a **0–100 security score**. It flags issues and assigns **severity** (CRITICAL/HIGH/MEDIUM/LOW/INFO).

**Checks include:**
- HSTS presence & quality (max-age, includeSubDomains, downgrade redirects)
- CSP presence & risky directives (unsafe-inline/eval, wildcards)
- Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
- MIME sniffing (X-Content-Type-Options: nosniff)
- Referrer-Policy presence & strength
- Permissions-Policy basics
- Cookie hygiene (Secure/HttpOnly/SameSite, SameSite=None + Secure)
- CORS misconfigurations (ACAO '*' + credentials, broad methods)
- Caching on sensitive pages (no-store/no-cache)
- Server/framework version disclosure
- Deprecated headers (X-XSS-Protection)

Outputs:
- **Pages** CSV/JSON with per-page `security_score`
- **Issues** CSV/JSON with severities and recommendations
