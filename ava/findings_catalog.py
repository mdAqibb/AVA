"""Findings knowledge base.

One entry per detectable issue, holding the *static* report content: title,
CWE, OWASP category, a CVSS v3.1 vector, and the prose a developer needs
(description, root cause, impact, remediation + secure-code examples,
references). Check modules look up an entry by `check_id` and fill in the
*dynamic* parts (exact URL/param, evidence, confidence).

Keeping this content centralized makes the report consistent and makes it easy
to review/extend detection coverage without touching detection logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CatalogEntry:
    title: str
    cwe: str
    owasp: str
    cvss_vector: str
    description: str
    root_cause: str
    impact: str
    remediation: str
    remediation_code: dict = field(default_factory=dict)
    references: tuple = ()


CATALOG: dict[str, CatalogEntry] = {
    # ---- security headers --------------------------------------------------
    "header.csp.missing": CatalogEntry(
        title="Missing Content-Security-Policy header",
        cwe="CWE-693",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        description="The response does not set a Content-Security-Policy (CSP) "
                    "header. CSP is a defence-in-depth control that constrains "
                    "which scripts, styles, and other resources a page may load.",
        root_cause="The application/web server does not emit a CSP header, so "
                   "the browser applies no source restrictions and will execute "
                   "any inline or injected script the page contains.",
        impact="Removes a key mitigation against cross-site scripting and data "
               "injection: if an XSS flaw exists elsewhere, there is no CSP to "
               "blunt its impact (e.g. block inline script or exfiltration).",
        remediation="Send a restrictive CSP, starting from a deny-by-default "
                    "policy and explicitly allowing only required sources. "
                    "Prefer nonces/hashes over 'unsafe-inline'.",
        remediation_code={
            "python": "# Flask\n"
                      "@app.after_request\n"
                      "def csp(resp):\n"
                      "    resp.headers['Content-Security-Policy'] = (\n"
                      "        \"default-src 'self'; object-src 'none'; \"\n"
                      "        \"base-uri 'self'; frame-ancestors 'none'\")\n"
                      "    return resp",
            "node": "// Express + helmet\n"
                    "const helmet = require('helmet');\n"
                    "app.use(helmet.contentSecurityPolicy({\n"
                    "  directives: { defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"],\n"
                    "    baseUri: [\"'self'\"], frameAncestors: [\"'none'\"] }\n"
                    "}));",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/693.html",
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
        ),
    ),
    "header.hsts.missing": CatalogEntry(
        title="Missing HTTP Strict-Transport-Security header (HTTPS site)",
        cwe="CWE-319",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        description="The HTTPS response does not set Strict-Transport-Security, "
                    "so browsers are not told to enforce HTTPS for future visits.",
        root_cause="Without HSTS the browser will still honour http:// links and "
                   "manual address-bar entry over cleartext, leaving a window for "
                   "SSL-stripping/downgrade on the first or subsequent requests.",
        impact="An active network attacker can downgrade the connection to HTTP "
               "and intercept or modify traffic (credentials, session cookies).",
        remediation="Emit Strict-Transport-Security with a long max-age on all "
                    "HTTPS responses, ideally with includeSubDomains; consider "
                    "preloading once you are confident all subdomains are HTTPS.",
        remediation_code={
            "python": "# Flask\n"
                      "resp.headers['Strict-Transport-Security'] = \\\n"
                      "    'max-age=31536000; includeSubDomains'",
            "node": "// Express + helmet\n"
                    "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/319.html",
        ),
    ),
    "header.xcto.missing": CatalogEntry(
        title="Missing X-Content-Type-Options: nosniff header",
        cwe="CWE-693",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        description="The response omits X-Content-Type-Options: nosniff, allowing "
                    "browsers to MIME-sniff the body and reinterpret its type.",
        root_cause="Without nosniff, a browser may treat a response as a content "
                   "type other than the one declared, enabling content-type "
                   "confusion attacks.",
        impact="User-supplied content served with the wrong type could be "
               "interpreted as script/HTML, contributing to XSS.",
        remediation="Set X-Content-Type-Options: nosniff on all responses.",
        remediation_code={
            "python": "resp.headers['X-Content-Type-Options'] = 'nosniff'",
            "node": "app.use(helmet.noSniff());",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/693.html",
        ),
    ),
    "header.xfo.missing": CatalogEntry(
        title="Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
        cwe="CWE-1021",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        description="Neither X-Frame-Options nor a CSP frame-ancestors directive "
                    "is present, so the page can be framed by any origin.",
        root_cause="With no framing restriction, an attacker can embed the page "
                   "in a transparent iframe and trick users into interacting with "
                   "it (clickjacking / UI redress).",
        impact="Users can be tricked into performing unintended actions (e.g. "
               "state-changing clicks) on the application.",
        remediation="Set CSP 'frame-ancestors' (preferred) and/or "
                    "X-Frame-Options: DENY (or SAMEORIGIN where framing is needed).",
        remediation_code={
            "python": "resp.headers['X-Frame-Options'] = 'DENY'\n"
                      "# and/or include frame-ancestors 'none' in your CSP",
            "node": "app.use(helmet.frameguard({ action: 'deny' }));",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1021.html",
        ),
    ),
    "header.referrer.missing": CatalogEntry(
        title="Missing Referrer-Policy header",
        cwe="CWE-200",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        description="No Referrer-Policy is set, so the browser may send the full "
                    "URL (including sensitive path/query data) in the Referer "
                    "header to other origins.",
        root_cause="The default referrer behaviour can leak in-URL secrets (tokens, "
                   "IDs) to third-party sites linked from the page.",
        impact="Sensitive data embedded in URLs may leak to external origins via "
               "the Referer header.",
        remediation="Set Referrer-Policy to a privacy-preserving value such as "
                    "'strict-origin-when-cross-origin' or 'no-referrer'.",
        remediation_code={
            "python": "resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
            "node": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ),
    ),
    "info.server.version": CatalogEntry(
        title="Server software version disclosure",
        cwe="CWE-200",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        description="Response headers (Server / X-Powered-By) disclose specific "
                    "software and version information.",
        root_cause="Verbose server banners are emitted by default and not stripped, "
                   "revealing the technology stack and exact versions.",
        impact="Lets an attacker fingerprint the stack and target known CVEs for "
               "the disclosed versions, lowering the effort to find an exploit.",
        remediation="Suppress or genericise version banners (Server, X-Powered-By) "
                    "at the application and reverse-proxy layers.",
        remediation_code={
            "python": "# Flask: remove the header before responding\n"
                      "resp.headers['Server'] = 'web'\n"
                      "resp.headers.pop('X-Powered-By', None)",
            "node": "// Express\napp.disable('x-powered-by');",
        },
        references=(
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ),
    ),
    # ---- cookies -----------------------------------------------------------
    "cookie.secure.missing": CatalogEntry(
        title="Cookie set without the Secure attribute",
        cwe="CWE-614",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        description="A cookie is set without the Secure attribute, so it may be "
                    "transmitted over unencrypted HTTP.",
        root_cause="The Secure flag was not set when the cookie was issued, so "
                   "the browser will include it on cleartext requests.",
        impact="A network attacker can capture the cookie (e.g. a session token) "
               "over HTTP, enabling session hijacking.",
        remediation="Set the Secure attribute on all cookies, especially session "
                    "and authentication cookies.",
        remediation_code={
            "python": "# Flask\napp.config['SESSION_COOKIE_SECURE'] = True\n"
                      "# or: resp.set_cookie('sid', v, secure=True, httponly=True, samesite='Lax')",
            "node": "// Express\nres.cookie('sid', v, { secure: true, httpOnly: true, sameSite: 'lax' });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/614.html",
        ),
    ),
    "cookie.httponly.missing": CatalogEntry(
        title="Cookie set without the HttpOnly attribute",
        cwe="CWE-1004",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        description="A cookie is set without HttpOnly, so it is readable by "
                    "client-side JavaScript.",
        root_cause="The HttpOnly flag was not set, leaving the cookie exposed to "
                   "the DOM and to any injected script.",
        impact="If an XSS flaw exists, the cookie (e.g. session token) can be "
               "stolen via document.cookie.",
        remediation="Set HttpOnly on session/auth cookies that do not need to be "
                    "read by JavaScript.",
        remediation_code={
            "python": "app.config['SESSION_COOKIE_HTTPONLY'] = True",
            "node": "res.cookie('sid', v, { httpOnly: true, secure: true, sameSite: 'lax' });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1004.html",
        ),
    ),
    "cookie.samesite.missing": CatalogEntry(
        title="Cookie set without a SameSite attribute",
        cwe="CWE-1275",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        description="A cookie is set without an explicit SameSite attribute.",
        root_cause="Without SameSite the cookie may be sent on cross-site requests, "
                   "weakening CSRF defences (browser defaults vary).",
        impact="Increases exposure to cross-site request forgery against "
               "state-changing endpoints.",
        remediation="Set SameSite explicitly (Lax or Strict) on session cookies; "
                    "use None only with Secure for legitimate cross-site needs.",
        remediation_code={
            "python": "app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'",
            "node": "res.cookie('sid', v, { sameSite: 'lax', secure: true, httpOnly: true });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1275.html",
        ),
    ),
    # ---- TLS ---------------------------------------------------------------
    "tls.weak_protocol": CatalogEntry(
        title="Server supports a weak/deprecated TLS protocol version",
        cwe="CWE-326",
        owasp="A02:2021 Cryptographic Failures",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description="The server negotiates a deprecated protocol (SSLv2/v3, "
                    "TLS 1.0 or TLS 1.1) known to have cryptographic weaknesses.",
        root_cause="Legacy protocol versions remain enabled in the TLS "
                   "configuration for backward compatibility.",
        impact="Deprecated protocols are vulnerable to known attacks (e.g. POODLE, "
               "BEAST), potentially exposing data in transit.",
        remediation="Disable SSLv2/v3, TLS 1.0 and 1.1; require TLS 1.2+ (prefer "
                    "1.3) with a modern cipher suite.",
        remediation_code={
            "python": "# nginx\nssl_protocols TLSv1.2 TLSv1.3;\n"
                      "ssl_prefer_server_ciphers on;",
            "node": "// Node TLS server\nhttps.createServer({ minVersion: 'TLSv1.2', /* ... */ });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/326.html",
        ),
    ),
    "tls.cert_expiring": CatalogEntry(
        title="TLS certificate expired or expiring soon",
        cwe="CWE-298",
        owasp="A02:2021 Cryptographic Failures",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        description="The server's TLS certificate has expired or is close to "
                    "expiry.",
        root_cause="Certificate lifecycle/renewal automation is missing or failing.",
        impact="An expired certificate breaks trust, triggers browser warnings, "
               "and trains users to click through security errors.",
        remediation="Renew the certificate and automate renewal (e.g. ACME/"
                    "Let's Encrypt) with monitoring/alerting on expiry.",
        remediation_code={},
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/298.html",
        ),
    ),
    # ---- information disclosure / exposed files ----------------------------
    "disclosure.exposed_file": CatalogEntry(
        title="Sensitive file exposed",
        cwe="CWE-538",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description="A sensitive file or path is reachable over HTTP and returns "
                    "content.",
        root_cause="Deployment artefacts or VCS/config files are served by the "
                   "web server instead of being excluded from the web root.",
        impact="May disclose source code, credentials, internal configuration, or "
               "repository history — high-value reconnaissance for an attacker.",
        remediation="Remove these files from the web root, deny access at the "
                    "server, and exclude deployment/VCS artefacts from releases.",
        remediation_code={
            "python": "# nginx — deny dotfiles and VCS dirs\n"
                      "location ~ /\\.(git|env|svn) { deny all; return 404; }",
            "node": "// Do not serve the project root; serve only a built /public dir\n"
                    "app.use(express.static('public'));",
        },
        references=(
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/538.html",
        ),
    ),
    "disclosure.directory_listing": CatalogEntry(
        title="Directory listing enabled",
        cwe="CWE-548",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        description="A directory returns an auto-generated index of its contents.",
        root_cause="Automatic directory indexing is enabled on the web server.",
        impact="Reveals file names and structure, aiding discovery of sensitive "
               "or unlinked resources.",
        remediation="Disable automatic directory indexing on the web server.",
        remediation_code={
            "python": "# nginx\nautoindex off;",
            "node": "// serve-index / express.static: do not enable directory listing",
        },
        references=(
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/548.html",
        ),
    ),
    "disclosure.stack_trace": CatalogEntry(
        title="Verbose error / stack trace disclosure",
        cwe="CWE-209",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        description="A response contains a stack trace or detailed framework error "
                    "message.",
        root_cause="The application runs with debug/verbose error output enabled "
                   "in a reachable environment.",
        impact="Leaks file paths, library versions, and internal logic that help "
               "an attacker craft further attacks.",
        remediation="Disable debug mode in production; return generic error pages "
                    "and log details server-side only.",
        remediation_code={
            "python": "# Flask / Django\napp.config['DEBUG'] = False  # Flask\n"
                      "DEBUG = False  # Django settings.py",
            "node": "// Express: add a generic error handler; do not send err.stack\n"
                    "app.use((err, req, res, next) => { res.status(500).send('Internal Server Error'); });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/209.html",
        ),
    ),
    # ---- active: injection -------------------------------------------------
    "injection.sqli": CatalogEntry(
        title="SQL injection",
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        description="A parameter is concatenated into a SQL query without "
                    "parameterization, allowing the query structure to be altered "
                    "by attacker-controlled input.",
        root_cause="User input is interpolated directly into SQL text (string "
                   "building / format strings) instead of being passed as a bound "
                   "parameter, so input can change the parsed query.",
        impact="Read or modify arbitrary database data, bypass authentication, "
               "and in some configurations achieve code execution on the DB host.",
        remediation="Use parameterized queries / prepared statements everywhere; "
                    "never build SQL by string concatenation. Use an ORM safely "
                    "(avoid raw fragments with interpolation) and apply least "
                    "privilege to the DB account.",
        remediation_code={
            "python": "# psycopg2 / sqlite3 — bind parameters, do NOT f-string\n"
                      "cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                      "# Django ORM\nUser.objects.filter(id=user_id)",
            "node": "// node-postgres — parameterized\n"
                    "await client.query('SELECT * FROM users WHERE id = $1', [userId]);\n"
                    "// Prisma\nprisma.user.findUnique({ where: { id: userId } });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ),
    ),
    "injection.command": CatalogEntry(
        title="OS command injection",
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="A parameter is incorporated into an OS command, allowing "
                    "injection of additional shell commands.",
        root_cause="User input reaches a shell-invoking call (e.g. a shell=True "
                   "subprocess or backticks) without strict validation or argument "
                   "separation, so shell metacharacters are interpreted.",
        impact="Execute arbitrary commands on the server with the application's "
               "privileges — full host compromise in many cases.",
        remediation="Avoid invoking a shell. Pass arguments as a list to the "
                    "process API (no shell), validate against a strict allow-list, "
                    "and never pass user input to a shell string.",
        remediation_code={
            "python": "# subprocess WITHOUT a shell, args as a list\n"
                      "subprocess.run(['ping', '-c', '1', host], shell=False, check=True)\n"
                      "# validate `host` against an allow-list / regex first",
            "node": "// execFile (no shell) instead of exec\n"
                    "const { execFile } = require('child_process');\n"
                    "execFile('ping', ['-c', '1', host]);",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ),
    ),
    "injection.template": CatalogEntry(
        title="Server-side template injection (SSTI)",
        cwe="CWE-1336",
        owasp="A03:2021 Injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="User input is evaluated as a template expression by a "
                    "server-side template engine, as evidenced by an injected "
                    "arithmetic expression being evaluated in the response.",
        root_cause="Untrusted input is concatenated into a template string and "
                   "then rendered, so the engine evaluates attacker-supplied "
                   "expressions instead of treating them as data.",
        impact="Often escalates to remote code execution via the template "
               "engine's object model; at minimum discloses server-side data.",
        remediation="Never render templates built from user input. Pass user data "
                    "as template *variables/context*, not as part of the template "
                    "source; use a sandboxed environment where unavoidable.",
        remediation_code={
            "python": "# Jinja2 — pass data as context, do NOT build the template\n"
                      "tmpl = env.get_template('page.html')\n"
                      "tmpl.render(name=user_input)   # NOT Template('Hi '+user_input)",
            "node": "// Pass variables to the engine; never concatenate into source\n"
                    "res.render('page', { name: userInput });",
        },
        references=(
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/1336.html",
        ),
    ),
    # ---- active: XSS -------------------------------------------------------
    "xss.reflected": CatalogEntry(
        title="Reflected cross-site scripting (XSS)",
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        description="A request parameter is reflected into the response without "
                    "context-appropriate output encoding, and HTML-significant "
                    "characters survive unescaped.",
        root_cause="Output encoding is missing or wrong for the context in which "
                   "the value is placed (HTML body, attribute, JS, URL), so markup "
                   "supplied in the request is rendered as markup.",
        impact="Execute script in a victim's browser in the site's origin: steal "
               "session tokens, perform actions as the user, or deface content.",
        remediation="Apply context-aware output encoding at every sink, prefer "
                    "framework auto-escaping, and add a strict CSP as defence in "
                    "depth. Validate input but do not rely on it alone.",
        remediation_code={
            "python": "# Jinja2 autoescaping is on for .html templates — keep it on\n"
                      "# Django templates autoescape by default; avoid |safe on user data\n"
                      "from markupsafe import escape\nreturn escape(user_input)",
            "node": "// Escape on output; if using a templating engine keep autoescape on\n"
                    "const escapeHtml = s => s.replace(/[&<>\"']/g, c =>\n"
                    "  ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ),
    ),
    "xss.stored": CatalogEntry(
        title="Stored cross-site scripting (XSS)",
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        description="Input submitted to the application is later served back "
                    "unescaped to other users, persisting an XSS payload.",
        root_cause="Stored user input is rendered without output encoding when "
                   "displayed, so injected markup persists and executes for every "
                   "viewer.",
        impact="Persistent script execution against any user who views the "
               "content — broad session theft / account takeover potential.",
        remediation="Encode on output for the rendering context, keep framework "
                    "auto-escaping on, sanitize rich-text server-side with a "
                    "vetted allow-list sanitizer, and apply a strict CSP.",
        remediation_code={
            "python": "# Sanitize rich text server-side with an allow-list (bleach)\n"
                      "import bleach\nclean = bleach.clean(user_html, tags=ALLOWED, strip=True)",
            "node": "// DOMPurify (server-side via jsdom) for rich text\n"
                    "const clean = DOMPurify.sanitize(userHtml, { ALLOWED_TAGS: allowed });",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ),
    ),
    "xss.dom": CatalogEntry(
        title="DOM-based XSS sink (candidate)",
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        description="Client-side JavaScript flows a controllable source (e.g. "
                    "location.hash/search) into a dangerous sink (innerHTML, "
                    "document.write, eval) — a likely DOM XSS site for review.",
        root_cause="Browser-side code writes attacker-influenceable data into an "
                   "HTML/script sink without sanitization, so the DOM is modified "
                   "with untrusted markup.",
        impact="Script execution in the victim's browser driven entirely on the "
               "client, often without the payload ever reaching the server logs.",
        remediation="Use safe sink APIs (textContent, setAttribute) instead of "
                    "innerHTML; sanitize with DOMPurify before any HTML sink; "
                    "avoid eval/Function on dynamic input.",
        remediation_code={
            "node": "// Prefer textContent; sanitize before innerHTML\n"
                    "el.textContent = userValue;            // safe\n"
                    "el.innerHTML = DOMPurify.sanitize(userValue);  // if HTML needed",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ),
    ),
    # ---- active: redirect / SSRF ------------------------------------------
    "redirect.open": CatalogEntry(
        title="Open redirect",
        cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        description="A redirect parameter sends the browser to an attacker-"
                    "controlled, off-site URL without validation.",
        root_cause="The redirect destination is taken from user input and used "
                   "without checking it against an allow-list of permitted "
                   "targets.",
        impact="Enables convincing phishing (trusted domain in the link), and can "
               "aid OAuth token theft and filter bypass.",
        remediation="Redirect only to a server-side allow-list of paths, or map an "
                    "opaque token to a destination. Reject absolute/off-site URLs.",
        remediation_code={
            "python": "# Validate against allow-list; only allow relative paths\n"
                      "from urllib.parse import urlparse\n"
                      "if urlparse(nxt).netloc:  # absolute URL -> reject\n"
                      "    nxt = '/'\nreturn redirect(nxt)",
            "node": "// Only permit known internal paths\n"
                    "const allow = new Set(['/home','/dashboard']);\n"
                    "res.redirect(allow.has(next) ? next : '/');",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ),
    ),
    "ssrf.candidate": CatalogEntry(
        title="Server-side request forgery (candidate)",
        cwe="CWE-918",
        owasp="A10:2021 Server-Side Request Forgery",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
        description="A parameter accepts a URL/host that the server appears to "
                    "fetch. Flagged for manual confirmation (safe automated "
                    "confirmation needs an out-of-band interaction endpoint).",
        root_cause="The server makes an outbound request to a user-supplied "
                   "destination without restricting the target, allowing access "
                   "to internal services and metadata endpoints.",
        impact="Reach internal-only services, cloud metadata (credentials), and "
               "pivot within the internal network.",
        remediation="Allow-list permitted hosts/schemes, resolve and validate the "
                    "target against internal ranges (block RFC1918/link-local/"
                    "metadata IPs), and disable unneeded redirect following.",
        remediation_code={
            "python": "# Resolve & block internal targets before fetching\n"
                      "import ipaddress, socket\n"
                      "ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
                      "if ip.is_private or ip.is_link_local: abort(400)",
            "node": "// Validate host against an allow-list and block private IPs\n"
                    "if (isPrivateIp(await resolve(host))) throw new Error('blocked');",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
    ),
    # ---- active: access control / CSRF / CORS -----------------------------
    "access.idor_candidate": CatalogEntry(
        title="Insecure direct object reference (candidate)",
        cwe="CWE-639",
        owasp="A01:2021 Broken Access Control",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        description="An endpoint exposes a direct object identifier (numeric/UUID) "
                    "in a parameter. Flagged for manual access-control testing — "
                    "automated confirmation requires authenticated multi-user "
                    "context.",
        root_cause="Object access is keyed on a client-supplied identifier without "
                   "a server-side authorization check that the current user may "
                   "access that object.",
        impact="If authorization is missing, an attacker can read or modify other "
               "users' records by changing the identifier.",
        remediation="Enforce per-object authorization on every access (check the "
                    "object belongs to / is permitted for the current principal); "
                    "consider unguessable identifiers as defence in depth.",
        remediation_code={
            "python": "# Scope the query to the current user\n"
                      "obj = Document.objects.get(id=doc_id, owner=request.user)",
            "node": "// Verify ownership before returning\n"
                    "const doc = await Doc.findOne({ _id: id, owner: req.user.id });\n"
                    "if (!doc) return res.sendStatus(403);",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
        ),
    ),
    "csrf.missing_token": CatalogEntry(
        title="State-changing form without anti-CSRF token",
        cwe="CWE-352",
        owasp="A01:2021 Broken Access Control",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        description="A POST form carries no detectable anti-CSRF token, so a "
                    "cross-site request could submit it on a victim's behalf.",
        root_cause="The form/endpoint relies only on ambient cookies for state "
                   "and lacks a per-request unpredictable token (or SameSite "
                   "protection).",
        impact="An attacker page can force the authenticated victim's browser to "
               "perform the state-changing action without consent.",
        remediation="Use the framework's CSRF protection (synchronizer token or "
                    "double-submit), and set SameSite=Lax/Strict on session "
                    "cookies as defence in depth.",
        remediation_code={
            "python": "# Flask-WTF / Django provide CSRF tokens out of the box\n"
                      "# Django template: {% csrf_token %} inside the <form>",
            "node": "// csurf middleware (or framework equivalent)\n"
                    "app.use(csurf()); // render res.locals csrfToken into the form",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
        ),
    ),
    "cors.misconfig": CatalogEntry(
        title="CORS misconfiguration (overly permissive)",
        cwe="CWE-942",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        description="The server reflects an arbitrary Origin into "
                    "Access-Control-Allow-Origin (or uses '*' together with "
                    "credentials), trusting cross-origin callers it should not.",
        root_cause="The CORS policy echoes the request Origin without validating "
                   "it against an allow-list, or combines a wildcard origin with "
                   "Allow-Credentials.",
        impact="A malicious origin can read authenticated cross-origin responses, "
               "exposing user data and tokens.",
        remediation="Reflect only origins from a strict server-side allow-list; "
                    "never combine Access-Control-Allow-Credentials: true with a "
                    "wildcard or reflected arbitrary origin.",
        remediation_code={
            "python": "# Flask-CORS — explicit allow-list, not '*'\n"
                      "CORS(app, origins=['https://app.example.com'], supports_credentials=True)",
            "node": "// cors — validate against an allow-list\n"
                    "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
        },
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/942.html",
        ),
    ),
}


def get(check_id: str) -> CatalogEntry:
    return CATALOG[check_id]
