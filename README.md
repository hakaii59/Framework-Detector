# Framework Detector

A fast, lightweight CLI tool that identifies web frameworks and technologies by analyzing HTTP responses — headers, cookies, HTML patterns, error pages, and known paths.

Built for **security researchers**, **pentesters**, and **bug bounty hunters** who need quick recon on a target's tech stack.

## Features

- **50+ frameworks detected** — PHP (Laravel, Symfony, WordPress...), Python (Django, Flask, FastAPI), Node.js (Express, Next.js, Nuxt.js), Ruby (Rails), Java (Spring Boot), .NET, Go, and more
- **Multi-layer analysis** — HTTP headers, cookies (name + encrypted value), HTML content, 404 error page signatures, path probing
- **Laravel deep detection** — decodes cookie values to identify Laravel's encrypted format (`iv/value/mac`), catching renamed session cookies that other tools miss
- **Directory structure mapping** — shows the standard directory layout for each detected framework
- **Sensitive path suggestions** — lists interesting paths (`.env`, logs, config files, debug endpoints) with full URLs ready to test
- **Confidence scoring** — HIGH / MED / LOW based on number of matched indicators
- **Multi-threaded** path probing for speed
- **Cross-platform** — works on Windows, Linux, and macOS

## Installation

```bash
git clone https://github.com/hakaii59/Framework-Detector.git
cd Framework-Detector
pip install -r requirements.txt
```

## Usage

```bash
python detect.py https://example.com
python detect.py https://example.com --no-probe
python detect.py https://example.com -v --timeout 15
```

### Options

| Option | Description |
|---|---|
| `URL` | Target URL to scan (required) |
| `--no-probe` | Skip path probing — faster and stealthier |
| `--timeout N` | Request timeout in seconds (default: 10) |
| `--threads N` | Threads for path probing (default: 10) |
| `-v, --verbose` | Show detailed scan progress |

## Example Output

```
============================================================
  Framework Detector v2.0
  Target: http://target.com
============================================================

[Phase 1] Fetching main page...
  Status:       200
  Server:       nginx
  X-Powered-By: PHP/7.4.10
  Cookies:      app_session, token123

[Phase 2] Fetching 404 error page...
  Status: 404

[Phase 3] Probing 21 known paths...

============================================================
  RESULTS
============================================================

  [HIGH] #########            Laravel
         - Cookie name pattern '_session$': app_session
         - Cookie 'app_session' has Laravel encrypted format (iv/value/mac)
         - Cookie 'token123' has Laravel encrypted format (iv/value/mac)

  [MED ] ######               PHP
         - Header: X-Powered-By: PHP/7.4.10
         - HTML: .php"

  [LOW ] ###                  Nginx
         - Header: Server: nginx

============================================================
  DIRECTORY STRUCTURES & SENSITIVE PATHS
============================================================

  [ Laravel ]

  Directory Structure:
  /
  ├── app/Http/Controllers/
  ├── config/
  ├── database/migrations/
  ├── public/index.php
  ├── resources/views/
  ├── routes/web.php
  ├── storage/logs/laravel.log
  ├── .env
  └── composer.json

  Sensitive / Interesting Paths:
    > /.env                       http://target.com/.env
    > /storage/logs/laravel.log   http://target.com/storage/logs/laravel.log
    > /vendor/composer/installed  http://target.com/vendor/composer/installed.json
    > /.git/config                http://target.com/.git/config
    ...
```

## Supported Technologies

| Category | Frameworks |
|---|---|
| **PHP** | Laravel, Symfony, CodeIgniter, CakePHP, Yii, ThinkPHP |
| **PHP CMS** | WordPress, Drupal, Joomla, Magento |
| **Python** | Django, Flask, FastAPI, Tornado |
| **Node.js** | Express, Next.js, Nuxt.js, Gatsby, Remix, Astro |
| **Frontend** | React, Angular, Vue.js, Svelte/SvelteKit, jQuery |
| **Ruby** | Ruby on Rails, Sinatra |
| **Java** | Spring Boot, Apache Struts, JSF, Apache Tomcat |
| **.NET** | ASP.NET, Blazor |
| **Go** | Gin, Fiber |
| **Static Generators** | Jekyll, Hugo, Hexo, Pelican, GitBook, MkDocs, Docusaurus, VitePress |
| **Infrastructure** | Nginx, Apache, Cloudflare, Varnish, LiteSpeed, IIS, Caddy |

## How It Works

The tool runs three detection phases:

1. **Phase 1 — Main Page**: Fetches the homepage and analyzes HTTP headers, cookies (both names and encrypted values), and HTML content against a signature database
2. **Phase 2 — Error Page**: Triggers a 404 response and inspects the error page for framework-specific signatures (Whoops for Laravel, Whitelabel for Spring Boot, Werkzeug for Flask, etc.)
3. **Phase 3 — Path Probing**: Sends requests to known framework-specific paths (`/wp-login.php`, `/actuator`, `/docs`, `/admin/`, etc.)

After detection, it outputs:
- **Detected frameworks** with confidence level and evidence
- **Directory structure** of each detected framework
- **Sensitive paths** with full URLs for further investigation

## Contributing

Contributions are welcome! To add a new framework:

1. Add signature patterns to `framework_detector/signatures.py`
2. Add directory structure to `framework_detector/structures.py`
3. Test against a real instance
4. Submit a PR

## Disclaimer

This tool is intended for **authorized security testing** and **educational purposes** only. Always obtain proper authorization before scanning any target. The authors are not responsible for any misuse.

## License

[MIT](LICENSE)
