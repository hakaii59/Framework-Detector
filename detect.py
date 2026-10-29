#!/usr/bin/env python3
"""Web Framework Detector — identifies server-side and client-side frameworks
by inspecting HTTP headers, cookies, HTML content, and probing known paths."""

import argparse
import base64
import json
import re
import sys
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()

# ── Signature database ────────────────────────────────────────────────────────
# Each entry has:
#   cookies  — regex matched against cookie names
#   headers  — regex matched against "Header-Name: value" string
#   html     — regex matched against the page body
#   paths    — paths to probe (HTTP < 400 = match)
#   error_pages — regex matched against 404 error page body

SIGNATURES = {
    # ═══════════════════════════════════════════════════════════
    # PHP
    # ═══════════════════════════════════════════════════════════
    "Laravel": {
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "cookie_name_patterns": [r"_session$"],
        "cookie_value_checks": ["laravel_encrypted"],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']csrf-token["\']',
            r'name=["\']_token["\']',
        ],
        "paths": [
            "/storage/logs/laravel.log",
            "/vendor/laravel",
        ],
        "error_pages": [
            r"Whoops!?\s",
            r"Ignition",
            r"IlluminateFoundation",
            r"laravel",
        ],
    },
    "Symfony": {
        "cookies": [r"^symfony$"],
        "headers": [r"^X-Debug-Token:", r"^X-Debug-Token-Link:"],
        "html": [r"sf-toolbar", r"/_profiler"],
        "paths": ["/_profiler", "/app_dev.php"],
        "error_pages": [r"Symfony\\\\", r"Symfony Exception"],
    },
    "CodeIgniter": {
        "cookies": [r"^ci_session$"],
        "headers": [],
        "html": [r"/index\.php/\w+/\w+"],
        "paths": [],
        "error_pages": [r"CodeIgniter"],
    },
    "CakePHP": {
        "cookies": [r"^cakephp$", r"^csrfToken$"],
        "headers": [],
        "html": [r"cakephp"],
        "paths": [],
        "error_pages": [r"CakePHP", r"Missing Controller"],
    },
    "Yii": {
        "cookies": [r"^YII_CSRF_TOKEN$", r"^_csrf$"],
        "headers": [],
        "html": [r"yii\.js", r'class=["\'][^"\']*yii-'],
        "paths": [],
        "error_pages": [r"yii\\\\web\\\\", r"CHttpException"],
    },
    "ThinkPHP": {
        "cookies": [r"^think_"],
        "headers": [r"X-Powered-By:\s*ThinkPHP"],
        "html": [r"thinkphp"],
        "paths": [],
        "error_pages": [r"ThinkPHP", r"think\\\\"],
    },

    # ═══════════════════════════════════════════════════════════
    # PHP CMS
    # ═══════════════════════════════════════════════════════════
    "WordPress": {
        "cookies": [r"^wordpress_", r"^wp-settings-"],
        "headers": [r"^Link:.*wp-json"],
        "html": [
            r"/wp-content/",
            r"/wp-includes/",
            r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress',
        ],
        "paths": ["/wp-login.php", "/wp-json/"],
        "error_pages": [],
    },
    "Drupal": {
        "cookies": [r"^SESS[0-9a-f]{20,}$"],
        "headers": [r"^X-Generator:\s*Drupal"],
        "html": [r"/sites/default/files", r'content="Drupal'],
        "paths": ["/core/misc/drupal.js"],
        "error_pages": [],
    },
    "Joomla": {
        "cookies": [r"^joomla_"],
        "headers": [],
        "html": [
            r"/media/jui/",
            r"/media/system/js/",
            r'content="Joomla',
        ],
        "paths": ["/administrator/"],
        "error_pages": [],
    },
    "Magento": {
        "cookies": [r"^PHPSESSID$", r"^mage-"],
        "headers": [],
        "html": [r"/static/version", r"Magento", r"mage/cookies"],
        "paths": ["/magento_version"],
        "error_pages": [],
    },

    # ═══════════════════════════════════════════════════════════
    # Python
    # ═══════════════════════════════════════════════════════════
    "Django": {
        "cookies": [r"^csrftoken$", r"^sessionid$"],
        "headers": [],
        "html": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "paths": ["/admin/login/"],
        "error_pages": [
            r"DEBUG = True",
            r"DisallowedHost",
            r"You.re seeing this error because",
            r"django",
        ],
    },
    "Flask": {
        "cookies": [],
        "headers": [r"^Server:\s*Werkzeug"],
        "html": [],
        "paths": [],
        "error_pages": [r"Werkzeug Debugger", r"Werkzeug/"],
    },
    "FastAPI": {
        "cookies": [],
        "headers": [r"^server:\s*uvicorn"],
        "html": [r"FastAPI"],
        "paths": ["/docs", "/openapi.json", "/redoc"],
        "error_pages": [r'"detail":\s*"Not Found"'],
    },
    "Tornado": {
        "cookies": [],
        "headers": [r"^Server:\s*TornadoServer"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },

    # ═══════════════════════════════════════════════════════════
    # JavaScript / Node.js
    # ═══════════════════════════════════════════════════════════
    "Express": {
        "cookies": [r"^connect\.sid$"],
        "headers": [r"^X-Powered-By:\s*Express"],
        "html": [],
        "paths": [],
        "error_pages": [r"Cannot GET /", r"Cannot POST /"],
    },
    "Next.js": {
        "cookies": [],
        "headers": [r"^X-Powered-By:\s*Next\.js", r"^x-nextjs-"],
        "html": [
            r"/_next/static/",
            r"/_next/data/",
            r'id=["\']__next["\']',
            r"__NEXT_DATA__",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Nuxt.js": {
        "cookies": [],
        "headers": [],
        "html": [
            r"/_nuxt/",
            r'id=["\']__nuxt["\']',
            r"__NUXT__",
            r"nuxt\.js",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Gatsby": {
        "cookies": [],
        "headers": [r"^x-powered-by:\s*Gatsby"],
        "html": [
            r'id=["\']___gatsby["\']',
            r"/page-data/",
            r"gatsby-",
        ],
        "paths": ["/page-data/index/page-data.json"],
        "error_pages": [],
    },
    "Remix": {
        "cookies": [],
        "headers": [],
        "html": [
            r"__remixContext",
            r"__remixManifest",
            r"remix",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Astro": {
        "cookies": [],
        "headers": [],
        "html": [
            r"astro-island",
            r"astro-slot",
            r'<meta\s+name=["\']generator["\']\s+content=["\']Astro',
        ],
        "paths": [],
        "error_pages": [],
    },

    # ── Frontend libraries ──
    "React": {
        "cookies": [],
        "headers": [],
        "html": [
            r'id=["\']root["\']>\s*</div>',
            r"/static/js/main\.\w+\.js",
            r"_reactRootContainer",
            r"react\.production",
            r"react-dom",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Angular": {
        "cookies": [],
        "headers": [],
        "html": [
            r"<app-root[\s>]",
            r'ng-version=["\']',
            r"zone\.js",
            r"polyfills\.\w+\.js",
            r"ng-app=",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Vue.js": {
        "cookies": [],
        "headers": [],
        "html": [
            r"vue[\.-]",
            r"vue\.runtime",
            r"data-v-[0-9a-f]{6,}",
            r"__vue__",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Svelte / SvelteKit": {
        "cookies": [],
        "headers": [],
        "html": [
            r"__sveltekit/",
            r"svelte-[a-z0-9]+",
            r'class=["\'][^"\']*svelte-',
        ],
        "paths": [],
        "error_pages": [],
    },
    "jQuery": {
        "cookies": [],
        "headers": [],
        "html": [r"jquery[\.-]\d", r"jquery\.min\.js"],
        "paths": [],
        "error_pages": [],
    },

    # ═══════════════════════════════════════════════════════════
    # Ruby
    # ═══════════════════════════════════════════════════════════
    "Ruby on Rails": {
        "cookies": [r"_\w+_session"],
        "headers": [
            r"^X-Powered-By:\s*Phusion Passenger",
            r"^Server:\s*Puma",
        ],
        "html": [
            r'<meta\s+name=["\']csrf-param["\']',
            r"rails-ujs",
            r"turbolinks",
            r"data-turbo-",
            r"actioncable",
        ],
        "paths": ["/rails/info/routes"],
        "error_pages": [r"Action Controller", r"Routing Error"],
    },
    "Sinatra": {
        "cookies": [],
        "headers": [r"^X-Powered-By:\s*Sinatra"],
        "html": [],
        "paths": [],
        "error_pages": [r"Sinatra doesn.t know this ditty"],
    },

    # ═══════════════════════════════════════════════════════════
    # Java
    # ═══════════════════════════════════════════════════════════
    "Spring Boot": {
        "cookies": [r"^JSESSIONID$"],
        "headers": [r"^X-Application-Context:"],
        "html": [],
        "paths": ["/actuator", "/actuator/health", "/actuator/info"],
        "error_pages": [
            r"Whitelabel Error Page",
            r"There was an unexpected error",
        ],
    },
    "Apache Struts": {
        "cookies": [],
        "headers": [],
        "html": [
            r'action=["\'][^"\']*\.action["\']',
            r'href=["\'][^"\']*\.do["\']',
        ],
        "paths": [],
        "error_pages": [r"Struts Problem Report", r"struts2"],
    },
    "JSF": {
        "cookies": [],
        "headers": [],
        "html": [
            r"javax\.faces",
            r"jsf\.js",
            r'action=["\'][^"\']*\.xhtml["\']',
        ],
        "paths": [],
        "error_pages": [],
    },
    "Apache Tomcat": {
        "cookies": [],
        "headers": [],
        "html": [],
        "paths": ["/manager/html"],
        "error_pages": [r"Apache Tomcat"],
    },

    # ═══════════════════════════════════════════════════════════
    # .NET
    # ═══════════════════════════════════════════════════════════
    "ASP.NET": {
        "cookies": [r"^ASP\.NET_SessionId$", r"^\.AspNetCore\."],
        "headers": [r"^X-Powered-By:\s*ASP\.NET", r"^X-AspNet-Version:"],
        "html": [
            r"__VIEWSTATE",
            r"__EVENTVALIDATION",
            r"aspnetForm",
        ],
        "paths": [],
        "error_pages": [
            r"Server Error in .* Application",
            r"ASP\.NET",
            r"X-AspNet-Version",
        ],
    },
    "Blazor": {
        "cookies": [],
        "headers": [],
        "html": [r"_framework/blazor", r"blazor\.web\.js", r"blazor\.server"],
        "paths": ["/_framework/blazor.boot.json"],
        "error_pages": [],
    },

    # ═══════════════════════════════════════════════════════════
    # Go
    # ═══════════════════════════════════════════════════════════
    "Gin (Go)": {
        "cookies": [],
        "headers": [],
        "html": [],
        "paths": [],
        "error_pages": [r"gin-gonic"],
    },
    "Fiber (Go)": {
        "cookies": [],
        "headers": [r"^X-Powered-By:\s*Fiber"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },

    # ═══════════════════════════════════════════════════════════
    # Static site generators
    # ═══════════════════════════════════════════════════════════
    "Jekyll": {
        "cookies": [],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']generator["\']\s+content=["\']Jekyll',
            r"jekyll",
            r"/assets/css/style\.css\?v=",
        ],
        "paths": ["/feed.xml"],
        "error_pages": [],
    },
    "Hugo": {
        "cookies": [],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']generator["\']\s+content=["\']Hugo',
            r"hugo-",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Hexo": {
        "cookies": [],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']generator["\']\s+content=["\']Hexo',
            r"hexo-",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Pelican": {
        "cookies": [],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']generator["\']\s+content=["\']Pelican',
        ],
        "paths": [],
        "error_pages": [],
    },
    "GitBook": {
        "cookies": [],
        "headers": [],
        "html": [r"gitbook", r"GitBook"],
        "paths": [],
        "error_pages": [],
    },
    "MkDocs": {
        "cookies": [],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']generator["\']\s+content=["\']mkdocs',
            r"mkdocs",
        ],
        "paths": [],
        "error_pages": [],
    },
    "Docusaurus": {
        "cookies": [],
        "headers": [],
        "html": [
            r'<meta\s+name=["\']generator["\']\s+content=["\']Docusaurus',
            r"docusaurus",
        ],
        "paths": [],
        "error_pages": [],
    },
    "VitePress": {
        "cookies": [],
        "headers": [],
        "html": [r"vitepress", r"VPContent"],
        "paths": [],
        "error_pages": [],
    },

    # ═══════════════════════════════════════════════════════════
    # Language detection (from headers)
    # ═══════════════════════════════════════════════════════════
    "PHP": {
        "cookies": [r"^PHPSESSID$"],
        "headers": [r"^X-Powered-By:\s*PHP"],
        "html": [r'\.php["\'\?\s>]'],
        "paths": [],
        "error_pages": [r"Fatal error:", r"Parse error:"],
    },

    # ═══════════════════════════════════════════════════════════
    # Infrastructure / CDN / Servers
    # ═══════════════════════════════════════════════════════════
    "Nginx": {
        "cookies": [],
        "headers": [r"^Server:\s*nginx"],
        "html": [],
        "paths": [],
        "error_pages": [r"<title>\d+ nginx", r"nginx/\d"],
    },
    "Apache HTTPD": {
        "cookies": [],
        "headers": [r"^Server:\s*Apache"],
        "html": [],
        "paths": [],
        "error_pages": [r"Apache/\d"],
    },
    "Cloudflare": {
        "cookies": [r"^__cf_bm$", r"^cf_clearance$"],
        "headers": [r"^Server:\s*cloudflare", r"^cf-ray:"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },
    "Varnish": {
        "cookies": [],
        "headers": [r"^Via:.*varnish", r"^X-Varnish:"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },
    "LiteSpeed": {
        "cookies": [],
        "headers": [r"^Server:\s*LiteSpeed"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },
    "IIS": {
        "cookies": [],
        "headers": [r"^Server:\s*Microsoft-IIS"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },
    "Caddy": {
        "cookies": [],
        "headers": [r"^Server:\s*Caddy"],
        "html": [],
        "paths": [],
        "error_pages": [],
    },
}

# ── Directory structure database ──────────────────────────────────────────────

DIRECTORY_STRUCTURES = {
    "Laravel": {
        "tree": r"""
  /
  ├── app/
  │   ├── Console/              # Artisan commands
  │   ├── Exceptions/           # Exception handlers
  │   ├── Http/
  │   │   ├── Controllers/      # Route controllers
  │   │   ├── Middleware/        # HTTP middleware
  │   │   └── Requests/         # Form request validation
  │   ├── Models/               # Eloquent models
  │   └── Providers/            # Service providers
  ├── bootstrap/
  │   └── cache/                # Framework cache (routes, config)
  ├── config/                   # All configuration files
  │   ├── app.php
  │   ├── database.php
  │   └── ...
  ├── database/
  │   ├── factories/            # Model factories
  │   ├── migrations/           # DB migrations
  │   └── seeders/              # DB seeders
  ├── public/                   # Web root (index.php, assets)
  │   └── index.php             # Entry point
  ├── resources/
  │   ├── views/                # Blade templates (.blade.php)
  │   ├── css/
  │   └── js/
  ├── routes/
  │   ├── web.php               # Web routes
  │   ├── api.php               # API routes
  │   └── console.php
  ├── storage/
  │   ├── app/                  # App-generated files
  │   ├── framework/
  │   │   ├── cache/
  │   │   ├── sessions/         # File-based sessions
  │   │   └── views/            # Compiled Blade views
  │   └── logs/
  │       └── laravel.log       # Application log
  ├── vendor/                   # Composer dependencies
  ├── .env                      # Environment variables (DB creds, APP_KEY)
  ├── artisan                   # CLI tool
  └── composer.json
""",
        "sensitive_paths": [
            "/.env",
            "/storage/logs/laravel.log",
            "/vendor/composer/installed.json",
            "/bootstrap/cache/config.php",
            "/config/database.php",
            "/storage/framework/sessions/",
            "/.git/config",
            "/composer.json",
            "/composer.lock",
            "/artisan",
            "/phpinfo.php",
            "/server.php",
        ],
    },
    "Symfony": {
        "tree": r"""
  /
  ├── bin/
  │   └── console              # CLI tool
  ├── config/
  │   ├── packages/            # Bundle configs
  │   ├── routes/
  │   ├── bundles.php
  │   └── services.yaml
  ├── migrations/              # Doctrine migrations
  ├── public/
  │   └── index.php            # Entry point
  ├── src/
  │   ├── Controller/          # Route controllers
  │   ├── Entity/              # Doctrine entities
  │   ├── Repository/          # DB repositories
  │   ├── Form/
  │   └── Kernel.php
  ├── templates/               # Twig templates
  ├── translations/
  ├── var/
  │   ├── cache/
  │   └── log/
  ├── vendor/
  ├── .env
  └── composer.json
""",
        "sensitive_paths": [
            "/.env",
            "/var/log/",
            "/config/packages/",
            "/vendor/composer/installed.json",
            "/_profiler",
            "/app_dev.php",
            "/config/secrets/",
        ],
    },
    "CodeIgniter": {
        "tree": r"""
  /
  ├── app/
  │   ├── Config/              # Configuration
  │   ├── Controllers/
  │   ├── Database/
  │   │   └── Migrations/
  │   ├── Filters/
  │   ├── Models/
  │   └── Views/
  ├── public/
  │   └── index.php
  ├── writable/
  │   ├── cache/
  │   ├── logs/
  │   └── session/
  ├── vendor/
  ├── .env
  └── composer.json
""",
        "sensitive_paths": [
            "/.env",
            "/writable/logs/",
            "/app/Config/Database.php",
        ],
    },
    "WordPress": {
        "tree": r"""
  /
  ├── wp-admin/                # Admin dashboard
  │   ├── includes/
  │   └── ...
  ├── wp-content/
  │   ├── plugins/             # Installed plugins
  │   ├── themes/              # Installed themes
  │   │   └── <theme>/
  │   │       ├── style.css
  │   │       ├── functions.php
  │   │       └── templates/
  │   ├── uploads/             # Media uploads (by year/month)
  │   │   └── 2026/
  │   └── cache/
  ├── wp-includes/             # Core WordPress
  │   ├── js/
  │   ├── css/
  │   └── ...
  ├── wp-config.php            # DB credentials, salts, debug
  ├── wp-login.php             # Login page
  ├── wp-cron.php
  ├── xmlrpc.php               # XML-RPC (often attack surface)
  └── .htaccess
""",
        "sensitive_paths": [
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/.wp-config.php.swp",
            "/wp-content/debug.log",
            "/wp-content/uploads/",
            "/wp-json/wp/v2/users",
            "/xmlrpc.php",
            "/readme.html",
            "/license.txt",
            "/.htaccess",
            "/wp-content/plugins/",
            "/wp-includes/version.php",
        ],
    },
    "Drupal": {
        "tree": r"""
  /
  ├── core/                    # Drupal core
  │   ├── modules/
  │   ├── themes/
  │   └── misc/
  ├── modules/                 # Custom/contrib modules
  ├── profiles/
  ├── sites/
  │   ├── default/
  │   │   ├── files/           # Uploaded files
  │   │   └── settings.php     # DB config
  │   └── all/
  ├── themes/                  # Custom/contrib themes
  ├── vendor/
  └── .htaccess
""",
        "sensitive_paths": [
            "/sites/default/settings.php",
            "/CHANGELOG.txt",
            "/core/CHANGELOG.txt",
            "/sites/default/files/",
            "/update.php",
            "/install.php",
            "/core/install.php",
        ],
    },
    "Joomla": {
        "tree": r"""
  /
  ├── administrator/           # Admin panel
  │   ├── components/
  │   ├── modules/
  │   └── templates/
  ├── components/              # Frontend components
  ├── media/
  ├── modules/
  ├── plugins/
  ├── templates/
  ├── tmp/
  ├── cache/
  ├── configuration.php        # DB credentials
  └── .htaccess
""",
        "sensitive_paths": [
            "/configuration.php",
            "/configuration.php.bak",
            "/administrator/",
            "/README.txt",
            "/LICENSE.txt",
            "/tmp/",
            "/cache/",
        ],
    },
    "Django": {
        "tree": r"""
  /
  ├── <project>/
  │   ├── __init__.py
  │   ├── settings.py          # DB, SECRET_KEY, DEBUG, ALLOWED_HOSTS
  │   ├── urls.py              # URL routing
  │   ├── wsgi.py
  │   └── asgi.py
  ├── <app>/
  │   ├── models.py            # DB models
  │   ├── views.py             # View logic
  │   ├── urls.py
  │   ├── admin.py             # Admin registration
  │   ├── forms.py
  │   ├── serializers.py       # DRF serializers
  │   ├── templates/
  │   │   └── <app>/
  │   ├── static/
  │   └── migrations/
  ├── static/                  # Collected static files
  ├── media/                   # User uploads
  ├── templates/               # Project-level templates
  ├── manage.py                # CLI tool
  ├── requirements.txt
  ├── .env
  └── db.sqlite3               # Default SQLite DB
""",
        "sensitive_paths": [
            "/admin/",
            "/admin/login/",
            "/static/admin/",
            "/media/",
            "/settings.py",
            "/.env",
            "/db.sqlite3",
            "/requirements.txt",
            "/manage.py",
            "/__debug__/",
        ],
    },
    "Flask": {
        "tree": r"""
  /
  ├── app/
  │   ├── __init__.py          # App factory
  │   ├── routes.py            # Route handlers
  │   ├── models.py
  │   ├── forms.py
  │   ├── templates/           # Jinja2 templates
  │   └── static/
  │       ├── css/
  │       └── js/
  ├── migrations/              # Flask-Migrate / Alembic
  ├── instance/                # Instance-specific config
  │   └── config.py
  ├── config.py                # Configuration
  ├── requirements.txt
  ├── .env
  └── run.py / wsgi.py
""",
        "sensitive_paths": [
            "/.env",
            "/config.py",
            "/instance/config.py",
            "/requirements.txt",
            "/console",
            "/debug",
        ],
    },
    "FastAPI": {
        "tree": r"""
  /
  ├── app/
  │   ├── __init__.py
  │   ├── main.py              # FastAPI app, routes
  │   ├── models.py            # Pydantic / SQLAlchemy models
  │   ├── schemas.py           # Pydantic schemas
  │   ├── crud.py              # DB operations
  │   ├── database.py          # DB connection
  │   ├── dependencies.py
  │   └── routers/
  │       └── *.py
  ├── alembic/                 # DB migrations
  ├── tests/
  ├── .env
  └── requirements.txt
""",
        "sensitive_paths": [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/.env",
            "/requirements.txt",
        ],
    },
    "Express": {
        "tree": r"""
  /
  ├── routes/                  # Route handlers
  │   ├── index.js
  │   └── api.js
  ├── controllers/
  ├── models/                  # Mongoose/Sequelize models
  ├── middleware/
  ├── views/                   # EJS/Pug/Handlebars templates
  ├── public/                  # Static files
  │   ├── css/
  │   ├── js/
  │   └── images/
  ├── config/
  ├── node_modules/
  ├── app.js / server.js       # Entry point
  ├── package.json
  ├── .env
  └── .gitignore
""",
        "sensitive_paths": [
            "/.env",
            "/package.json",
            "/package-lock.json",
            "/.git/config",
            "/server.js",
            "/app.js",
            "/config/",
        ],
    },
    "Next.js": {
        "tree": r"""
  /
  ├── app/                     # App Router (Next 13+)
  │   ├── layout.tsx
  │   ├── page.tsx
  │   ├── api/                 # API routes
  │   │   └── route.ts
  │   └── [slug]/
  │       └── page.tsx
  ├── pages/                   # Pages Router (legacy)
  │   ├── _app.tsx
  │   ├── _document.tsx
  │   ├── index.tsx
  │   └── api/
  ├── components/
  ├── lib/
  ├── public/                  # Static assets
  ├── styles/
  ├── .next/                   # Build output
  ├── next.config.js
  ├── package.json
  └── .env.local
""",
        "sensitive_paths": [
            "/.env",
            "/.env.local",
            "/package.json",
            "/next.config.js",
            "/_next/static/",
            "/.next/BUILD_ID",
        ],
    },
    "Nuxt.js": {
        "tree": r"""
  /
  ├── pages/                   # File-based routing
  ├── components/
  ├── composables/
  ├── layouts/
  ├── middleware/
  ├── plugins/
  ├── server/
  │   ├── api/                 # Server API routes
  │   └── middleware/
  ├── public/
  ├── assets/
  ├── .nuxt/                   # Build output
  ├── nuxt.config.ts
  ├── package.json
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/package.json",
            "/nuxt.config.ts",
            "/nuxt.config.js",
        ],
    },
    "Ruby on Rails": {
        "tree": r"""
  /
  ├── app/
  │   ├── assets/
  │   ├── channels/
  │   ├── controllers/
  │   │   └── application_controller.rb
  │   ├── helpers/
  │   ├── javascript/
  │   ├── jobs/
  │   ├── mailers/
  │   ├── models/
  │   │   └── user.rb
  │   └── views/
  │       └── layouts/
  ├── bin/
  │   └── rails
  ├── config/
  │   ├── database.yml         # DB config
  │   ├── routes.rb            # Route definitions
  │   ├── credentials.yml.enc  # Encrypted secrets
  │   ├── master.key           # Decryption key
  │   └── environments/
  ├── db/
  │   ├── migrate/
  │   ├── schema.rb
  │   └── seeds.rb
  ├── lib/
  ├── log/
  ├── public/
  ├── storage/
  ├── tmp/
  ├── vendor/
  ├── Gemfile
  └── Gemfile.lock
""",
        "sensitive_paths": [
            "/config/database.yml",
            "/config/master.key",
            "/config/credentials.yml.enc",
            "/config/secrets.yml",
            "/.env",
            "/Gemfile",
            "/Gemfile.lock",
            "/log/production.log",
            "/log/development.log",
            "/tmp/",
            "/rails/info/routes",
        ],
    },
    "Spring Boot": {
        "tree": r"""
  /
  ├── src/
  │   ├── main/
  │   │   ├── java/com/<org>/<app>/
  │   │   │   ├── Application.java       # @SpringBootApplication
  │   │   │   ├── controller/
  │   │   │   ├── service/
  │   │   │   ├── repository/
  │   │   │   ├── model/ (entity/)
  │   │   │   ├── config/
  │   │   │   └── security/
  │   │   └── resources/
  │   │       ├── application.properties  # Config (DB, ports, secrets)
  │   │       ├── application.yml
  │   │       ├── static/
  │   │       └── templates/              # Thymeleaf templates
  │   └── test/
  ├── target/                  # Build output
  │   └── *.jar / *.war
  ├── pom.xml                  # Maven
  └── build.gradle             # Gradle
""",
        "sensitive_paths": [
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/configprops",
            "/actuator/heapdump",
            "/actuator/mappings",
            "/actuator/beans",
            "/swagger-ui.html",
            "/v2/api-docs",
            "/v3/api-docs",
            "/h2-console",
            "/console",
        ],
    },
    "ASP.NET": {
        "tree": r"""
  /
  ├── Controllers/
  │   └── HomeController.cs
  ├── Models/
  ├── Views/
  │   ├── Shared/
  │   │   └── _Layout.cshtml
  │   └── Home/
  ├── wwwroot/                 # Static files
  │   ├── css/
  │   ├── js/
  │   └── lib/
  ├── Areas/
  ├── Data/
  ├── Migrations/
  ├── Properties/
  │   └── launchSettings.json
  ├── appsettings.json         # Config (connection strings)
  ├── appsettings.Development.json
  ├── Program.cs               # Entry point
  ├── Startup.cs
  └── web.config
""",
        "sensitive_paths": [
            "/web.config",
            "/appsettings.json",
            "/appsettings.Development.json",
            "/elmah.axd",
            "/trace.axd",
            "/Global.asax",
        ],
    },
    "CakePHP": {
        "tree": r"""
  /
  ├── config/
  │   └── app.php
  ├── src/
  │   ├── Controller/
  │   ├── Model/
  │   │   ├── Entity/
  │   │   └── Table/
  │   ├── View/
  │   └── Template/
  ├── plugins/
  ├── webroot/                 # Document root
  │   └── index.php
  ├── tmp/
  │   ├── cache/
  │   └── logs/
  ├── vendor/
  ├── .env
  └── composer.json
""",
        "sensitive_paths": [
            "/.env",
            "/config/app.php",
            "/tmp/logs/",
            "/composer.json",
        ],
    },
    "Yii": {
        "tree": r"""
  /
  ├── config/
  │   ├── db.php
  │   ├── web.php
  │   └── params.php
  ├── controllers/
  ├── models/
  ├── views/
  │   └── layouts/
  ├── runtime/
  │   └── logs/
  ├── web/                     # Document root
  │   └── index.php
  ├── vendor/
  └── composer.json
""",
        "sensitive_paths": [
            "/config/db.php",
            "/runtime/logs/",
            "/composer.json",
        ],
    },
    "ThinkPHP": {
        "tree": r"""
  /
  ├── app/
  │   ├── controller/
  │   ├── model/
  │   └── view/
  ├── config/
  │   └── database.php
  ├── public/
  │   └── index.php
  ├── runtime/
  │   └── log/
  ├── vendor/
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/runtime/log/",
            "/config/database.php",
            "/vendor/composer/installed.json",
        ],
    },
    "Magento": {
        "tree": r"""
  /
  ├── app/
  │   ├── code/                # Custom modules
  │   ├── design/              # Themes
  │   └── etc/
  │       └── env.php          # DB credentials
  ├── pub/                     # Document root
  │   ├── media/
  │   └── static/
  ├── var/
  │   ├── log/
  │   └── cache/
  ├── vendor/
  └── composer.json
""",
        "sensitive_paths": [
            "/app/etc/env.php",
            "/app/etc/local.xml",
            "/var/log/",
            "/downloader/",
            "/magento_version",
        ],
    },
    "React": {
        "tree": r"""
  /  (Create React App)
  ├── public/
  │   ├── index.html
  │   └── manifest.json
  ├── src/
  │   ├── App.js / App.tsx
  │   ├── index.js
  │   ├── components/
  │   ├── pages/
  │   ├── hooks/
  │   ├── context/
  │   └── utils/
  ├── build/                   # Production build
  │   └── static/
  │       ├── js/
  │       └── css/
  ├── node_modules/
  ├── package.json
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/package.json",
            "/static/js/main.*.js.map",
            "/asset-manifest.json",
        ],
    },
    "Angular": {
        "tree": r"""
  /
  ├── src/
  │   ├── app/
  │   │   ├── app.component.ts
  │   │   ├── app.module.ts
  │   │   ├── app-routing.module.ts
  │   │   └── <feature>/
  │   ├── assets/
  │   ├── environments/
  │   │   ├── environment.ts
  │   │   └── environment.prod.ts
  │   ├── index.html
  │   └── main.ts
  ├── dist/                    # Production build
  ├── node_modules/
  ├── angular.json
  ├── package.json
  └── tsconfig.json
""",
        "sensitive_paths": [
            "/package.json",
            "/angular.json",
            "/.env",
            "/assets/",
        ],
    },
    "Vue.js": {
        "tree": r"""
  /
  ├── src/
  │   ├── App.vue
  │   ├── main.js
  │   ├── components/
  │   ├── views/
  │   ├── router/
  │   ├── store/               # Vuex / Pinia
  │   └── assets/
  ├── public/
  │   └── index.html
  ├── dist/                    # Production build
  ├── node_modules/
  ├── package.json
  ├── vue.config.js
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/package.json",
            "/vue.config.js",
        ],
    },
    "Jekyll": {
        "tree": r"""
  /
  ├── _posts/                  # Blog posts (YYYY-MM-DD-title.md)
  ├── _pages/
  ├── _layouts/                # Page templates
  ├── _includes/               # Reusable partials
  ├── _data/                   # YAML/JSON data files
  ├── _sass/
  ├── _site/                   # Generated static site
  ├── assets/
  ├── _config.yml              # Site config
  ├── Gemfile
  └── index.md / index.html
""",
        "sensitive_paths": [
            "/_config.yml",
            "/Gemfile",
            "/feed.xml",
            "/sitemap.xml",
        ],
    },
    "Hugo": {
        "tree": r"""
  /
  ├── archetypes/
  ├── content/                 # Markdown content
  ├── data/
  ├── layouts/                 # Templates
  ├── public/                  # Generated site
  ├── static/                  # Static assets
  ├── themes/
  ├── config.toml / hugo.toml
  └── go.mod
""",
        "sensitive_paths": [
            "/config.toml",
            "/hugo.toml",
            "/sitemap.xml",
        ],
    },
    "Gatsby": {
        "tree": r"""
  /
  ├── src/
  │   ├── pages/
  │   ├── components/
  │   ├── templates/
  │   └── images/
  ├── static/
  ├── public/                  # Build output
  ├── gatsby-config.js
  ├── gatsby-node.js
  ├── gatsby-browser.js
  └── package.json
""",
        "sensitive_paths": [
            "/page-data/index/page-data.json",
            "/package.json",
            "/gatsby-config.js",
        ],
    },
    "Blazor": {
        "tree": r"""
  /
  ├── Pages/
  │   ├── Index.razor
  │   └── *.razor
  ├── Shared/
  │   ├── MainLayout.razor
  │   └── NavMenu.razor
  ├── wwwroot/
  │   └── _framework/
  │       └── blazor.boot.json
  ├── Data/
  ├── Program.cs
  └── appsettings.json
""",
        "sensitive_paths": [
            "/_framework/blazor.boot.json",
            "/appsettings.json",
        ],
    },
    "Sinatra": {
        "tree": r"""
  /
  ├── app.rb / server.rb       # Main app file
  ├── config.ru                # Rack config
  ├── views/                   # ERB/Haml templates
  ├── public/                  # Static files
  ├── lib/
  ├── Gemfile
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/Gemfile",
            "/config.ru",
        ],
    },
    "Tornado": {
        "tree": r"""
  /
  ├── app.py / server.py       # Entry point
  ├── handlers/                # Request handlers
  ├── models/
  ├── templates/
  ├── static/
  ├── requirements.txt
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/requirements.txt",
        ],
    },
    "Remix": {
        "tree": r"""
  /
  ├── app/
  │   ├── root.tsx
  │   ├── entry.client.tsx
  │   ├── entry.server.tsx
  │   └── routes/
  ├── public/
  ├── build/
  ├── remix.config.js
  ├── package.json
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/package.json",
            "/remix.config.js",
        ],
    },
    "Astro": {
        "tree": r"""
  /
  ├── src/
  │   ├── pages/
  │   ├── components/
  │   ├── layouts/
  │   └── content/
  ├── public/
  ├── dist/                    # Build output
  ├── astro.config.mjs
  ├── package.json
  └── .env
""",
        "sensitive_paths": [
            "/.env",
            "/package.json",
            "/astro.config.mjs",
        ],
    },
    "Apache Struts": {
        "tree": r"""
  /  (WAR deployed in Tomcat)
  ├── WEB-INF/
  │   ├── web.xml              # Servlet config
  │   ├── struts.xml           # Struts actions
  │   ├── classes/
  │   └── lib/
  ├── META-INF/
  ├── *.jsp
  └── *.action / *.do
""",
        "sensitive_paths": [
            "/WEB-INF/web.xml",
            "/WEB-INF/struts.xml",
            "/META-INF/",
            "/struts/",
        ],
    },
    "JSF": {
        "tree": r"""
  /
  ├── WEB-INF/
  │   ├── web.xml
  │   ├── faces-config.xml     # JSF configuration
  │   └── lib/
  ├── resources/
  │   ├── css/
  │   └── js/
  └── *.xhtml / *.jsf
""",
        "sensitive_paths": [
            "/WEB-INF/web.xml",
            "/WEB-INF/faces-config.xml",
        ],
    },
    "Apache Tomcat": {
        "tree": r"""
  /  ($CATALINA_HOME)
  ├── bin/
  │   ├── startup.sh
  │   └── catalina.sh
  ├── conf/
  │   ├── server.xml           # Ports, connectors
  │   ├── tomcat-users.xml     # Manager credentials
  │   └── web.xml
  ├── lib/
  ├── logs/
  ├── webapps/
  │   ├── ROOT/
  │   ├── manager/
  │   └── host-manager/
  ├── temp/
  └── work/
""",
        "sensitive_paths": [
            "/manager/html",
            "/host-manager/html",
            "/manager/status",
            "/conf/tomcat-users.xml",
        ],
    },
}

# ── Scan logic ────────────────────────────────────────────────────────────────

BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
DIM = "\033[2m"
RESET = "\033[0m"


class FrameworkDetector:
    def __init__(self, url, timeout=10, probe_paths=True, threads=10, verbose=False):
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.probe_paths = probe_paths
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        self.session.verify = False
        self.results = defaultdict(list)

    def log(self, msg):
        if self.verbose:
            print(f"  {DIM}[*] {msg}{RESET}", file=sys.stderr)

    def fetch(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except RequestException as e:
            self.log(f"Request failed: {url} — {e}")
            return None

    @staticmethod
    def _is_laravel_encrypted(value):
        try:
            decoded = base64.b64decode(urllib.parse.unquote(value))
            obj = json.loads(decoded)
            return {"iv", "value", "mac"}.issubset(obj.keys())
        except Exception:
            return False

    def check_cookies(self, resp, framework, sigs):
        patterns = sigs.get("cookies", [])
        name_patterns = sigs.get("cookie_name_patterns", [])
        value_checks = sigs.get("cookie_value_checks", [])

        for cookie in resp.cookies:
            for pat in patterns:
                if re.search(pat, cookie.name, re.IGNORECASE):
                    self.results[framework].append(f"Cookie: {cookie.name}")

            for pat in name_patterns:
                if re.search(pat, cookie.name, re.IGNORECASE):
                    self.results[framework].append(
                        f"Cookie name pattern '{pat}': {cookie.name}"
                    )

            for check in value_checks:
                if check == "laravel_encrypted" and self._is_laravel_encrypted(cookie.value):
                    self.results[framework].append(
                        f"Cookie '{cookie.name}' has Laravel encrypted format (iv/value/mac)"
                    )

    def check_headers(self, resp, framework, patterns):
        for header, value in resp.headers.items():
            for pat in patterns:
                combined = f"{header}: {value}"
                if re.search(pat, combined, re.IGNORECASE):
                    self.results[framework].append(f"Header: {header}: {value}")

    def check_html(self, body, framework, patterns):
        for pat in patterns:
            match = re.search(pat, body, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:80]
                self.results[framework].append(f"HTML: {snippet}")

    def check_error_pages(self, body, framework, patterns):
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                snippet = m.group(0)[:60]
                self.results[framework].append(f"Error page: {snippet}")

    def probe_path(self, path):
        full = self.url + path
        self.log(f"Probing {full}")
        resp = self.fetch(full)
        if resp is None:
            return None
        return (path, resp.status_code, resp.text[:2000], resp.headers)

    def run(self):
        print(f"\n{BOLD}{'='*60}")
        print(f"  Framework Detector v2.0")
        print(f"  Target: {CYAN}{self.url}{RESET}")
        print(f"{BOLD}{'='*60}{RESET}\n")

        # ── Phase 1: Main page ────────────────────────────────────
        print(f"{BOLD}[Phase 1]{RESET} Fetching main page...")
        resp = self.fetch(self.url)
        if resp is None:
            print(f"{RED}[!] Could not reach target. Aborting.{RESET}")
            return

        print(f"  Status:       {resp.status_code}")
        print(f"  Server:       {resp.headers.get('Server', 'N/A')}")
        print(f"  X-Powered-By: {resp.headers.get('X-Powered-By', 'N/A')}")
        cookies_str = ", ".join(c.name for c in resp.cookies) or "N/A"
        print(f"  Cookies:      {cookies_str}")

        body = resp.text

        for fw, sigs in SIGNATURES.items():
            self.check_cookies(resp, fw, sigs)
            self.check_headers(resp, fw, sigs["headers"])
            self.check_html(body, fw, sigs["html"])

        # ── Phase 2: Error page (trigger 404) ─────────────────────
        print(f"\n{BOLD}[Phase 2]{RESET} Fetching 404 error page...")
        err_resp = self.fetch(self.url + "/th1s-p4g3-d0es-n0t-ex1st-xyzzy42")
        if err_resp:
            print(f"  Status: {err_resp.status_code}")
            err_body = err_resp.text
            for fw, sigs in SIGNATURES.items():
                self.check_error_pages(err_body, fw, sigs["error_pages"])
                self.check_headers(err_resp, fw, sigs["headers"])
                self.check_cookies(err_resp, fw, sigs)

        # ── Phase 3: Probe known paths ────────────────────────────
        if self.probe_paths:
            all_paths = set()
            for sigs in SIGNATURES.values():
                all_paths.update(sigs.get("paths", []))

            print(f"\n{BOLD}[Phase 3]{RESET} Probing {len(all_paths)} known paths...")

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {pool.submit(self.probe_path, p): p for p in all_paths}
                for future in as_completed(futures):
                    result = future.result()
                    if result is None:
                        continue
                    path, status, body_snippet, headers = result
                    if status < 400:
                        for fw, sigs in SIGNATURES.items():
                            if path in sigs.get("paths", []):
                                self.results[fw].append(
                                    f"Path {GREEN}{status}{RESET}: {path}"
                                )

        # ── Report ────────────────────────────────────────────────
        self._print_report()

    def _print_report(self):
        print(f"\n{BOLD}{'='*60}")
        print(f"  RESULTS")
        print(f"{'='*60}{RESET}\n")

        if not self.results:
            print(f"  {DIM}No frameworks detected.")
            print(f"  The site may hide its stack or use custom code.{RESET}")
            return

        sorted_results = sorted(
            self.results.items(), key=lambda x: len(x[1]), reverse=True
        )

        for fw, evidence in sorted_results:
            unique = list(dict.fromkeys(evidence))
            count = len(unique)
            if count >= 3:
                color = GREEN
                level = "HIGH"
            elif count == 2:
                color = YELLOW
                level = "MED "
            else:
                color = DIM
                level = "LOW "

            bar = "#" * min(count * 3, 20)
            print(f"  {color}[{level}]{RESET} {bar:<20s} {BOLD}{fw}{RESET}")
            for e in unique:
                print(f"         {DIM}-{RESET} {e}")
            print()

        # ── Directory structures for detected frameworks ──────────
        detected = [fw for fw, _ in sorted_results if fw in DIRECTORY_STRUCTURES]
        if not detected:
            return

        print(f"{BOLD}{'='*60}")
        print(f"  DIRECTORY STRUCTURES & SENSITIVE PATHS")
        print(f"{'='*60}{RESET}")

        for fw in detected:
            info = DIRECTORY_STRUCTURES[fw]
            print(f"\n  {BOLD}{CYAN}[ {fw} ]{RESET}")

            print(f"\n  {BOLD}Directory Structure:{RESET}")
            print(info["tree"])

            paths = info.get("sensitive_paths", [])
            if paths:
                print(f"  {BOLD}{RED}Sensitive / Interesting Paths:{RESET}")
                for p in paths:
                    full = f"{self.url}{p}"
                    print(f"    {YELLOW}>{RESET} {p:<45s} {DIM}{full}{RESET}")
                print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Detect web frameworks from HTTP responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python detect.py https://example.com
  python detect.py https://example.com --no-probe
  python detect.py https://example.com -v --timeout 15
""",
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip path probing (faster, stealthier)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Threads for path probing"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    args = parser.parse_args()

    detector = FrameworkDetector(
        url=args.url,
        timeout=args.timeout,
        probe_paths=not args.no_probe,
        threads=args.threads,
        verbose=args.verbose,
    )
    detector.run()


if __name__ == "__main__":
    main()
