"""Signature database for framework detection.

Each entry can have:
  cookies             — regex matched against cookie names
  cookie_name_patterns — regex matched against cookie names (looser patterns)
  cookie_value_checks — special value checks (e.g. "laravel_encrypted")
  headers             — regex matched against "Header-Name: value" string
  html                — regex matched against the page body
  paths               — paths to probe (HTTP < 400 = match)
  error_pages         — regex matched against 404 error page body
"""

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
