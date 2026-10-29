"""Directory structure and sensitive path database for detected frameworks."""

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
  │   ├── Controller/
  │   ├── Entity/              # Doctrine entities
  │   ├── Repository/
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
  │   ├── Config/
  │   ├── Controllers/
  │   ├── Database/Migrations/
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
        "sensitive_paths": ["/.env", "/writable/logs/", "/app/Config/Database.php"],
    },
    "WordPress": {
        "tree": r"""
  /
  ├── wp-admin/                # Admin dashboard
  ├── wp-content/
  │   ├── plugins/             # Installed plugins
  │   ├── themes/              # Installed themes
  │   ├── uploads/             # Media uploads (by year/month)
  │   └── cache/
  ├── wp-includes/             # Core WordPress
  ├── wp-config.php            # DB credentials, salts, debug
  ├── wp-login.php             # Login page
  ├── wp-cron.php
  ├── xmlrpc.php               # XML-RPC (often attack surface)
  └── .htaccess
""",
        "sensitive_paths": [
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-content/debug.log",
            "/wp-content/uploads/",
            "/wp-json/wp/v2/users",
            "/xmlrpc.php",
            "/readme.html",
            "/.htaccess",
            "/wp-content/plugins/",
            "/wp-includes/version.php",
        ],
    },
    "Drupal": {
        "tree": r"""
  /
  ├── core/
  │   ├── modules/
  │   ├── themes/
  │   └── misc/
  ├── modules/                 # Custom/contrib modules
  ├── sites/
  │   └── default/
  │       ├── files/           # Uploaded files
  │       └── settings.php     # DB config
  ├── themes/
  ├── vendor/
  └── .htaccess
""",
        "sensitive_paths": [
            "/sites/default/settings.php",
            "/CHANGELOG.txt",
            "/core/CHANGELOG.txt",
            "/sites/default/files/",
            "/update.php",
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
  ├── components/
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
            "/tmp/",
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
  ├── pub/
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
            "/magento_version",
        ],
    },
    "Django": {
        "tree": r"""
  /
  ├── <project>/
  │   ├── settings.py          # DB, SECRET_KEY, DEBUG
  │   ├── urls.py              # URL routing
  │   ├── wsgi.py
  │   └── asgi.py
  ├── <app>/
  │   ├── models.py
  │   ├── views.py
  │   ├── urls.py
  │   ├── admin.py
  │   ├── templates/<app>/
  │   ├── static/
  │   └── migrations/
  ├── static/
  ├── media/                   # User uploads
  ├── manage.py
  ├── requirements.txt
  ├── .env
  └── db.sqlite3               # Default SQLite DB
""",
        "sensitive_paths": [
            "/admin/",
            "/admin/login/",
            "/static/admin/",
            "/media/",
            "/.env",
            "/db.sqlite3",
            "/requirements.txt",
            "/__debug__/",
        ],
    },
    "Flask": {
        "tree": r"""
  /
  ├── app/
  │   ├── __init__.py          # App factory
  │   ├── routes.py
  │   ├── models.py
  │   ├── templates/           # Jinja2 templates
  │   └── static/
  ├── migrations/              # Flask-Migrate
  ├── instance/config.py
  ├── config.py
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
        ],
    },
    "FastAPI": {
        "tree": r"""
  /
  ├── app/
  │   ├── main.py              # FastAPI app
  │   ├── models.py
  │   ├── schemas.py
  │   ├── crud.py
  │   ├── database.py
  │   └── routers/*.py
  ├── alembic/                 # DB migrations
  ├── tests/
  ├── .env
  └── requirements.txt
""",
        "sensitive_paths": ["/docs", "/redoc", "/openapi.json", "/.env", "/requirements.txt"],
    },
    "Express": {
        "tree": r"""
  /
  ├── routes/
  ├── controllers/
  ├── models/
  ├── middleware/
  ├── views/                   # EJS/Pug/Handlebars
  ├── public/
  ├── config/
  ├── node_modules/
  ├── app.js / server.js
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
        ],
    },
    "Next.js": {
        "tree": r"""
  /
  ├── app/                     # App Router (Next 13+)
  │   ├── layout.tsx
  │   ├── page.tsx
  │   └── api/route.ts
  ├── pages/                   # Pages Router (legacy)
  │   ├── _app.tsx
  │   └── api/
  ├── components/
  ├── lib/
  ├── public/
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
        ],
    },
    "Nuxt.js": {
        "tree": r"""
  /
  ├── pages/
  ├── components/
  ├── composables/
  ├── layouts/
  ├── middleware/
  ├── plugins/
  ├── server/api/
  ├── public/
  ├── .nuxt/                   # Build output
  ├── nuxt.config.ts
  ├── package.json
  └── .env
""",
        "sensitive_paths": ["/.env", "/package.json", "/nuxt.config.ts"],
    },
    "Ruby on Rails": {
        "tree": r"""
  /
  ├── app/
  │   ├── controllers/
  │   ├── models/
  │   ├── views/layouts/
  │   ├── assets/
  │   ├── javascript/
  │   ├── jobs/
  │   └── mailers/
  ├── config/
  │   ├── database.yml         # DB config
  │   ├── routes.rb
  │   ├── credentials.yml.enc  # Encrypted secrets
  │   └── master.key           # Decryption key
  ├── db/
  │   ├── migrate/
  │   └── schema.rb
  ├── log/
  ├── public/
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
            "/log/production.log",
            "/log/development.log",
            "/rails/info/routes",
        ],
    },
    "Spring Boot": {
        "tree": r"""
  /
  ├── src/main/
  │   ├── java/com/<org>/<app>/
  │   │   ├── Application.java
  │   │   ├── controller/
  │   │   ├── service/
  │   │   ├── repository/
  │   │   ├── model/
  │   │   └── config/
  │   └── resources/
  │       ├── application.properties
  │       ├── application.yml
  │       ├── static/
  │       └── templates/
  ├── src/test/
  ├── target/*.jar
  ├── pom.xml
  └── build.gradle
""",
        "sensitive_paths": [
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/configprops",
            "/actuator/heapdump",
            "/actuator/mappings",
            "/swagger-ui.html",
            "/v2/api-docs",
            "/v3/api-docs",
            "/h2-console",
        ],
    },
    "ASP.NET": {
        "tree": r"""
  /
  ├── Controllers/
  ├── Models/
  ├── Views/Shared/_Layout.cshtml
  ├── wwwroot/                 # Static files
  ├── Areas/
  ├── Data/
  ├── Migrations/
  ├── appsettings.json
  ├── appsettings.Development.json
  ├── Program.cs
  ├── Startup.cs
  └── web.config
""",
        "sensitive_paths": [
            "/web.config",
            "/appsettings.json",
            "/appsettings.Development.json",
            "/elmah.axd",
            "/trace.axd",
        ],
    },
    "CakePHP": {
        "tree": r"""
  /
  ├── config/app.php
  ├── src/
  │   ├── Controller/
  │   ├── Model/Entity/
  │   ├── Model/Table/
  │   └── Template/
  ├── plugins/
  ├── webroot/index.php
  ├── tmp/cache/
  ├── tmp/logs/
  ├── vendor/
  ├── .env
  └── composer.json
""",
        "sensitive_paths": ["/.env", "/config/app.php", "/tmp/logs/", "/composer.json"],
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
  ├── views/layouts/
  ├── runtime/logs/
  ├── web/index.php
  ├── vendor/
  └── composer.json
""",
        "sensitive_paths": ["/config/db.php", "/runtime/logs/", "/composer.json"],
    },
    "ThinkPHP": {
        "tree": r"""
  /
  ├── app/
  │   ├── controller/
  │   ├── model/
  │   └── view/
  ├── config/database.php
  ├── public/index.php
  ├── runtime/log/
  ├── vendor/
  └── .env
""",
        "sensitive_paths": ["/.env", "/runtime/log/", "/config/database.php"],
    },
    "React": {
        "tree": r"""
  /  (Create React App)
  ├── public/index.html
  ├── src/
  │   ├── App.js
  │   ├── index.js
  │   ├── components/
  │   └── hooks/
  ├── build/static/js/
  ├── node_modules/
  ├── package.json
  └── .env
""",
        "sensitive_paths": ["/.env", "/package.json", "/static/js/main.*.js.map", "/asset-manifest.json"],
    },
    "Angular": {
        "tree": r"""
  /
  ├── src/
  │   ├── app/
  │   ├── assets/
  │   ├── environments/
  │   └── index.html
  ├── dist/
  ├── angular.json
  ├── package.json
  └── tsconfig.json
""",
        "sensitive_paths": ["/package.json", "/angular.json", "/.env"],
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
  │   └── store/
  ├── public/index.html
  ├── dist/
  ├── package.json
  └── .env
""",
        "sensitive_paths": ["/.env", "/package.json", "/vue.config.js"],
    },
    "Jekyll": {
        "tree": r"""
  /
  ├── _posts/
  ├── _layouts/
  ├── _includes/
  ├── _data/
  ├── _sass/
  ├── _site/                   # Generated output
  ├── assets/
  ├── _config.yml
  ├── Gemfile
  └── index.md
""",
        "sensitive_paths": ["/_config.yml", "/Gemfile", "/feed.xml", "/sitemap.xml"],
    },
    "Hugo": {
        "tree": r"""
  /
  ├── content/
  ├── layouts/
  ├── public/
  ├── static/
  ├── themes/
  └── config.toml / hugo.toml
""",
        "sensitive_paths": ["/config.toml", "/hugo.toml", "/sitemap.xml"],
    },
    "Gatsby": {
        "tree": r"""
  /
  ├── src/pages/
  ├── src/components/
  ├── static/
  ├── public/
  ├── gatsby-config.js
  └── package.json
""",
        "sensitive_paths": ["/page-data/index/page-data.json", "/package.json"],
    },
    "Blazor": {
        "tree": r"""
  /
  ├── Pages/*.razor
  ├── Shared/MainLayout.razor
  ├── wwwroot/_framework/blazor.boot.json
  ├── Data/
  ├── Program.cs
  └── appsettings.json
""",
        "sensitive_paths": ["/_framework/blazor.boot.json", "/appsettings.json"],
    },
    "Sinatra": {
        "tree": r"""
  /
  ├── app.rb
  ├── config.ru
  ├── views/
  ├── public/
  ├── Gemfile
  └── .env
""",
        "sensitive_paths": ["/.env", "/Gemfile", "/config.ru"],
    },
    "Apache Struts": {
        "tree": r"""
  /  (WAR in Tomcat)
  ├── WEB-INF/
  │   ├── web.xml
  │   ├── struts.xml
  │   ├── classes/
  │   └── lib/
  ├── META-INF/
  └── *.action / *.do
""",
        "sensitive_paths": ["/WEB-INF/web.xml", "/WEB-INF/struts.xml", "/META-INF/"],
    },
    "Apache Tomcat": {
        "tree": r"""
  /  ($CATALINA_HOME)
  ├── bin/
  ├── conf/
  │   ├── server.xml
  │   ├── tomcat-users.xml
  │   └── web.xml
  ├── logs/
  ├── webapps/
  │   ├── ROOT/
  │   ├── manager/
  │   └── host-manager/
  └── work/
""",
        "sensitive_paths": [
            "/manager/html",
            "/host-manager/html",
            "/manager/status",
        ],
    },
}
