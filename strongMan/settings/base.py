import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'strongMan.helper_apps.vici',
    'strongMan.apps.connections',
    'strongMan.apps.certificates',
    'strongMan.apps.eap_secrets',
    'strongMan.apps.server_connections',
    'strongMan.apps.server_tunnels',
    'strongMan.apps.pools',
    'django_tables2',
    'dj_static',
]

MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

ROOT_URLCONF = 'strongMan.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.request',
            ],
        },
    },
]

WSGI_APPLICATION = 'strongMan.wsgi.application'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Seoul'

USE_I18N = True

USE_L10N = True

USE_TZ = True


STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles/')
STATIC_URL = '/static/'

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)
LOGIN_URL = (
    '/login/'
)


def create_read_key(file_path):
    '''
    Generates a secure django SECRET_KEY
    https://gist.github.com/ndarville/3452907
    :param file_path: Path to the file which persists the key
    :return: secure secret key 50 bytes long
    '''
    SECRET_FILE = file_path
    try:
        return open(SECRET_FILE).read().strip()
    except IOError:
        try:
            import random
            SECRET_KEY = ''.join([random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)') for i in range(50)])
            with open(SECRET_FILE, 'w') as f:
                f.write(SECRET_KEY)
            print("Create a new key in " + SECRET_FILE + ".")
            return SECRET_KEY
        except IOError:
            Exception('Please create a %s file with random characters \
            to generate your secret key!' % SECRET_FILE)


SECRET_KEY = create_read_key('secret_key.txt')
DB_SECRET_KEY = create_read_key('db_key.txt')

SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_AGE = 600  # 10 mins
#SESSION_COOKIE_DOMAIN = None
#SESSION_COOKIE_NAME = 'DSESSIONID'
SESSION_COOKIE_SECURE = False

LOGGING = {
    'version': 1,
    'diable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)8s] %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
        'logfile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'maxBytes': 1024 * 1024 * 10,
            'backupCount': 10,
            # 'class': 'logging.FileHandler',
            'filename': '/var/log/django.log',
            'formatter': 'standard'
        },
    },
    'loggers': {
        'default': {
            'level': 'DEBUG',
            'handlers': ['console', 'logfile']
        },
    },
}
