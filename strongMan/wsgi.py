"""
WSGI config for strongMan project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.9/howto/deployment/wsgi/
"""

import os
import sys
path = os.path.abspath(__file__+'/../..')
if path not in sys.path:
    sys.path.append(path)

from django.core.wsgi import get_wsgi_application
from dj_static import Cling

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "strongMan.settings.local")

application = Cling(get_wsgi_application())
