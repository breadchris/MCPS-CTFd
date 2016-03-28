#!/usr/bin/python
import sys, logging
sys.path.insert(0,"/var/www/html/BetterHSF/")
logging.basicConfig(stream=sys.stderr)

from CTFd import create_app
application = create_app()
