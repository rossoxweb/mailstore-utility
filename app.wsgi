activate_this = '/path/to/utility.domain.com/venv/bin/activate_this.py'
exec(compile(open(activate_this, "rb").read(), activate_this, 'exec'), dict(__file__=activate_this))

import logging
import sys

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/path/to/utility.domain.com/')

from app import create_app
application = create_app()
