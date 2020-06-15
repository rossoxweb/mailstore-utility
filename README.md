# Mail Store Utility
<a>
    <img src="https://img.shields.io/badge/stability-stable-green.svg?style=flat-square"
    alt="stability" />
</a>
  
<br />
<br />

This Web App is born to give the capability to the costumer of:
* Change mailstore user password
* Check Storage usage for logged user
* Check profiles status
* Change IMAP profiles password

without using the Desktop Client for Windows.
 
## Built With

* [Flask](https://flask.palletsprojects.com/) - python web micro-framework  ![coverage](https://img.shields.io/badge/flask-Flask%201.1.1-red.svg?style=flat-square)
* [Virtualenv](https://virtualenv.pypa.io/) - Virtual Enviroment    ![coverage](https://img.shields.io/badge/virtualenv-v20.0.18-blue.svg?style=flat-square)
* [MailStore SPE API](https://help.mailstore.com/en/spe/Management_API_-_Function_Reference)
* [MailStore Python Library](https://help.mailstore.com/en/spe/Python_API_Wrapper_Tutorial)


## Index

- [Description of files](#description-of-files)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installing](#installing)
- [Deployment](#layering)
  - [Local Deploy](#local-deploy)
  - [Web Server](#web-server)
  - [Logout](logout)
- [Contributing](#contributing)
- [Authors](#authors)
- [License](#license)


Description of files
--------------------

app folder:

filename                          |  description
----------------------------------|------------------------------------------------------------------------------------
__init __.py                      |  Contain the application factory, and it tells Python that the app directory should be treated as a package
auth.py                           |  Authentication route and functions.
data.py                           |  Route and functions to return data async for data.html ajax.
app.wsgi                          |  Contains the code mod_wsgi is executing on startup to get the application object.
setup.py                          |  Install required package for virtual environment.

mailstore folder:

filename                          |  description
----------------------------------|------------------------------------------------------------------------------------
__init __.py                      |  Define package.
mgmt.py                           |  MailStore library.
mailstore.py                      |  Class build to interrogate in our desired way the API.

static folder:

filename                          |  description
----------------------------------|------------------------------------------------------------------------------------
css                               |  Contains StyleSheet from MailStore Web Panel and custom StyleSheet.
img                               |  Icons, wallpaper.
js                                |  Javascript of MailStore Web Panel and jquery-3.5.1.min.js.

templates folder:

filename                          |  description
----------------------------------|------------------------------------------------------------------------------------
auth/login.html                   |  Contains jinja2 templates for authentication.
data/data.html                    |  jinja2 templates for dashboard, jquery for ajax request.
data/usermk.html                  |  jinja2 templates mailstore user password update.
data/userprofile.html             |  jinja2 templates mailstore user profiles password update.
base.html                         |  jinja2 template, base of the all other templates.
operationsuccess.html             |  jinja2 template rendered when a operation is successful.



## Getting Started

### Prerequisites

To try this software you need:

```
License for MailStore SPE v10 or superior, System requirements at https://help.mailstore.com/en/spe/System_Requirements
python3
flask v1.1.1
virtualenv v20.0.18

```
### Installing

These instructions will get you a copy of the project up and running on your local machine for development. 

Clone the repo:
```
git@github.com:rossoxweb/mailstore-utility.git
```

Setup virtual enviroment:

```
python3 -m virtualenv venv 
```
Activate the virtual enviroment:

```
. venv/bin/activate
```

Install the required dependencies:

```
python3 setup.py install
```

Flask Manual Setup Script: https://flask.palletsprojects.com/en/1.1.x/patterns/distribute/

## Deployment


### Local Deploy

You can use Flask tools for test the app on your local machine https://flask.palletsprojects.com/en/1.1.x/tutorial/factory/#run-the-application

For Linux and Mac:

```
export FLASK_APP=app
export FLASK_ENV=development
flask run
```
For Windows cmd, use set instead of export:
```
set FLASK_APP=app
set FLASK_ENV=development
flask run
```

### Web Server

Official Flask Manual: https://flask.palletsprojects.com/en/1.1.x/deploying/mod_wsgi/

We use an Apache Web Server (Centos7) in this example, you can see more at https://flask.palletsprojects.com/en/1.1.x/deploying/


Add "app.wsgi" to root folder of the app:

```python
activate_this = '/path/to/utility.domain.com/venv/bin/activate_this.py'
exec(compile(open(activate_this, "rb").read(), activate_this, 'exec'), dict(__file__=activate_this))

import logging
import sys

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/path/to/utility.domain.com/')

from app import create_app
application = create_app()
```

Install mod_wsgi:

```
yum install mod_wsgi
```

Create the apache config:

```apacheconf
<VirtualHost *>
    DocumentRoot /path/to/utility.domain.com
    ServerName utility.domain.com

    LoadModule wsgi_module modules/mod_wsgi.so

    WSGIDaemonProcess app user=apache group=apache threads=5
    WSGIScriptAlias / /path/to/utility.domain.com/app.wsgi


    ErrorLog logs/utility.domain.com-ssl-error_log
    CustomLog logs/utility.domain.com-ssl-access_log common

    <Directory "/path/to/utility.domain.com">
        WSGIProcessGroup app
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptReloading On

        Options FollowSymLinks
        AllowOverride All
        Require all granted
        <IfModule mod_ruid2.c>
            RMode stat
        </IfModule>
    </Directory>

</VirtualHost>
```

Restart Apache:

```
systemctl restart httpd
```

## Contributing

Before start, read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.


## Authors

* **Fabio Capanni** - *Full Stack Developer* - [rossoXweb](https://github.com/rossoxweb)


## License
<a>
    <img src="https://img.shields.io/badge/license-AGPL-blue.svg?style=flat-square"
    alt="stability" />
</a><br>


This project is licensed under the AGPL License - see the [LICENSE.md](LICENSE.md) file for details

