from setuptools import setup
from setuptools import find_packages

setup(
    name='mailstore-utility',
    version='1.0',
    author="Fabio Capanni",
    author_email="fcapanni@seit.it",
    description="small web application for mailstore spe",
    long_description=__doc__,
    packages=['app'],
    include_package_data=True,
    zip_safe=False,
    install_requires = [
        "Flask",
        "Werkzeug",
        "Jinja2",
        "itsdangerous",
        "click",
        "requests",
        "imapclient"
    ],
)