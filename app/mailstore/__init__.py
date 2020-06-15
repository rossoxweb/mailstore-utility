# -*- coding: utf-8 -*-
#
# Copyright (c) 2012 - 2018 MailStore Software GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

__doc__ = """Wrapper for MailStore Administration API and MailStore Management API.

This Python library provides a wrapper for
the MailStore Administration API provided by MailStore Server and
the MailStore Management API provided by MailStore Service Provider Edition. 

For MailStore Server (Administration API) use 

   >>> client = mailstore.mgmt.ServerClient(username, password, hostname)

and for MailStore Service Provider Edition (Management API) use

   >>> client = mailstore.mgmt.SPEClient(username, password, hostname)

to initialize API client.

The full documentation can be found here

Server:
https://help.mailstore.com/en/server/Python_API_Wrapper_Tutorial
https://help.mailstore.com/en/server/Administration_API_-_Function_Reference
https://help.mailstore.com/en/server/Administration_API_-_Using_the_API

SPE:
https://help.mailstore.com/en/spe/Python_API_Wrapper_Tutorial
https://help.mailstore.com/en/spe/Management_API_-_Function_Reference
https://help.mailstore.com/en/spe/Management_API_-_Using_the_API
"""

import app.mailstore.mgmt
from app.mailstore.mailstore import MailStoreAPI
