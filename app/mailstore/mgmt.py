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

__doc__ = """Wrapper for MailStore Server's Administration API"""


import urllib.request
import urllib.error
import urllib.parse
import logging
import json
import ssl


class BaseClient:
    """The API client class"""
    def __init__(self, username, password, host, port, autoHandleToken, waitTime, callback, logLevel,
                 ignoreInvalidSSLCerts):

        # Initialize connection settings
        self.username = username
        self.password = password
        self.host = host
        self.port = port
  
        # If set to true, client handles tokens/long running tasks itself.
        self.autoHandleToken = autoHandleToken 

        # Time in milliseconds the API should wait before returning a status token.
        self.waitTime = waitTime               

        # Define logging parameters
        self.logLevel = logLevel
        self.logLevels = {0: logging.NOTSET,   # No log output
                          1: logging.ERROR,    # Log errors only
                          2: logging.WARNING,  # Log errors and warnings
                          3: logging.INFO,     # Log informational about what is being done
                          4: logging.DEBUG}    # Log also send and received data

        # Callback Function for status
        self.callback = callback

        # SSL/TLS ignore invalid certificates
        self.ignoreInvalidSSLCerts = ignoreInvalidSSLCerts

        # instanceID is required for SPE Connections
        self.instanceID = None

        # Initialize password manager
        self.passwordMgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        self.realm = (None,
                      "https://{}:{}".format(self.host, self.port),
                      self.username,
                      self.password)
        self.passwordMgr.add_password(*self.realm)
        self.authMgr = urllib.request.HTTPBasicAuthHandler(password_mgr=self.passwordMgr)

        if self.ignoreInvalidSSLCerts:
            # Initialize SSL context
            self.ignoreSslContext = ssl.create_default_context()
            self.ignoreSslContext.check_hostname = False
            self.ignoreSslContext.verify_mode = ssl.CERT_NONE
            self.ignoreSslHandler = urllib.request.HTTPSHandler(context=self.ignoreSslContext)
            # Build Opener with ignoreInvalidSSLCerts
            self.opener = urllib.request.build_opener(self.ignoreSslHandler, self.authMgr)
        else:
            # Build Opener without ignoreInvalidSSLCerts
            # = strict SSL checking, if Python does this by default (>= Python 3.4.3)
            # when using older Python version, strict SSL checking is disabled by default in Python
            # and this wrapper does not implement its own SSL checking routine
            self.opener = urllib.request.build_opener(self.authMgr)

        # By installing this opener every request is handled by our custom BasicAuth and HTTPS handlers
        self.installOpener = urllib.request.install_opener(self.opener)

        # Logger functionality
        self.log = logging.getLogger("MGMTLogger")
        self.log.setLevel(self.logLevels[self.logLevel])
        logging.basicConfig(format="%(asctime)s %(levelname)-8s %(module)s.%(funcName)s() [%(lineno)d]: %(message)s")

        # Retrieve metadata from service so we can check for method availability
        self.metadata = [{"name": "get-status", "args": []},
                         {"name": "cancel-async", "args": []},
                         {"name": "get-metadata", "args": []}]

        self.metadata.extend(self.GetMetadata())

        # Test whether all server methods are implemented
        self._self_test()

    # ---------------------------------------------------------------- #
    # Private Methods                                                  #
    # ---------------------------------------------------------------- #

    def _has_token(self, jsonValues):
        """Verifies that all required attributes for token handling are available."""
        if "token" in jsonValues and jsonValues["token"] is not None and "statusVersion" in jsonValues:
            self.log.info("Status token: {} statusVersion: {}".format(jsonValues["token"], jsonValues["statusVersion"]))
            return True
        else:
            self.log.info("No status token detected.")
            return False

    def _self_test(self):
        """Test method that verifies that all backend methods are implemented."""
        for server_method in self.metadata:
            if server_method["name"] not in ["get-status", "cancel-async", "get-metadata"]:
                if not hasattr(self, server_method["name"]):
                    self.log.error("Client does not implement server method '{}'".format(server_method["name"]))

    def _server_has_method(self, method):
        """Verifies that the backend offers the called method."""
        for server_method in self.metadata:
            if server_method["name"] == method:
                return True
        return False

    def _method_requires_instance_id(self, method):
        """Checks whether a method requires an instance ID."""
        for server_method in self.metadata:
            if server_method["name"] == method:
                for argument in server_method["args"]:
                    # noinspection PyTypeChecker
                    if argument["name"] == "instanceID":
                        return True
                return False

    def call(self, method, arguments=None, invoke=True, autoHandleToken=None):
        """This is where the magic happens! This method is called by all other public methods that wrap
        an Administration API method."""

        if not self._server_has_method(method):
            raise Exception("Server does not implement method '{}'.".format(method))

        if arguments is None:
            arguments = {}

        url = "https://{}:{}/api{}/{}".format(self.host, self.port, "/invoke" if invoke else "", method)

        arguments = [(key, arguments[key]) for key in list(arguments) if arguments[key]]

        if self._method_requires_instance_id(method):
            self.log.debug("Method '{}' requires instanceID.".format(method))
            if self.instanceID is not None:
                arguments.append(("instanceID", self.instanceID))
            else:
                raise Exception("Required argument 'instanceID' for method '{}' cannot be set.".format(method))

        data = urllib.parse.urlencode(arguments)

        self.log.debug("METHOD: {}".format(method))
        self.log.debug("ARGUMENTS: {}".format(arguments))
        self.log.info("HTTP POST: {}, {}".format(url, data))

        # Try making the HTTP request...
        try:
            response = urllib.request.urlopen(url, data=data.encode())
        # ...and catch exceptions.
        except urllib.error.HTTPError as e:
            exceptionString = "{} {} {} {}".format(e.url, e.msg, e.code, data)
            self.log.error(exceptionString)
            raise e
        except urllib.error.URLError as e:
            exceptionString = "{} {}".format(e.reason, url)
            self.log.error(exceptionString)
            if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
                self.log.error("Use a valid TLS certificate or initialize {} with 'ignoreInvalidSSLCerts=True' to workaround this error.".format(
                    self.__class__.__name__))
            raise e
        except Exception as e:
            self.log.error("Unhandled Exception: {}".format(repr(e)))
            raise e

        # Parse server response, which is always in JSON format.
        decodedValues = response.read().decode("utf-8-sig")
        jsonValues = json.loads(decodedValues)
        self.log.debug("HTTP RESPONSE: {}".format(decodedValues))

        # Check if response contains a status token and, depending on the
        # value of autoHandleToken, handle the token ourselves or just
        # return the JSON response to the caller.
        autoHandleToken = self.autoHandleToken if autoHandleToken is None else autoHandleToken

        if self._has_token(jsonValues):
            if autoHandleToken:
                self.log.info("Automatic token handling is ENABLED.")
                returnData = self.HandleToken(jsonValues)
            else:
                self.log.info("Automatic token handling is DISABLED.")
                returnData = jsonValues
        else:
            returnData = jsonValues

        self.log.info("Returning data to caller method '{}'".format(method))
        self.log.debug("DATA: {}".format(str(returnData)))

        return returnData

    def HandleToken(self, json_values, waitTime=None):
        """Helper function for status tokens handling"""
        waitTime = waitTime if waitTime is not None else self.waitTime

        while json_values["statusCode"] == "running":
            self.log.info("Refreshing status for task with token {}.".format(json_values["token"]))
            json_values = self.GetStatus(json_values, waitTime=waitTime)
            self.log.debug("New token values: {}".format(json_values))
            if callable(self.callback):
                self.log.info("Executing callback function '{}' for refreshed status.".format(self.callback.__name__))
                self.callback(json_values)

        self.log.info("Task with token {} finished.".format(json_values["token"]))
        return json_values

    def YieldStatus(self, json_values, waitTime=None):
        """Helper function for status tokens handling"""
        waitTime = waitTime if waitTime is not None else self.waitTime
        yield json_values

        while json_values["statusCode"] == "running":
            self.log.info("Refreshing status for task with token {}.".format(json_values["token"]))
            json_values = self.GetStatus(json_values, waitTime=waitTime)
            yield json_values

    # ---------------------------------------------------------------- #
    # Public Methods                                                   #
    # ---------------------------------------------------------------- #
 
    def GetStatus(self, jsonValues, waitTime=None):
        """Retrieve and update status token of long running task. This
        method is used for automatic token handling, but can also be
        called directly when manual token handling is done."""
        return self.call("get-status", {"token": jsonValues["token"],
                                        "millisecondsTimeout": self.waitTime if waitTime is None else waitTime,
                                        "lastKnownStatusVersion": str(jsonValues["statusVersion"])}, False,
                         autoHandleToken=False)

    def CancelAsync(self, jsonValues):
        """Cancels a long running task."""
        return self.call("cancel-async", {"token": jsonValues["token"]}, False)

    def GetMetadata(self):
        """Retrieves all available methods from backend server."""
        return self.call("get-metadata", invoke=False, autoHandleToken=True)

    # ---------------------------------------------------------------- #
    # Wrapped Administration API methods                               #
    # ---------------------------------------------------------------- #

    # ---------------------------------------------------------------- #
    # Users                                                            #
    # ---------------------------------------------------------------- #

    def GetUsers(self, autoHandleToken=None):
        """Retrieve list of all users

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetUsers", autoHandleToken=autoHandleToken)

    def GetUserInfo(self, userName, autoHandleToken=None):
        """Retrieve detailed user information about specific user

        :param userName:        User name of the user whose information should be returned.
        :type userName:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetUserInfo", {"userName": userName}, autoHandleToken=autoHandleToken)

    def CreateUser(self, userName, privileges=None, fullName=None, distinguishedName=None, authentication=None,
                   password=None, autoHandleToken=None):
        """Creates a new user

        :param userName:            Name of the user to be created.
        :type userName:             str
        :param privileges:          Comma-separated list of global privileges that the user should be granted. Possible values are:
                                    * none                  The user is granted no global privileges.
                                                            If specified, this value has to be the only value in the list.
                                    * admin                 The user is granted administrator privileges.
                                                            If specified, this value has to be the only value in the list.
                                    * login                 The user can log on to MailStore Server.
                                    * changePassword        The user can change his own MailStore Server password.
                                                            Only useful if the authentication is set to 'integrated'.
                                    * archive               The user can run archiving profiles.
                                    * modifyArchiveProfiles The user can create, modify and delete archiving profiles.
                                    * export                The user can run export profiles.
                                    * modifyExportProfiles  The user can create, modify and delete export profiles.
                                    * delete:               The user can delete messages.
                                                            Please note: Normal user can only delete messages in folders where he has
                                                            been granted delete access. In addition, compliance settings may be in
                                                            effect, preventing administrators and normal users from deleting messages
                                                            even when they have been granted the privilege to do so.
        :type privileges:           str
        :param fullName:            (optional) The full name (display name) of the user, e.g. "John Doe".
        :type fullName:             str
        :param distinguishedName:   (optional) The LDAP distinguished name of the user. This is typically automatically
        :type distinguishedName:    str
                                    specified when synchronizing with Active Directory or other LDAP servers.
        :param authentication:      (optional) The authentication mode. Possible values are:
                                    integrated:         Specifies MailStore-integrated authentication. This is the default value.
                                    directoryServices:  Specified Directory Services authentication. If this value is specified,
                                    the password is stored, but is ignored when the user logs on to MailStore Server.
        :type authentication:       str
        :param password:            (optional) The password that the user can use to log on to MailStore Server.
                                    Only used when authentication is set to 'integrated'.
        :type password:             str
        :param autoHandleToken:     If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:      bool
        """
        if isinstance(privileges, (list, tuple)):
            privileges = ",".join(privileges)
        if privileges is None:
            privileges = "none"
        return self.call("CreateUser", {"userName": userName, "privileges": privileges, "fullName": fullName,
                                        "distinguishedName": distinguishedName,
                                        "authentication": authentication,
                                        "password": password}, autoHandleToken=autoHandleToken)

    def SetUserAuthentication(self, userName, authentication, autoHandleToken=None):
        """Set authentication mode of a user

        :param userName:        The user name of the user whose authentication mode should be set.
        :type userName:         str
        :param authentication:  The authentication mode. Possible values are:
                                * integrated          Specifies MailStore-integrated authentication. This is the default value.
                                * directoryServices   Specified Directory Services authentication. If this value is specified,
                                                      the password is stored, but is ignored when the user logs on to MailStore Server.
        :type authentication:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetUserAuthentication", {"userName": userName, "authentication": authentication},
                         autoHandleToken=autoHandleToken)

    def SetUserDistinguishedName(self, userName, distinguishedName=None, autoHandleToken=None):
        """Set distinguished name (DN) of a user

        :param userName:            The user name of the user whose distinguished name should be set (or removed).
        :type userName:             str
        :param distinguishedName:   (optional) The distinguished name to be set. If this argument is not specified,
                                    the distinguished name of the specified user is removed.
        :type distinguishedName:    str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetUserDistinguishedName", {"userName": userName, "distinguishedName": distinguishedName},
                         autoHandleToken=autoHandleToken)

    def SetUserEmailAddresses(self, userName, emailAddresses=None, autoHandleToken=None):
        """Sets the e-mail addresses of a user

        :param userName:        The user name of the user whose e-mail addresses are to be set.
        :type userName:         str
        :param emailAddresses:  (optional) A comma-separated list of e-mail addresses. The first e-mail address
                                in the list must be the user's primary e-mail address.
        :type emailAddresses:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        if isinstance(emailAddresses, (list, tuple)):
            emailAddresses = ",".join(emailAddresses)
        return self.call("SetUserEmailAddresses", {"userName": userName, "emailAddresses": emailAddresses},
                         autoHandleToken=autoHandleToken)

    def SetUserFullName(self, userName, fullName=None, autoHandleToken=None):
        """Set the full name (display name) of a user

        :param userName:        The user name of the user whose full name (display name) should be set (or removed).
        :type userName:         str
        :param fullName:        (optional) The full name to be set. If this argument is not specified, the full
                                name of the specified user is removed.
        :type fullName:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetUserFullName", {"userName": userName, "fullName": fullName},
                         autoHandleToken=autoHandleToken)

    def SetUserPassword(self, userName, password, autoHandleToken=None):
        """Set password of a user

        :param userName:        The user name of the user whose MailStore Server should be set.
        :type userName:         str
        :param password:        The new password.
        :type password:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetUserPassword", {"userName": userName, "password": password},
                         autoHandleToken=autoHandleToken)

    def SetUserPop3UserNames(self, userName, pop3UserNames=None, autoHandleToken=None):
        """Sets POP3 user names of a user (used for MailStore Proxy).

        :param userName:        The user name of the user whose POP3 user names should be set.
        :type userName:         str
        :param pop3UserNames:   (optional) A comma-separated list of POP3 user names that should be set.
        :type pop3UserNames:    str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        if isinstance(pop3UserNames, (list, tuple)):
            pop3UserNames = ",".join(pop3UserNames)
        return self.call("SetUserPop3UserNames", {"userName": userName, "pop3UserNames": pop3UserNames},
                         autoHandleToken=autoHandleToken)

    def SetUserPrivileges(self, userName, privileges, autoHandleToken=None):
        """Set the privileges of a user

        :param userName:        The user name of the user whose global privileges should be set.
        :type userName:         str
        :param privileges:      Comma-separated list of global privileges that the user should be granted. Possible values are:
                                * none                   The user is granted no global privileges.
                                                         If specified, this value has to be the only value in the list.
                                * admin                  The user is granted administrator privileges.
                                                         If specified, this value has to be the only value in the list.
                                * login                  The user can log on to MailStore Server.
                                * changePassword         The user can change his own MailStore Server password.
                                                         Only useful if the authentication is set to 'integrated'.
                                * archive                The user can run archiving profiles.
                                * modifyArchiveProfiles  The user can create, modify and delete archiving profiles.
                                * export                 The user can run export profiles.
                                * modifyExportProfiles   The user can create, modify and delete export profiles.
                                * delete:                The user can delete messages.
                                                         Please note: Normal user can only delete messages in folders where he has
                                                         been granted delete access. In addition, compliance settings may be in
                                                         effect, preventing administrators and normal users from deleting messages
                                                         even when they have been granted the privilege to do so.
        :type privileges:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        if isinstance(privileges, (list, tuple)):
            privileges = ",".join(privileges)
        return self.call("SetUserPrivileges", {"userName": userName, "privileges": privileges},
                         autoHandleToken=autoHandleToken)

    def RenameUser(self, oldUserName, newUserName, autoHandleToken=None):
        """Rename user.
        The user's archive will not be renamed by this method.
        Use the MoveFolder and SetUserPrivilegesOnFolder methods to move the archive as well.

        :param oldUserName:     User name of the user to be renamed.
        :type oldUserName:      str
        :param newUserName:     New user name.
        :type newUserName:      str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RenameUser", {"oldUserName": oldUserName, "newUserName": newUserName},
                         autoHandleToken=autoHandleToken)

    def DeleteUser(self, userName, autoHandleToken=None):
        """Delete a user
        Neither the user's archive nor the user's archived e-mail are deleted when deleting a user.

        :param userName:        The user name of the user to be deleted.
        :type userName:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteUser", {"userName": userName}, autoHandleToken=autoHandleToken)

    def SetUserPrivilegesOnFolder(self, userName, folder, privileges, autoHandleToken=None):
        """Set user's privileges on a specific folder

        :param userName:    The user name of the user who should be granted or denied privileges.
        :type userName:     str
        :param folder:      The folder on which the user should be granted or denied privileges.
                            In the current version, this can only be a top-level folder (user archive).
        :type folder:       str
        :param privileges:  A comma-separated list of privileges that the specified user should be granted on the specified folder. Possible values are:
                            * none    The user is denied access to the specified folder. If specified, this value has to be the only value in the list.
                            * read    The user is granted read access to the specified folder.
                            * write   The user is granted write access to the specified folder.
                            * delete  The user is granted delete access to the specified folder.
        :type privileges:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        if isinstance(privileges, (list, tuple)):
            privileges = ",".join(privileges)
        return self.call("SetUserPrivilegesOnFolder",
                         {"userName": userName, "folder": folder, "privileges": privileges},
                         autoHandleToken=autoHandleToken)

    def ClearUserPrivilegesOnFolders(self, userName, autoHandleToken=None):
        """ Removes all privileges that a user has on archive folders.

        :param userName:        The user name of the user whose privileges on archive folders should be removed.
        :type userName:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("ClearUserPrivilegesOnFolders", {"userName": userName}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Directory Services                                               #
    # ---------------------------------------------------------------- #

    def GetDirectoryServicesConfiguration(self, autoHandleToken=None):
        """Retrieve the current directory service configuration

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetDirectoryServicesConfiguration", autoHandleToken=autoHandleToken)

    def SetDirectoryServicesConfiguration(self, config, autoHandleToken=None):
        """Set directory service configuration
        Use GetDirectoryServicesConfiguration to retrieve a valid config object.

        :param config:          Raw configuration object.
        :type config:           dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetDirectoryServicesConfiguration", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    def SyncUsersWithDirectoryServices(self, dryRun=False, autoHandleToken=None):
        """Synchronizes with currently configured directory service

        :param dryRun:          if set, only retrieve changes from the directory service synchronization
                                but do not store them in the user database.
        :type dryRun:           bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SyncUsersWithDirectoryServices", {"dryRun": json.dumps(dryRun)},
                         autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Compliance                                                       #
    # ---------------------------------------------------------------- #

    def GetComplianceConfiguration(self, autoHandleToken=None):
        """Retrieve the current compliance configuration

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetComplianceConfiguration", autoHandleToken=autoHandleToken)

    def SetComplianceConfiguration(self, config, autoHandleToken=None):
        """Set compliance configuration

        :param config:          Raw configuration object. Use GetComplianceConfiguration to retrieve a valid object.
        :type config:           dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetComplianceConfiguration", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Retention Policies                                               #
    # ---------------------------------------------------------------- #

    def GetRetentionPolicies(self, autoHandleToken=None):
        """Retrieve retention policies

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetRetentionPolicies", autoHandleToken=autoHandleToken)

    def SetRetentionPolicies(self, config, autoHandleToken=None):
        """Set retention policies

        :param config:          The retention policy configuration object. Use GetRetentionPolicies to retrieve the
                                currently set configuration.
        :type config:           dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetRetentionPolicies", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    def ProcessRetentionPolicies(self, autoHandleToken=None):
        """Process retention policies

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("ProcessRetentionPolicies", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # SMTP Settings                                                    #
    # ---------------------------------------------------------------- #

    def GetSmtpSettings(self, autoHandleToken=None):
        """Retrieve SMTP settings
        The returned password property is always None.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetSmtpSettings", autoHandleToken=autoHandleToken)

    def SetSmtpSettings(self, settings, autoHandleToken=None):
        """ Set SMTP settings

        :param settings:        The settings object. Use GetSmtpSettings to get the object structure and its properties.
        :type settings:         dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetSmtpSettings", {"settings": json.dumps(settings)}, autoHandleToken=autoHandleToken)

    def TestSmtpSettings(self, autoHandleToken=None):
        """Test SMTP settings by sending a test message

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("TestSmtpSettings", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Storage                                                          #
    # ---------------------------------------------------------------- #

    def MaintainFileSystemDatabases(self, autoHandleToken=None):
        """Runs maintenance on all file system based databases
        Each Firebird embedded database file (Master and Archive Stores) will be rebuild by this operation
        by creating a backup file and restoring from that backup file.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("MaintainFileSystemDatabases", autoHandleToken=autoHandleToken)

    def RefreshAllStoreStatistics(self, autoHandleToken=None):
        """Refresh statistics of all attached archive stores

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RefreshAllStoreStatistics", autoHandleToken=autoHandleToken)

    def RetryOpenStores(self, autoHandleToken=None):
        """Retry opening stores that could not be opened the last time

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RetryOpenStores", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Archive Stores                                                   #
    # ---------------------------------------------------------------- #

    def GetStores(self, includeSize=True, autoHandleToken=None):
        """Retrieve a list of attached archive stores

        :param includeSize:     Includes the size of the archive store. May be slow when running on slow hardware.
        :type includeSize:      bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetStores", {"includeSize": json.dumps(includeSize)}, autoHandleToken=autoHandleToken)

    def CreateStore(self, name=None, type=None, databasePath=None, contentPath=None, indexPath=None,
                    serverName=None, userName=None, password=None, databaseName=None, requestedState=None,
                    autoHandleToken=None):
        """Creates a new archive store and attaches it afterwards

        :param name:            A meaningful name for the archive store. Examples: "Messages 2012" or "2012-01".
        :type name:             str
        :param type:            Type of archive store. Must be one of the following:
                                * FileSystemInternal
                                * SQLServer
                                * PostgreSQL
        :type type:             str
        :param databasePath:    Directory containing folder information and email meta data. (FileSystemInternal only)
        :type databasePath:     str
        :param contentPath:     Directory containing email headers and contents.
        :type contentPath:      str
        :param indexPath:       Directory containing the full-text indexes.
        :type indexPath:        str
        :param serverName:      Hostname or IP address of database server (MS SQL Server and PostgreSQL only)
        :type serverName:       str
        :param userName:        Username for database access (MS SQL Server and PostgreSQL only)
        :type userName:         str
        :param password:        Password for database access MS SQL Server and PostgreSQL only)
        :type password:         str
        :param databaseName:    Name of SQL database containing folder information and e-mail metadata.
        :type databaseName:     str
        :param requestedState:  Status of the archive store after attaching. Must be one of the following
                                * current         New email messages should be archived into this store.
                                * normal          The archive store should be opened normally. Write access is possible, but new email messages are not archived into this store.
                                * writeProtected  The archive store should be write-protected.
                                * disabled        The archive store should be disabled. This causes the archive store to be closed if it is currently open.
        :type requestedState:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateStore", {"name": name, "type": type, "databasePath": databasePath, "contentPath": contentPath,
                           "indexPath": indexPath, "serverName": serverName, "userName": userName,
                           "password": password,
                           "databaseName": databaseName, "requestedState": requestedState},
                         autoHandleToken=autoHandleToken)

    def AttachStore(self, name, type=None, databasePath=None, contentPath=None, indexPath=None,
                    serverName=None, userName=None, password=None, databaseName=None, requestedState=None,
                    autoHandleToken=None):
        """Attaches an existing archive store
        
        :param name:            A meaningful name for the archive store. Examples: "Messages 2012" or "2012-01".
        :type name:             str
        :param type:            Type of archive store. Must be one of the following:
                                * FileSystemInternal
                                * SQLServer
                                * PostgreSQL
                                The SPE only supports FileSystemInternal and the type must not be given.
        :type type:             str
        :param databasePath:    Directory containing folder information and email meta data. (FileSystemInternal only)
        :type databasePath:     str
        :param contentPath:     Directory containing email headers and contents.
        :type contentPath:      str
        :param indexPath:       Directory containing the full-text indexes.
        :type indexPath:        str
        :param serverName:      Hostname or IP address of database server (MS SQL Server and PostgreSQL only)
        :type serverName:       str
        :param userName:        Username for database access (MS SQL Server and PostgreSQL only)
        :type userName:         str
        :param password:        Password for database access MS SQL Server and PostgreSQL only)
        :type password:         str
        :param databaseName:    Name of SQL database containing folder information and e-mail metadata.
        :type databaseName:     str
        :param requestedState:  Status of the archive store after attaching. Must be one of the follwing
                                * current         New email messages should be archived into this store.
                                * normal          The archive store should be opened normally. Write access is possible, but new email messages are not archived into this store.
                                * writeProtected  The archive store should be write-protected.
                                * disabled        The archive store should be disabled. This causes the archive store to be closed if it is currently open.
        :type requestedState:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("AttachStore", {"name": name, "type": type, "databaseName": databaseName,
                                         "databasePath": databasePath,
                                         "contentPath": contentPath, "indexPath": indexPath,
                                         "serverName": serverName,
                                         "userName": userName, "password": password,
                                         "requestedState": requestedState}, autoHandleToken=autoHandleToken)

    def SetStoreRequestedState(self, id, requestedState, autoHandleToken=None):
        """Set requested state of an archive store

        :param id:              Unique identifier of the archive store whose requested state should be set.
        :type id:               int
        :param requestedState:  Status of the archive store after attaching. Must be one of the following
                                * current         New email messages should be archived into this store.
                                * normal          The archive store should be opened normally. Write access is possible, but new email messages are not archived into this store.
                                * writeProtected  The archive store should be write-protected.
                                * disabled        The archive store should be disabled. This causes the archive store to be closed if it is currently open.
        :type requestedState:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetStoreRequestedState", {"id": id, "requestedState": requestedState},
                         autoHandleToken=autoHandleToken)

    def RenameStore(self, id, name, autoHandleToken=None):
        """Rename archive store

        :param id:              The unique identifier of the archive store to be renamed.
        :type id:               int
        :param name:            The new archive store name.
        :type name:             str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RenameStore", {"id": id, "name": name}, autoHandleToken=autoHandleToken)

    def DetachStore(self, id, autoHandleToken=None):
        """Detach archive store

        :param id:              This unique identifier of the archive store to be detached.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DetachStore", {"id": id}, autoHandleToken=autoHandleToken)

    def CompactStore(self, id, autoHandleToken=None):
        """Compacts an archive store

        :param id:              Unique ID of the  archive store to compact
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CompactStore", {"id": id}, autoHandleToken=autoHandleToken)

    def MergeStore(self, id, sourceId, autoHandleToken=None):
        """Merge two archive stores.
        The source archive store remains unchanged and should be detached afterwards.

        :param id:              Unique identifier of destination archive store
        :type id:               int
        :param sourceId:        Unique identifier of source archive store
        :type sourceId:         int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("MergeStore", {"id": id, "sourceId": sourceId}, autoHandleToken=autoHandleToken)

    def RecoverStore(self, id, encryptionKey=None, recoverDeletedMessages=False, autoHandleToken=None):
        """Recreates a broken Firebird database from recovery records.
        The archive store must have been upgraded to the latest version and the recovery records must not be corrupt.
        The archive store must be in the Disabled or Error state.

        :param id:                      The unique identifier of the archive store to be recovered.
        :type id:                       int
        :param encryptionKey:           (optional) Encryption key of the archive store if no key file is available.
        :type encryptionKey:            str
        :param recoverDeletedMessages:  (optional) Defines whether to recover deleted messages
                                        when the recovery records have not been compacted yet-.
        :type recoverDeletedMessages:   str
        :param autoHandleToken:         If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:          bool
        """
        return self.call("RecoverStore", {"id": id,
                                          "encryptionKey": encryptionKey,
                                          "recoverDeletedMessages": recoverDeletedMessages},
                         autoHandleToken=autoHandleToken)

    def RecreateRecoveryRecords(self, id, autoHandleToken=None):
        """Recreates broken Recovery Records of an archive store.
        Use VerifyStore to verify the state of the Recovery Records.
        Cannot be used for external archive stores that store their content in the database.

        :param id:              The unique identifier of the archive store.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RecreateRecoveryRecords", {"id": id}, autoHandleToken=autoHandleToken)

    def RepairStoreDatabase(self, id, autoHandleToken=None):
        """Recreates the internal indexes of a FireBird database.
        Use VerifyStore to verify the state of the internal indexes.
        Cannot be used for external archive stores that are not FireBird based.

        :param id:              The unique identifier of the archive store.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RepairStoreDatabase", {"id": id}, autoHandleToken=autoHandleToken)

    def UnlockStore(self, id, passphrase, autoHandleToken=None):
        """Unlock a foreign archive store

        In case an archive store from a foreign MailStore installation is attached,
        this method must used to unlock that archive store.

        :param id:              The unique identifier of the archive store to be unlocked.
        :type id:               int
        :param passphrase:      The product key or recovery key of the foreign MailStore installation.
        :type passphrase:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("UnlockStore", {"id": id, "passphrase": passphrase}, autoHandleToken=autoHandleToken)

    def UpgradeStore(self, id, autoHandleToken=None):
        """Upgrade archive store
        When an archive store is needs an upgrade, this method can be used to start this upgrade process.

        :param id:              The unique identifier of the archive store to be upgraded.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("UpgradeStore", {"id": id}, autoHandleToken=autoHandleToken)

    def VerifyStore(self, id, includeIndexes=True, autoHandleToken=None):
        """Verify archive store consistency

        :param id:              The unique identifier of the archive store to be verified.
        :type id:               int
        :param includeIndexes:  Specifies whether the search index files be verfied.
        :type includeIndexes:   bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("VerifyStore", {"id": id, "includeIndexes": json.dumps(includeIndexes)},
                         autoHandleToken=autoHandleToken)

    def VerifyStores(self, includeIndexes=True, autoHandleToken=None):
        """Verify consistency of all archive stores

        :param includeIndexes:  Specifies whether the search index files be verfied.
        :type includeIndexes:   bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("VerifyStores", {"includeIndexes": json.dumps(includeIndexes)},
                         autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Search Indexes                                                   #
    # ---------------------------------------------------------------- #

    def SelectAllStoreIndexesForRebuild(self, autoHandleToken=None):
        """Select all full text indexes for rebuild

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SelectAllStoreIndexesForRebuild", autoHandleToken=autoHandleToken)

    def RebuildSelectedStoreIndexes(self, autoHandleToken=None):
        """Rebuild all full-text indexes selected for rebuild

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RebuildSelectedStoreIndexes", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Jobs                                                             #
    # ---------------------------------------------------------------- #

    def GetJobs(self, autoHandleToken=None):
        """Retrieve list of jobs

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetJobs", autoHandleToken=autoHandleToken)

    def GetJobResults(self, fromIncluding, toExcluding, timeZoneId="$Local", jobId=None, autoHandleToken=None):
        """Retrieves list of finished job executions

        :param fromIncluding:   The date which indicates the beginning time, e.g. "2017-01-01T00:00:00".
        :type fromIncluding:    str
        :param toExcluding:     The date which indicates the ending time, e.g. "2018-01-01T00:00:00".
        :type toExcluding:      str
        :param timeZoneId:      The time zone the date should be converted to, e.g. "$Local",
                                which represents the time zone of the operating system.
                                Use the API command GetTimeZones to retrieve a list of all available time zones.
        :type timeZoneId:       str
        :param jobId:           The job id for which to retrieve results.
        :type jobId:            int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetJobResults",
                         {"fromIncluding": fromIncluding, "toExcluding": toExcluding, "timeZoneId": timeZoneId,
                          "jobId": jobId}, autoHandleToken=autoHandleToken)

    def CreateJob(self, name, action, owner, timeZoneId, date=None, interval=None, time=None, dayOfWeek=None,
                  dayOfMonth=None, autoHandleToken=None):
        """Create a new job to execute Management API commands

        :param name:            A meaningful name for the job. Example: "Daily Backup".
        :type name:             str
        :param action:          Management API command to execute.
        :type action:           str
        :param owner:           Username of the job owner; must be an administrator.
        :type owner:            str
        :param timeZoneId:      The time zone the date should be converted to, e.g. "$Local",
                                which represents the time zone of the operating system.
                                Use GetTimeZones to list all available time zones.
        :type timeZoneId:       str
        :param date:            Datetime string (YYYY-MM-DDThh:mm:ss) for running the job once.
        :type date:             str
        :param interval:        Interval for running job. Allowed value is 5, 10, 15, 20, 30, 60, 120, 180, 240, 360 or 720.
        :type interval:         int
        :param time:            Time for running job. Without additional parameter, this means daily execution.
        :type time:             str
        :param dayOfWeek:       Day of week to run job. Parameter "time" also required.
                                Allowed value is "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
        :type dayOfWeek:        str
        :param dayOfMonth:      Day of month to run job. Parameter "time" also required. dayOfWeek can optionally be used to define further.
                                Allowed values is 1 to 31 and "last".
        :type dayOfMonth:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateJob",
                         {"name": name, "action": action, "owner": owner, "timeZoneId": timeZoneId, "date": date,
                          "interval": interval,
                          "time": time, "dayOfWeek": dayOfWeek, "dayOfMonth": dayOfMonth},
                         autoHandleToken=autoHandleToken)

    def RenameJob(self, id, name, autoHandleToken=None):
        """Rename job

        :param id:              The unique identifier of the job to be renamed.
        :type id:               int
        :param name:            The new job name.
        :type name:             str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RenameJob", {"id": id, "name": name}, autoHandleToken=autoHandleToken)

    def SetJobEnabled(self, id, enabled, autoHandleToken=None):
        """Set enabled status of a job

        :param id:              The unique identifier of the job to be modified.
        :type id:               int
        :param enabled:         Boolean value of "enabled" attribute.
        :type enabled:          bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetJobEnabled", {"id": id, "enabled": json.dumps(enabled)}, autoHandleToken=autoHandleToken)

    def SetJobSchedule(self, id, timeZoneId, date=None, interval=None, time=None, dayOfWeek=None, dayOfMonth=None,
                       autoHandleToken=None):
        """Modify the schedule of a job

        :param id:              The unique identifier of the job to be modified.
        :type id:               int
        :param timeZoneId:      The time zone the date should be converted to, e.g. "$Local",
                                which represents the time zone of the operating system. Use GetTimeZones to get a list of
                                all available time zones and their ids.
        :type timeZoneId:       str
        :param date:            (optional) Datetime string (YYYY-MM-DDThh:mm:ss) for running the job once. E.g. "2018-12-14T05:30:00"
        :type date:             str
        :param interval:        (optional) Interval for running job. Allowed values are 5, 10, 15, 20, 30, 60, 120, 180, 240, 360 or 720.
        :type interval:         int
        :param time:            (optional) Time for running job. Without additional parameter, this means daily execution.
        :type time:             str
        :param dayOfWeek:       (optional) Day of week to run job. Parameter "time" also required.
                                Allowed values are "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
        :type dayOfWeek:        str
        :param dayOfMonth:      (optional) Day of month to run job. Parameter "time" also required. dayOfWeek can optionally be used to define further. Allowed values is 1 to 31 and "Last".
        :type dayOfMonth:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetJobSchedule",
                         {"id": id, "timeZoneId": timeZoneId, "date": date, "interval": interval,
                          "time": time, "dayOfWeek": dayOfWeek, "dayOfMonth": dayOfMonth},
                         autoHandleToken=autoHandleToken)

    def DeleteJob(self, id, autoHandleToken=None):
        """Deletes a job

        :param id:              The unique identifier of the job to be deleted
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteJob", {"id": id}, autoHandleToken=autoHandleToken)

    def RunJobAsync(self, id, autoHandleToken=None):
        """Run existing job
        Using this method will trigger the asynchronous execution of a previously created job. Thus this method does not
        wait for the triggered job to finish. Use GetJobResults to retrieve status of jobs.

        :param id:              The identifier of the job to be run.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RunJobAsync", {"id": id}, autoHandleToken=autoHandleToken)

    def CancelJobAsync(self, id, autoHandleToken=None):
        """Cancel a running job asynchronously

        :param id:              Unique ID of the job to be canceled.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CancelJobAsync", {"id": id}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Profiles                                                         #
    # ---------------------------------------------------------------- #

    def GetProfiles(self, raw=True, autoHandleToken=None):
        """Retrieve list of profiles

        :param raw:             Defines whether raw profile data is returned. Currently only True is supported
        :type raw:              bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetProfiles", {"raw": json.dumps(raw)}, autoHandleToken=autoHandleToken)

    def GetWorkerResults(self, fromIncluding, toExcluding, timeZoneID="$Local", profileID=None, userName=None,
                         autoHandleToken=None):
        """Retrieves list of finished profile executions
        This is the only method where ID in timeZoneID is written with a capital 'D'.

        :param fromIncluding:   The date which indicates the beginning time, e.g. "2017-01-01T00:00:00".
        :type fromIncluding:    str
        :param toExcluding:     The date which indicates the ending time, e.g. "2018-01-01T00:00:00".
        :type toExcluding       str
        :param timeZoneID:      The time zone the date should be converted to, e.g. "$Local",
                                which represents the time zone of the operating system.
        :type timeZoneID:       str
        :param profileID:       The profile id for which to retrieve results.
        :type profileID:        int
        :param userName:        The user name for which to retrieve results.
        :type userName:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetWorkerResults",
                         {"fromIncluding": fromIncluding, "toExcluding": toExcluding, "timeZoneID": timeZoneID,
                          "profileID": profileID, "userName": userName}, autoHandleToken=autoHandleToken)

    def CreateProfile(self, properties=None, raw=True, autoHandleToken=None):
        """Create a new archiving or exporting profile.

        :param properties:      Profile properties.
        :type properties:       dict
        :param raw:             Defines whether raw data is sent. Currently only True is supported.
        :type raw:              bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateProfile", {"properties": json.dumps(properties), "raw": json.dumps(raw)},
                         autoHandleToken=autoHandleToken)

    def RunProfile(self, id, autoHandleToken=None):
        """Run existing archiving or exporting profile

        :param id:              The identifier of the profile to be run.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RunProfile", {"id": id}, autoHandleToken=autoHandleToken)

    def RunTemporaryProfile(self, properties=None, raw=True, autoHandleToken=None):
        """Run temporary archiving or exporting profile
        Using this method will run the profile once, without actually storing the profile configuration in the database.
        Create a profile manually and use the GetProfiles method the get example properties that can be adjusted.

        :param properties:      The raw profile properties. Values of an existing profile can be used as template
        :type properties:       dict
        :param raw:             Defines whether raw profile data is sent. Only True is currently supported.
        :type raw:              bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RunTemporaryProfile", {"properties": json.dumps(properties), "raw": json.dumps(raw)},
                         autoHandleToken=autoHandleToken)

    def DeleteProfile(self, id, autoHandleToken=None):
        """Deletes an archiving or export profile

        :param id:              The unique identifier of the profile to be deleted.
        :type id:               int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteProfile", {"id": id}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Folders                                                          #
    # ---------------------------------------------------------------- #

    def GetFolderStatistics(self, autoHandleToken=None):
        """Retrieve folder statistics

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetFolderStatistics", autoHandleToken=autoHandleToken)

    def GetChildFolders(self, folder=None, maxLevels=None, autoHandleToken=None):
        """Retrieves a list of child folders of a specific folder.
        Depending on compliance settings this method may return only the first folder hierarchy level.

        :param folder:      (optional) The folder of which the child folders are to be retrieved. If you don't specify this parameter,
                            the method returns the child folders of the root level (user archives).
        :type folder:       str
        :param maxLevels:   (optional) If maxLevels is not specified, this method returns the child folders recursively,
                            which means that you get the whole folder hierarchy starting at the folder specified.
                            Set maxLevels to a value equal to or greater than 1 to limit the levels returned.
        :type maxLevels:    int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetChildFolders", {"folder": folder, "maxLevels": maxLevels}, autoHandleToken=autoHandleToken)

    def MoveFolder(self, fromFolder, toFolder, autoHandleToken=None):
        """Move or rename an archive folder

        :param fromFolder:      The folder which should be moved or renamed, e.g. "johndoe/Outlook/Inbox".
        :type fromFolder:       str
        :param toFolder:        The target folder name, e.g. "johndoe/Outlook/Inbox-new".
        :type toFolder:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("MoveFolder", {"fromFolder": fromFolder, "toFolder": toFolder},
                         autoHandleToken=autoHandleToken)

    def DeleteEmptyFolders(self, folder=None, autoHandleToken=None):
        """Deletes archive folders which don't contain any messages

        :param folder:          (optional) If specified, only this folder and its subfolders are deleted if empty.
                                Folder delimiter is /
                                If not specified, all empty folders in the entire archive are removed.
        :type folder:           str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteEmptyFolders", {"folder": folder}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Miscellaneous                                                    #
    # ---------------------------------------------------------------- #

    def SendStatusReport(self, timespan, timeZoneId, recipients, autoHandleToken=None):
        """Sends a status report covering timespan to the given recipients.

        :param timespan:        Timespan that is covered by the status report to send.
                                Valid values are: today, yesterday, thisweek, lastweek, thismonth, lastmonth
        :type timespan:         str
        :param timeZoneId:      TimeZoneId of the time zone to use. Use GetTimeZones to get a list of all available time zones and their ids.
        :type timeZoneId:       str
        :param recipients:      Comma separated list of recipients that will receive the status report.
        :type recipients:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SendStatusReport",
                         {"timespan": timespan, "timeZoneId": timeZoneId, "recipients": recipients},
                         autoHandleToken=autoHandleToken)

    def GetTimeZones(self, autoHandleToken=None):
        """Retrieve list of all available time zones on the server
        This is particularly useful for the GetWorkerResults and GetJobResults method.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetTimeZones", autoHandleToken=autoHandleToken)


class ServerClient(BaseClient):
    def __init__(self, username="admin", password="admin", host="127.0.0.1", port=8463,
                 autoHandleToken=True, waitTime=1000, callback=None, logLevel=2,
                 ignoreInvalidSSLCerts=False):
        super().__init__(username, password, host, port,
                         autoHandleToken, waitTime, callback, logLevel, ignoreInvalidSSLCerts)

        # Only done in ServerClient, because the SPE does not allow unauthorized access
        # to get-metadata and already throws an error when fetching that earlier in __init__
        self.auth_test()

    def auth_test(self):
        result = self.GetServerInfo()
        if result["statusCode"] == "failed":
            raise Exception(result["error"]["message"])

    # ---------------------------------------------------------------- #
    # MailStore Server specific API methods                            #
    # ---------------------------------------------------------------- #

    # ---------------------------------------------------------------- #
    # Storage                                                          #
    # ---------------------------------------------------------------- #

    def CreateBackup(self, path, excludeSearchIndexes, autoHandleToken=None):
        """Create a backup of the entire archive

        :param path:                    Path to directory into which the backup should be written.
        :type path:                     str
        :param excludeSearchIndexes:    Indicates whether the search index files should be excluded from the backup.
        :type excludeSearchIndexes:     bool
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateBackup",
                         {"path": path, "excludeSearchIndexes": json.dumps(excludeSearchIndexes)},
                         autoHandleToken=autoHandleToken)

    def CompactMasterDatabase(self, autoHandleToken=None):
        """Compacts the master database

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CompactMasterDatabase", autoHandleToken=autoHandleToken)

    def RenewMasterKey(self, autoHandleToken=None):
        """Renews the master key which is used to encrypt the encryption keys.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RenewMasterKey", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Archive Stores                                                   #
    # ---------------------------------------------------------------- #

    def SetStoreProperties(self, id, type=None, databasePath=None, contentPath=None, indexPath=None,
                           serverName=None, userName=None, password=None, databaseName=None, autoHandleToken=None):
        """Set properties of a store

        :param id:              Unique identifier of archive store to be modified.
        :type id:               int
        :param type:            Type of archive store. Must be one of the following:
                                * FileSystemInternal
                                * SQLServer
                                * PostgreSQL
        :type type:             str
        :param databasePath:    Directory containing folder information and email meta data. (FileSystemInternal only)
        :type databasePath:     str
        :param contentPath:     Directory containing email headers and contents.
        :type contentPath:      str
        :param indexPath:       Directory containing the full-text indexes.
        :type indexPath:        str
        :param serverName:      Hostname or IP address of database server (MS SQL Server and PostgreSQL only)
        :type serverName:       str
        :param userName:        Username for database access (MS SQL Server and PostgreSQL only)
        :type userName:         str
        :param password:        Password for database access MS SQL Server and PostgreSQL only)
        :type password:         str
        :param databaseName:    Name of SQL database containing folder information and e-mail metadata.
        :type databaseName:     str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetStoreProperties",
                         {"id": id, "type": type, "databaseName": databaseName, "databasePath": databasePath,
                          "contentPath": contentPath, "indexPath": indexPath, "serverName": serverName,
                          "userName": userName, "password": password}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Search Indexes                                                   #
    # ---------------------------------------------------------------- #

    def GetStoreIndexes(self, id=None, autoHandleToken=None):
        """Retrieve list of full text indexes for given archive store

        :param id:  The unique identifier of the archive store whose full-text indexes are to be returned.
        :type id:   int
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetStoreIndexes", {"id": id}, autoHandleToken=autoHandleToken)

    def RebuildStoreIndex(self, id, folder, autoHandleToken=None):
        """Rebuild full-text index

        :param id:              The unique identifier of the archive store that contains the full-text index to be rebuilt.
        :type id:               int
        :param folder:          Name of the archive of which the full-text index should be rebuild e.g. "johndoe".
        :type folder:           str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RebuildStoreIndex", {"id": id, "folder": folder}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Messages                                                         #
    # ---------------------------------------------------------------- #

    def GetMessages(self, folder, autoHandleToken=None):
        """Retrieve list of messages from a specific folder

        :param folder:          The folder from which to retrieve the message list
        :type folder:           str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetMessages", {"folder": folder}, autoHandleToken=autoHandleToken)

    def DeleteMessage(self, id, reason, autoHandleToken=None):
        """Deletes a single message from the archive

        :param id:              The unique identifier of the message to be deleted in format <store_id>:<message_num>
        :type id:               str
        :param reason:          The reason why a message has to be deleted.
        :type reason:           str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteMessage", {"id": id, "reason": reason}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Miscellaneous                                                    #
    # ---------------------------------------------------------------- #

    def GetServerInfo(self, autoHandleToken=None):
        """Retrieve list of general server information

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetServerInfo", autoHandleToken=autoHandleToken)

    def GetServiceConfiguration(self, autoHandleToken=None):
        """Retrieve service configuration

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetServiceConfiguration", autoHandleToken=autoHandleToken)

    def GetActiveSessions(self, autoHandleToken=None):
        """Retrieve list of active logon sessions

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetActiveSessions", autoHandleToken=autoHandleToken)


class SPEClient(BaseClient):
    def __init__(self, username="admin", password="admin", host="127.0.0.1", port=8474,
                 autoHandleToken=True, waitTime=1000, callback=None, logLevel=2,
                 ignoreInvalidSSLCerts=False, instanceID=None):
        super().__init__(username, password, host, port,
                         autoHandleToken, waitTime, callback, logLevel, ignoreInvalidSSLCerts)
        # Default instanceId for SPE connections
        self.instanceID = instanceID

    # ---------------------------------------------------------------- #
    # MailStore SPE specific API methods                               #
    # ---------------------------------------------------------------- #

    # ---------------------------------------------------------------- #
    # Management Server                                                #
    # ---------------------------------------------------------------- #

    def GetEnvironmentInfo(self, autoHandleToken=None):
        """Return general information about SPE environment.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetEnvironmentInfo", autoHandleToken=autoHandleToken)

    def GetServiceStatus(self, autoHandleToken=None):
        """Get current status of all SPE services.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetServiceStatus", autoHandleToken=autoHandleToken)

    def PairWithManagementServer(self, serverType, serverName, port, thumbprint, autoHandleToken=None):
        """Pair server role with Management Server.

        :param serverType:      Type of server role.
        :type serverType:       str
        :param serverName:      Name of server that hosts 'serverType' role.
        :type serverName:       str
        :param port:            TCP port on which 'serverType' role on 'serverName' accepts connections.
        :type port:             str
        :param thumbprint:      Thumbprint of SSL certificate used by serverType' role on 'serverName'.
        :type thumbprint:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("PairWithManagementServer",
                         {"serverType": serverType, "serverName": serverName, "port": port, "thumbprint": thumbprint},
                         autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Client Access Servers                                            #
    # ---------------------------------------------------------------- #

    def GetClientAccessServers(self, withServiceStatus, serverNameFilter=None, autoHandleToken=None):
        """Get list of Client Access Servers.

        :param withServiceStatus:   Include service status or not.
        :type withServiceStatus:    bool
        :param serverNameFilter:    Server name filter string.
        :type serverNameFilter:     str
        :param autoHandleToken:     If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:      bool
        """
        return self.call("GetClientAccessServers",
                         {"serverNameFilter": serverNameFilter, "withServiceStatus": json.dumps(withServiceStatus)},
                         autoHandleToken=autoHandleToken)

    def CreateClientAccessServer(self, config, autoHandleToken=None):
        """Register new client access server.

        :param config:          Configuration of new client access server
        :type config:           str  (JSON)
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateClientAccessServer", {"config": config}, autoHandleToken=autoHandleToken)

    def SetClientAccessServerConfiguration(self, config, autoHandleToken=None):
        """Set the configuration of a Client Access Server.

        :param config:          Client Access Server configuration.
        :type config:           str (JSON)
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetClientAccessServerConfiguration", {"config": config}, autoHandleToken=autoHandleToken)

    def DeleteClientAccessServer(self, serverName, autoHandleToken=None):
        """Delete Client Access Server from management database.

        :param serverName:      Name of Client Access Server.
        :type serverName:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteClientAccessServer", {"serverName": serverName}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Instance Hosts                                                   #
    # ---------------------------------------------------------------- #

    def GetInstanceHosts(self, serverNameFilter=None, autoHandleToken=None):
        """Get list of Instance Hosts.

        :param serverNameFilter: Server name filter string.
        :type serverNameFilter:  str
        :param autoHandleToken:  If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:   bool
        """
        return self.call("GetInstanceHosts", {"serverNameFilter": serverNameFilter}, autoHandleToken=autoHandleToken)

    def CreateInstanceHost(self, config, autoHandleToken=None):
        """Create a new Instance Host.

        :param config:          Configuration of new Instance Host.
        :type config:           str (JSON)
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateInstanceHost", {"config": config}, autoHandleToken=autoHandleToken)

    def SetInstanceHostConfiguration(self, config, autoHandleToken=None):
        """Set configuration of Instance Host.

        :param config:          Instance Host configuration.
        :type config:           str (JSON)
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetInstanceHostConfiguration", {"config": config}, autoHandleToken=autoHandleToken)

    def GetDirectoriesOnInstanceHost(self, serverName, path=None, autoHandleToken=None):
        """Get file system directory structure from Instance Host.

        :param serverName:      Name of Instance Host.
        :type serverName        str
        :param path:            Path of directory to obtain subdirectories from.
        :type path:             str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetDirectoriesOnInstanceHost", {"serverName": serverName, "path": path},
                         autoHandleToken=autoHandleToken)

    def CreateDirectoryOnInstanceHost(self, serverName, path, autoHandleToken=None):
        """Create a directory on an Instance Host

        :param serverName:      Name of Instance Host.
        :type serverName:       str
        :param path:            Path of directory to create.
        :type path:             str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        this can be used to create empty directories for new instances"""
        return self.call("CreateDirectoryOnInstanceHost", {"serverName": serverName, "path": path},
                         autoHandleToken=autoHandleToken)

    def DeleteInstanceHost(self, serverName, autoHandleToken=None):
        """Delete Instance Host from management database.

        :param serverName:      Name of Client Access Server.
        :type serverName:       str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteInstanceHost", {"serverName": serverName}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Instances                                                        #
    # ---------------------------------------------------------------- #

    def GetInstances(self, instanceFilter, autoHandleToken=None):
        """Get list of instances.

        :param instanceFilter:  Instance filter string.
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    def CreateInstance(self, config, autoHandleToken=None):
        """Creates new instance.

        :param config           Configuration of new Instance Host
        :type  config:          str (JSON)
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateInstance", {"config": config}, autoHandleToken=autoHandleToken)

    def GetInstanceConfiguration(self, autoHandleToken=None):
        """Get configuration of MailStore Instance.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetInstanceConfiguration", autoHandleToken=autoHandleToken)

    def SetInstanceConfiguration(self, config, autoHandleToken=None):
        """Set configuration of MailStore Instance

        :param config:          Instance configuration.
        :type config:           str (JSON)
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetInstanceConfiguration", {"config": config}, autoHandleToken=autoHandleToken)

    def StartInstances(self, instanceFilter, autoHandleToken=None):
        """Start one or multiple MailStore Instances.

        :param instanceFilter:  Instance filter string
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("StartInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    def RestartInstances(self, instanceFilter, autoHandleToken=None):
        """Restart one or multiple instances.

        :param instanceFilter:  Instance filter string
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("RestartInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    def StopInstances(self, instanceFilter, autoHandleToken=None):
        """Stop one or multiple MailStore Instances.

        :param instanceFilter:  Instance filter string
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("StopInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    def FreezeInstances(self, instanceFilter, autoHandleToken=None):
        """Freeze a MailStore Instance

        :param instanceFilter:  Instance filter string.
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("FreezeInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    def ThawInstances(self, instanceFilter, autoHandleToken=None):
        """Thaw one or multiple MailStore Instances.

        :param instanceFilter:  Instance filter string.
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("ThawInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    def GetInstanceStatistics(self, autoHandleToken=None):
        """Get archive statistics from instance.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetInstanceStatistics", autoHandleToken=autoHandleToken)

    def GetInstanceProcessLiveStatistics(self, autoHandleToken=None):
        """Get live statistics from Instance process.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetInstanceProcessLiveStatistics", autoHandleToken=autoHandleToken)

    def DeleteInstances(self, instanceFilter, autoHandleToken=None):
        """Delete one or multiple MailStore Instances

        :param instanceFilter:  Instance filter string
        :type instanceFilter:   str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteInstances", {"instanceFilter": instanceFilter}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Service Provider Access                                          #
    # ---------------------------------------------------------------- #

    def GetArchiveAdminEnabled(self, autoHandleToken=None):
        """Get current state of archive admin access.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetArchiveAdminEnabled", autoHandleToken=autoHandleToken)

    def SetArchiveAdminEnabled(self, enabled, autoHandleToken=None):
        """Enable or disable archive admin access.

        :param enabled:          Enable or disable flag.
        :type enabled:           bool
         :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
         :type autoHandleToken:  bool
        """
        return self.call("SetArchiveAdminEnabled", {"enabled": json.dumps(enabled)}, autoHandleToken=autoHandleToken)

    def CreateClientOneTimeUrlForArchiveAdmin(self, instanceUrl=None, autoHandleToken=None):
        """Create URL including OTP for $archiveadmin access.

        :param instanceUrl:     Base URL for accessing instance.
        :type instanceUrl:      str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateClientOneTimeUrlForArchiveAdmin", {"instanceUrl": instanceUrl}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Storage                                                          #
    # ---------------------------------------------------------------- #

    def CanRunArchiveProfiles(self, autoHandleToken=None):
        """Checks whether and instance can run archive profiles

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CanRunArchiveProfiles", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Archive Stores                                                   #
    # ---------------------------------------------------------------- #

    def SetStorePath(self, id, path, autoHandleToken=None):
        """Set the path to archive store data.

        :param id:              Unique ID of archive store.
        :type id:               int
        :param path:            Path to archive store data.
        :type path              str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetStorePath", {"id": id, "path": path}, autoHandleToken=autoHandleToken)

    def GetStoreAutoCreateConfiguration(self, autoHandleToken=None):
        """Get automatic archive store creation settings.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetStoreAutoCreateConfiguration", autoHandleToken=autoHandleToken)

    def SetStoreAutoCreateConfiguration(self, config, autoHandleToken=None):
        """Set configuration for automatic archive store creation.

        :param config:          Archive store automatic creation configuration.
        :type config:           dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetStoreAutoCreateConfiguration", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Search Indexes                                                   #
    # ---------------------------------------------------------------- #

    def GetIndexConfiguration(self, autoHandleToken=None):
        """Get list of attachment file types to index.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetIndexConfiguration", autoHandleToken=autoHandleToken)

    def SetIndexConfiguration(self, config, autoHandleToken=None):
        """Set full text search index configuration.

        :param config:          Full text search index configuration
        :type config            dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetIndexConfiguration", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # System Administrators                                            #
    # ---------------------------------------------------------------- #

    def GetSystemAdministrators(self, autoHandleToken=None):
        """Get list of system administrators.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetSystemAdministrators", autoHandleToken=autoHandleToken)

    def CreateSystemAdministrator(self, config, password, autoHandleToken=None):
        """Create a new SPE system administrator.

        :param config:          Configuration of new SPE system administrator.
        :type config:           dict
        :param password:        Password of new SPE system administrator.
        :type password:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("CreateSystemAdministrator", {"config": json.dumps(config), "password": password},
                         autoHandleToken=autoHandleToken)

    def SetSystemAdministratorConfiguration(self, config, autoHandleToken=None):
        """Set configuration of a system administrator.

        :param config:          The config object. Use GetSystemAdministrators to get the object structure and its properties.
        :type config:           dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetSystemAdministratorConfiguration", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    def SetSystemAdministratorPassword(self, userName, password, autoHandleToken=None):
        """Set password for SPE system administrator.

        :param userName:        User name of SPE system administrator.
        :type userName:         str
        :param password:        New password for SPE system administrator.
        :type password:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetSystemAdministratorPassword", {"userName": userName, "password": password},
                         autoHandleToken=autoHandleToken)

    def DeleteSystemAdministrator(self, userName, autoHandleToken=None):
        """Delete SPE system administrator.

        :param userName:        User name of SPE system administrator.
        :type userName:         str
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("DeleteSystemAdministrator", {"userName": userName}, autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # System SMTP Settings                                             #
    # ---------------------------------------------------------------- #

    def GetSystemSmtpConfiguration(self, autoHandleToken=None):
        """Retrieve system wide SMTP settings. The password property is always None.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("GetSystemSmtpConfiguration", autoHandleToken=autoHandleToken)

    def SetSystemSmtpConfiguration(self, config, autoHandleToken=None):
        """ Set system wide SMTP settings

        :param config:          The config object. Use GetSystemSmtpSettings to get the object structure and its properties.
        :type config:           dict
        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("SetSystemSmtpConfiguration", {"config": json.dumps(config)}, autoHandleToken=autoHandleToken)

    def TestSystemSmtpConfiguration(self, autoHandleToken=None):
        """Test system wide SMTP settings by sending a test message.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("TestSystemSmtpConfiguration", autoHandleToken=autoHandleToken)

    # ---------------------------------------------------------------- #
    # Miscellaneous                                                    #
    # ---------------------------------------------------------------- #

    def CreateLicenseRequest(self, autoHandleToken=None):
        """Create and return data of a license request.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type  autoHandleToken:  bool
        """
        return self.call("CreateLicenseRequest", autoHandleToken=autoHandleToken)

    def Ping(self, autoHandleToken=None):
        """Send a keep alive packet.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("Ping", autoHandleToken=autoHandleToken)

    def ReloadBranding(self, autoHandleToken=None):
        """Reloads the branding.

        :param autoHandleToken: If set to True, the caller does not need to handle tokens of long running tasks, but instead has to wait for the result.
        :type autoHandleToken:  bool
        """
        return self.call("ReloadBranding", autoHandleToken=autoHandleToken)
