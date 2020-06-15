#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = "Fabio Capanni"
__copyright__ = "Copyright 2020, SEIT srl"
__credits__ = ["Fabio Capanni"]
__license__ = "AGPL"
__version__ = "1.0.0"
__maintainer__ = "Fabio Capanni"
__email__ = "fcapanni@seit.it"
__status__ = "github_dev"

"""
    This class manage the python library given by MailStore
"""

from . import mgmt
import json
from datetime import datetime
from imapclient import IMAPClient


class MailStoreAPI:
    """The class that interacts with MailStore API"""
    def __init__(self, instance, user):
        """
        :param instance:    instance of the logged user
        :param user:        MailStore user that can login in the various Clients
        """
        self.instance = instance
        self.user = user

        # try api connection
        try:
            self.speClient = mgmt.SPEClient(username="", password="", host="", port=0000, ignoreInvalidSSLCerts="True")
            self.speClient.instanceID = self.instance
            print("Connessione API avvenuta con successo!")
        except:
            print("Si è verificato un errore")

    def get_user(self):
        """retrieve username"""
        for user in self.speClient.GetUsers()["result"]:
            user["userName"]

    def set_user_password(self, password):
        """change MailStore user password
        :param password: new password given
        """
        self.speClient.SetUserPassword(self.user, password)

    def get_profiles(self):
        """retrieve profiles filtered by username and targetUserFolder, always share the same name"""
        data_retrieved = self.speClient.GetProfiles()["result"]
        data_filtered = list(filter(lambda dato: dato['details']['targetUserFolder'] == self.user, data_retrieved))
        return data_filtered

    def profiles_status(self):
        """retrieve the results of profiles of the istance, in the current day"""

        # API example: GetWorkerResults - -fromIncluding = "2020-05-15T09:00:00" - -toExcluding = "2020-05-15T23:59:59"
        # - -timeZoneID = "W. Europe Standard Time" - -profileID = 1 - -userName = "admin"
        today = datetime.today().strftime('%Y-%m-%d')
        timeZoneID = "W. Europe Standard Time"
        fromIncluding = today + "T00:00:00"
        toExcluding = today + "T23:59:59"

        data_retrieved = self.speClient.GetWorkerResults(fromIncluding, toExcluding, timeZoneID)
        return data_retrieved

    def update_profile(self, profileId, password):
        """this function combine multiples API, because there is not a function to update a profile
        :param profileId: selected profile ID
        :param password: new password of email account
        :return:
        """

        # save the content of all profiles linked to the user
        profiles_list = self.get_profiles()

        # check if the id corresponding with GetWorkerResult ProfileID
        for profiles_dict in profiles_list:
            if str(profiles_dict['id']) in profileId:
                try:
                    # check if the password of IMAP server is correct, in our case, it must be inside the API,
                    # we don't give the opportunity to the costumer to change the host
                    server = IMAPClient(profiles_dict["details"]["host"], use_uid=True)
                    server.login(profiles_dict["details"]["emailAddress"], password)

                    # create the object by the directives of MailStore SPE API
                    # like in "get_profiles", we must set the MailStore User in details -> targetUserFolder
                    obj = '{ "owner": "'+ profiles_dict["owner"] +'",' \
                            ' "type": "I",' \
                            ' "connector": "'+ profiles_dict["connector"] +'",' \
                            ' "name": "' + profiles_dict["details"]["emailAddress"] + ' via IMAP-SSL from WEB ' + self.user + '",' \
                            ' "details": {"disableAutoExcludeSourceFolders": "0",' \
                            ' "disableAutomaticDetectionOfSentFolders": "0",' \
                            ' "emailAddress": "' + profiles_dict["details"]["emailAddress"] + '",' \
                            ' "excludeUnRead": "0",' \
                            ' "host": "' + profiles_dict["details"]["host"] + '",' \
                            ' "ignoreSSLPolicyErrors": "1",' \
                            ' "password": "' + password + '",' \
                            ' "protocol": "' + profiles_dict["details"]["protocol"] + '",' \
                            ' "subType": "0",' \
                            ' "targetUserFolder": "' + self.user + '",' \
                            ' "timeout": "0",' \
                            ' "userName": "' + profiles_dict["details"]["userName"] + '"},' \
                            ' "serverSideExecution": {"automatic": "true",' \
                            ' "automaticPauseBetweenExecutions": "300" } ' \
                            '}'

                    jsonObj = json.loads(obj)
                    # delete old profile
                    self.delete_profile(profileId)
                    self.create_profile(jsonObj)
                    return ("La password è stata aggiornata!")
                except:
                    return ("La password è errata")

    def delete_profile(self, profileId):
        """delete the profile by the id provided
        :param profileId: selected profile ID
        """
        if(profileId is None):
            return("Non è presente nessun profilo")
        else:
            self.speClient.DeleteProfile(profileId)

    def create_profile(self, properties):
        """create a new profile
        :param properties: object created by the directives of MailStore SPE API
        """
        self.speClient.CreateProfile(properties)

    def get_user_statistics(self):
        """return occupied storage from user in MB"""
        data_retrieved = self.speClient.GetFolderStatistics()["result"]
        user_bytes = list(filter(lambda dato: dato['folder'] == self.user, data_retrieved))

        for k in user_bytes:
            size_in_byte = k['size']
        size = self.bytesto(size_in_byte, 'm')
        return size

    def get_profile_connector(self, profileId):
        """check given profile and return it's connector
        :param profileId: selected profile ID
        :return:
        """
        profiles_list = self.get_profiles()

        for result in profiles_list:
            if str(result['id']) == profileId:
                return result['connector']

    def bytesto(self, bytes, to, bsize=1024):
        """ bytes conversion
        :param bytes: value you want to convert
        :param to: desired format
        """
        a = {'k': 1, 'm': 2, 'g': 3, 't': 4, 'p': 5, 'e': 6}
        r = float(bytes)
        for i in range(a[to]):
            r = r / bsize
        c = '{:,.2f}'.format(r).replace(',', ' ')
        return (c)