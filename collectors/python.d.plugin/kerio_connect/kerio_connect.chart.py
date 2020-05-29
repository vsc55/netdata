# -*- coding: utf-8 -*-
# Description: kerio connect netdata python.d module
# Author: vsc55 (vsc55@cerebelum.net)
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from requests import session

from bases.FrameworkServices.UrlService import UrlService

ORDER = [
    'uptime',
    'storage',
    # 'received',
]

CHARTS = {
    'uptime': {
        'options': [None, 'Uptime', 'minuts', 'Server Uptime', 'kerio_connect.uptime', 'line'],
        'lines': [
            ['uptime']
            
        ]
    },
    'storage': {
        'options': [None, 'Storage', 'GiB', 'Storage', 'kerio_connect.storage', 'stacked'],
        'lines': [
            ['storage_avail', 'avail', 'absolute'],
            ['storage_used', 'used', 'absolute']
        ]
    },
    # 'received': {
    #     'options': [None, 'Uptime', 'minuts', 'Server Uptime', 'kerio_connect.received', 'line'],
    #     'lines': [
    #         ['uptime']
            
    #     ]
    # },




}

class Service(UrlService):

    _default_body = {
        "jsonrpc": "2.0",
        "id": "Null",
        "method": "",
        "params": ""
    }

    def __init__(self, configuration=None, name=None):
        UrlService.__init__(self, configuration=configuration, name=name)
        self.order = ORDER
        self.definitions = CHARTS
        self.url = self.configuration.get('url', 'http://localhost/admin/api/jsonrpc/')
        self.method = "POST"
        self.request_timeout = 5
        self.update_every = self.configuration.get('update_every', 10)
        self._api_user = self.configuration.get('user', '')
        self._api_pass = self.configuration.get('pass', '')
        self._api_token = ""
        self._cookie_session = ""
        
        #self.header = {'content-type': 'application/json'}


    def _headers_get_cookies(self, headers):
        data_return = dict()
        if 'Set-Cookie' in headers:
            for item in headers['Set-Cookie'].split(";"):
                cookie = item.split("=", 1)
                data_return.update( {
                    cookie[0] : "" if len(cookie) == 1 else cookie[1]
                } )
        return data_return


    def _header_update(self):
        self.header = { 
            'content-type': 'application/json' 
        }

        if self._api_token:
            self.header.update( {
                'X-Token' : self._api_token
            } )

        if self._cookie_session:
            self.header.update( {
                "Cookie": "SESSION_CONNECT_WEBADMIN={0}".format(self._cookie_session)
            } )

        self._manager = self._build_manager()

    def _clean(self):
        self._api_token = ""
        self._cookie_session = ""


    def _login(self):
        if self._api_token:
            self._logout()

        self._clean()
        self._header_update()

        body = dict(self._default_body)
        body['method'] = "Session.login"
        body['params'] = {
            'userName': self._api_user,
            'password': self._api_pass,
            'application': {
                'name': 'Netdata Plugin',
                'vendor': 'Vendor',
                'version': '1.0',
            }
        }
        self.body = json.dumps(body)

        try:
            headers, raw = self._get_raw_data_advanced()
            cookies = self._headers_get_cookies(headers)
            self._cookie_session = "" if not 'SESSION_CONNECT_WEBADMIN' in cookies else cookies['SESSION_CONNECT_WEBADMIN']
            json_data = json.loads(raw)

        except (ValueError, AttributeError):
            self.debug("Login Exception!")
            return False

        finally:
            self.body = ""

        if 'error' in json_data:
            self.debug("Login ERR!")
            return False
        else:
            self.debug("Login OK!")
            self._api_token = json_data['result']['token']
            return True

    def _logout(self):
        self._header_update()

        body = dict(self._default_body)
        body['method'] = "Session.logout"
        self.body = json.dumps(body)

        try:
            _, raw = self._get_raw_data_advanced()
            json_data = json.loads(raw)

        except (ValueError, AttributeError):
            self.debug("Logout Exception!")
            return False
        
        finally:
            self.body = ""
            self._clean()

        if 'error' in json_data:
            self.debug("Logout Error!!!")
            return False
        else:
            self.debug("Logout OK!")
            return True

    def _get_statistics(self):
        self._header_update()

        body = dict(self._default_body)
        body['method'] = "Statistics.get"
        self.body = json.dumps(body)

        try:
            _, raw = self._get_raw_data_advanced()
            json_data = json.loads(raw)

        except (ValueError, AttributeError):
            self.debug("Get Statistics Exception!")
            return None
        
        finally:
            self.body = ""

        if 'error' in json_data:
            self.debug("Get Statistics Error!!!")
            return None
        else:
            self.debug("Get Statistics OK!")
            return json_data['result']['statistics']



    def _get_data(self):
        data_return = dict()
        if self._login():
            datos = self._get_statistics()
            # print(datos)

            data_return = {

                # "uptime": {
                #     "days": 2,
                #     "hours": 4,
                #     "minutes": 41
                # }
                'uptime': int( datos['uptime']['minutes'] + (datos['uptime']['hours'] * 60) + ( (datos['uptime']['days'] * 60) * 24 ) ),

                # "storage": {
                #     "total": {
                #         "value": 10717,
                #         "units": "GigaBytes"
                #     },
                #     "occupied": {
                #         "value": 9834,
                #         "units": "GigaBytes"
                #     },
                #     "percentage": "91"
                # }
                'storage_total' : int(datos['storage']['total']['value']),
                'storage_used' : int(datos['storage']['occupied']['value']),
                'storage_avail' : int(datos['storage']['total']['value']) - int(datos['storage']['occupied']['value']),
            }
            # print(data_return)
            # data_return = dict()
            self._logout()

        return data_return
        
    
            










# "start": 1555847378,
# "received": {
# "storedInQueue": {
# "transmitted": {
# "deliveredToLocals": {
# "mx": {
# "relay": {
# "failures": {
# "deliveryStatus": {
# "antivirus": {
# "spam": {
# "other": {
# "smtpServer": {
# "smtpClient": {
# "pop3Server": {
# "pop3Client": {
# "imapServer": {
# "ldapServer": {
# "webServer": {
# "xmppServer": {
# "dnsResolver": {
# "antibombing": {
# "greylisting": {




# {
    # "jsonrpc": "2.0",
    # "id": 1,
    # "result": {
        # "statistics": {
            # "start": 1555847378,

            # "received": {
                # "count": "47350",
                # "volume": {
                    # "value": 2986,
                    # "units": "MegaBytes"
                # },
                # "recipients": "49460"
            # },

            # "storedInQueue": {
                # "count": "0",
                # "volume": {
                    # "value": 0,
                    # "units": "Bytes"
                # },
                # "recipients": "0"
            # },

            # "transmitted": {
                # "count": "48941",
                # "volume": {
                    # "value": 3087,
                    # "units": "MegaBytes"
                # },
                # "recipients": "48941"
            # },

            # "deliveredToLocals": {
                # "count": "47967",
                # "volume": {
                    # "value": 2632,
                    # "units": "MegaBytes"
                # },
                # "recipients": "47967"
            # },

            # "mx": {
                # "count": "0",
                # "volume": {
                    # "value": 0,
                    # "units": "Bytes"
                # },
                # "recipients": "0"
            # },

            # "relay": {
                # "count": "974",
                # "volume": {
                    # "value": 465322,
                    # "units": "KiloBytes"
                # },
                # "recipients": "974"
            # },

            # "failures": {
                # "transientFailures": "93",
                # "permanentFailures": "4"
            # },

            # "deliveryStatus": {
                # "success": "1",
                # "delay": "2",
                # "failure": "4"
            # },

            # "antivirus": {
                # "checkedAttachments": "0",
                # "foundViruses": "0",
                # "prohibitedTypes": "0"
            # },

            # "spam": {
                # "checked": "46942",
                # "tagged": "17",
                # "rejected": "0",
                # "markedAsSpam": "1",
                # "markedAsNotSpam": "2"
            # },

            # "other": {
                # "largest": {
                    # "value": 34994,
                    # "units": "KiloBytes"
                # },
                # "loops": "0"
            # },

            # "smtpServer": {
                # "totalIncomingConnections": "28083",
                # "lostConnections": "718",
                # "rejectedByBlacklist": "0",
                # "authenticationAttempts": "30",
                # "authenticationFailures": "27",
                # "rejectedRelays": "0",
                # "acceptedMessages": "26789"
            # },

            # "smtpClient": {
                # "connectionAttempts": "1048",
                # "dnsFailures": "0",
                # "connectionFailures": "56",
                # "connectionLosses": "10"
            # },

            # "pop3Server": {
                # "totalIncomingConnections": "0",
                # "authenticationFailures": "0",
                # "sentMessages": "0"
            # },

            # "pop3Client": {
                # "connectionAttempts": "5752784",
                # "connectionFailures": "0",
                # "authenticationFailures": "1383",
                # "totalDownloads": "19707"
            # },

            # "imapServer": {
                # "totalIncomingConnections": "3",
                # "authenticationFailures": "1"
            # },
            # "ldapServer": {
                # "totalIncomingConnections": "6",
                # "authenticationFailures": "0",
                # "totalSearchRequests": "96"
            # },

            # "webServer": {
                # "totalIncomingConnections": "2440141"
            # },

            # "xmppServer": {
                # "totalIncomingConnections": "0",
                # "authenticationFailures": "0"
            # },

            # "dnsResolver": {
                # "hostnameQueries": "5753836",
                # "cachedHostnameQueries": "5555652",
                # "mxQueries": "0",
                # "cachedMxQueries": "0"
            # },

            # "antibombing": {
                # "rejectedConnections": "0",
                # "rejectedMessages": "0",
                # "rejectedHarvestAttacks": "0"
            # },

            # "greylisting": {
                # "messagesAccepted": "0",
                # "messagesDelayed": "0",
                # "messagesSkipped": "0"
            # }
        # }
    # }
# }