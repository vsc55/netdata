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
    'antivirus',
    'spam',
    'deliveryStatus',
    'antibombing',
    'dnsResolver',
    'smtpClient',
    'pop3Client',
    'serversTotalIncomingConnections',
    'serversAuthenticationFailures',
    'ldapServer',
    'smtpServer',
    'messages',
]

CHARTS = {
    'uptime': {
        'options': [None, 'Service uptime', 'minuts', 'Server Uptime', 'kerio_connect.uptime', 'line'],
        'lines': [
            ['uptime']
        ]
    },

    'storage': {
        'options': [None, 'Disc space', 'B', 'Storage', 'kerio_connect.storage', 'stacked'],
        'lines': [
            ['storage_avail', 'avail', 'absolute'],
            ['storage_used', 'used', 'absolute'],
        ]
    },

    'antivirus': {
        'options': [None, 'Virus', 'count', 'Antivirus', 'kerio_connect.antivirus', 'line'],
        'lines': [
            ['antivirus_checkedAttachments', 'Attachments'],
            ['antivirus_foundViruses', 'Viruses found'],
            ['antivirus_prohibitedTypes', 'Prohibited filename/MIME types found'],
        ]
    },

    'spam': {
        'options': [None, 'Messages Spam', 'count', 'Spam', 'kerio_connect.spam', 'line'],
        'lines': [
            # ['spam_checked', 'Msg Checked'],
            ['spam_tagged', 'Tagged'],
            ['spam_rejected', 'Rejected'],
            ['spam_markedAsSpam', 'User Mark'],
            ['spam_markedAsNotSpam', 'non-spam user mark'],
        ]
    },

    'deliveryStatus': {
        'options': [None, 'Notifications sent', 'count', 'Delivery notifications', 'kerio_connect.deliveryStatus', 'line'],
        'lines': [
            ['deliveryStatus_success', 'Success'],
            ['deliveryStatus_delay', 'Delay'],
            ['deliveryStatus_failure', 'Failure'],
        ]
    },

    'antibombing': {
        'options': [None, 'Number Total', 'count', 'Antibombing', 'kerio_connect.antibombing', 'line'],
        'lines': [
            ['antibombing_rejectedConnections', 'Connections rejected'],
            ['antibombing_rejectedMessages', 'Rejected Messages'],
            ['antibombing_rejectedHarvestAttacks', 'Harvest Attacks detected'],
        ]
    },

    'dnsResolver': {
        'options': [None, 'Number Total', 'Record Queries', 'DNS Resolvers', 'kerio_connect.dnsResolver', 'line'],
        'lines': [
            ['dnsResolver_hostnameQueries', 'A (hostnames)'],
            ['dnsResolver_cachedHostnameQueries', 'A Cached'],
            ['dnsResolver_mxQueries', 'MX'],
            ['dnsResolver_cachedMxQueries', 'MX Cache'],
        ]
    },

    'smtpClient': {
        'options': [None, 'Number Total', 'Count', 'SMTP Client', 'kerio_connect.smtpClient', 'line'],
        'lines': [
            ['smtpClient_connectionAttempts', 'Connect attempts'],
            ['smtpClient_dnsFailures', 'DNS lookup failure'],
            ['smtpClient_connectionFailures', 'Connect failed'],
            ['smtpClient_connectionLosses', 'Connect lost'],
        ]
    },

    'pop3Client': {
        'options': [None, 'Number Total', 'Count', 'POP3 Client', 'kerio_connect.pop3Client', 'line'],
        'lines': [
            ['pop3Client_connectionAttempts', 'Connect attempts'],
            ['pop3Client_connectionFailures', 'Connect failed'],
            ['pop3Client_authenticationFailures', 'Authentication failure'],
            ['pop3Client_totalDownloads', 'Messeages downloaded'],
        ]
    },

    'serversTotalIncomingConnections': {
        'options': [None, 'Incoming Connections', 'connections', 'Incoming Connections', 'kerio_connect.serversTotalIncomingConnections', 'line'],
        'lines': [
            ['smtpServer_totalIncomingConnections', 'SMTP'],
            ['pop3Server_totalIncomingConnections', 'POP3'],
            ['imapServer_totalIncomingConnections', 'IMAP'],
            ['xmppServer_totalIncomingConnections', 'XMPP'],
            ['ldapServer_totalIncomingConnections', 'LDAP'],
            ['webServer_totalIncomingConnections', 'Web'],
        ]
    },

    'serversAuthenticationFailures': {
        'options': [None, 'Authentication Failures', 'count', 'Authentication Failures', 'kerio_connect.serversAuthenticationFailures', 'line'],
        'lines': [
            ['smtpServer_authenticationFailures', 'SMTP'],
            ['pop3Server_authenticationFailures', 'POP3'],
            ['imapServer_authenticationFailures', 'IMAP'],
            ['xmppServer_authenticationFailures', 'XMPP'],
            ['ldapServer_authenticationFailures', 'LDAP'],
        ]
    },

    'ldapServer': {
        'options': [None, 'Searchs', 'count', 'LDAP Server', 'kerio_connect.ldapServer', 'line'],
        'lines': [
            ['ldapServer_totalSearchRequests', 'Searchs'],
        ]
    },

    'smtpServer': {
        'options': [None, 'Connections', 'Connections', 'SMTP Server', 'kerio_connect.smtpServer', 'line'],
        'lines': [
            ['smtpServer_authenticationAttempts', 'Incomming'],
            ['smtpServer_lostConnections', 'Lost'],
            ['smtpServer_rejectedByBlacklist', 'Rejected by blacklist'],
            ['smtpServer_rejectedRelays', 'Relay attempts rejected by antispam'],   
        ]
    },

    'messages': {
        'options': [None, 'Messages', 'count', 'Messages', 'kerio_connect.messages', 'line'],
        'lines': [
            ['pop3Server_sentMessages', 'POP3 Sent'],
            ['smtpServer_acceptedMessages', 'SMTP Accepted'],
        ]
    },


               














}

class Service(UrlService):
    # API: https://manuals.gfi.com/en/kerio/api/connect/admin/reference/sample_communication.html#login

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
        self._enabled = self.configuration.get('enabled', True)
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

    def _conversor_units(self, value, unit):
        data_return = int(value)
        t_unit = str(unit)

        while t_unit:
            t_unit = t_unit.replace("Bytes", "")

            if t_unit == "Kilo":
                t_unit = "Bytes"

            if t_unit == "Mega":
                t_unit = "Kilo"
            
            if t_unit == "Giga":
                t_unit = "Mega"
            
            if t_unit == "Tera":
                t_unit = "Giga"

            if t_unit:
                data_return = data_return * 1024

        return data_return


    def check(self):
        if not self._enabled:
            self.debug("Job is disabled")
            return None

        return super().check()


    def _get_data(self):
        data_return = dict()
        if self._login():
            datos = self._get_statistics()
            # print(datos)

            storage_total_fix_unit  = self._conversor_units( int(datos['storage']['total']['value']), str(datos['storage']['total']['units']) )
            storage_used_fix_unit   = self._conversor_units( int(datos['storage']['occupied']['value']), str(datos['storage']['occupied']['units']) )


            data_return = {

                # "start": 1555847378,
                #       INFO: Fecha y hora en formato UNIX del inicio de las estadisticas.
                'start': int( datos['start'] ),

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
                'storage_total' : storage_total_fix_unit,
                'storage_used' : storage_used_fix_unit,
                'storage_avail' : storage_total_fix_unit - storage_used_fix_unit,

                # "antivirus": {
                #     "checkedAttachments": "0",
                #     "foundViruses": "0",
                #     "prohibitedTypes": "0"
                # }
                'antivirus_checkedAttachments'  : int(datos['antivirus']['checkedAttachments']),
                'antivirus_foundViruses'        : int(datos['antivirus']['foundViruses']),
                'antivirus_prohibitedTypes'     : int(datos['antivirus']['prohibitedTypes']),

                # "spam": {
                #     "checked": "46942",
                #     "tagged": "17",
                #     "rejected": "0",
                #     "markedAsSpam": "1",
                #     "markedAsNotSpam": "2"
                # }
                'spam_checked'          : int(datos['spam']['checked']),
                'spam_tagged'           : int(datos['spam']['tagged']),
                'spam_rejected'         : int(datos['spam']['rejected']),
                'spam_markedAsSpam'     : int(datos['spam']['markedAsSpam']),
                'spam_markedAsNotSpam'  : int(datos['spam']['markedAsNotSpam']),

                # "deliveryStatus": {
                #     "success": "1",
                #     "delay": "2",
                #     "failure": "4"
                # }
                'deliveryStatus_success'  : int(datos['deliveryStatus']['success']),
                'deliveryStatus_delay'    : int(datos['deliveryStatus']['delay']),
                'deliveryStatus_failure'  : int(datos['deliveryStatus']['failure']),

                # "antibombing": {
                #     "rejectedConnections": "0",
                #     "rejectedMessages": "0",
                #     "rejectedHarvestAttacks": "0"
                # }
                'antibombing_rejectedConnections'    : int(datos['antibombing']['rejectedConnections']),
                'antibombing_rejectedMessages'       : int(datos['antibombing']['rejectedMessages']),
                'antibombing_rejectedHarvestAttacks' : int(datos['antibombing']['rejectedHarvestAttacks']),

                # "dnsResolver": {
                #     "hostnameQueries": "5753836",
                #     "cachedHostnameQueries": "5555652",
                #     "mxQueries": "0",
                #     "cachedMxQueries": "0"
                # }
                'dnsResolver_hostnameQueries'       : int(datos['dnsResolver']['hostnameQueries']),
                'dnsResolver_cachedHostnameQueries' : int(datos['dnsResolver']['cachedHostnameQueries']),
                'dnsResolver_mxQueries'             : int(datos['dnsResolver']['mxQueries']),
                'dnsResolver_cachedMxQueries'       : int(datos['dnsResolver']['cachedMxQueries']),
                
                # "smtpClient": {
                #     "connectionAttempts": "1048",
                #     "dnsFailures": "0",
                #     "connectionFailures": "56",
                #     "connectionLosses": "10"
                # }
                'smtpClient_connectionAttempts' : int(datos['smtpClient']['connectionAttempts']),
                'smtpClient_dnsFailures'        : int(datos['smtpClient']['dnsFailures']),
                'smtpClient_connectionFailures' : int(datos['smtpClient']['connectionFailures']),
                'smtpClient_connectionLosses'   : int(datos['smtpClient']['connectionLosses']),

                #  "pop3Client": {
                #     "connectionAttempts": "5752784",
                #     "connectionFailures": "0",
                #     "authenticationFailures": "1383",
                #     "totalDownloads": "19707"
                # }
                'pop3Client_connectionAttempts'     : int(datos['pop3Client']['connectionAttempts']),
                'pop3Client_connectionFailures'     : int(datos['pop3Client']['connectionFailures']),
                'pop3Client_authenticationFailures' : int(datos['pop3Client']['authenticationFailures']),
                'pop3Client_totalDownloads'         : int(datos['pop3Client']['totalDownloads']),

                # "smtpServer": {
                #     "totalIncomingConnections": "28083",
                #     "lostConnections": "718",
                #     "rejectedByBlacklist": "0",
                #     "authenticationAttempts": "30",
                #     "authenticationFailures": "27",
                #     "rejectedRelays": "0",
                #     "acceptedMessages": "26789"
                # }
                'smtpServer_totalIncomingConnections' : int(datos['smtpServer']['totalIncomingConnections']),
                'smtpServer_lostConnections'          : int(datos['smtpServer']['lostConnections']),
                'smtpServer_rejectedByBlacklist'      : int(datos['smtpServer']['rejectedByBlacklist']),
                'smtpServer_authenticationAttempts'   : int(datos['smtpServer']['authenticationAttempts']),
                'smtpServer_authenticationFailures'   : int(datos['smtpServer']['authenticationFailures']),
                'smtpServer_rejectedRelays'           : int(datos['smtpServer']['rejectedRelays']),
                'smtpServer_acceptedMessages'         : int(datos['smtpServer']['acceptedMessages']),

                # "pop3Server": {
                #     "totalIncomingConnections": "0",
                #     "authenticationFailures": "0",
                #     "sentMessages": "0"
                # }
                'pop3Server_totalIncomingConnections' : int(datos['pop3Server']['totalIncomingConnections']),
                'pop3Server_authenticationFailures'   : int(datos['pop3Server']['authenticationFailures']),
                'pop3Server_sentMessages'             : int(datos['pop3Server']['sentMessages']),

                # "imapServer": {
                #     "totalIncomingConnections": "3",
                #     "authenticationFailures": "1"
                # }
                'imapServer_totalIncomingConnections' : int(datos['imapServer']['totalIncomingConnections']),
                'imapServer_authenticationFailures'   : int(datos['imapServer']['authenticationFailures']),

                # "ldapServer": {
                #     "totalIncomingConnections": "6",
                #     "authenticationFailures": "0",
                #     "totalSearchRequests": "96"
                # }
                'ldapServer_totalIncomingConnections' : int(datos['ldapServer']['totalIncomingConnections']),
                'ldapServer_authenticationFailures'   : int(datos['ldapServer']['authenticationFailures']),
                'ldapServer_totalSearchRequests'      : int(datos['ldapServer']['totalSearchRequests']),

                # "webServer": {
                #     "totalIncomingConnections": "2440141"
                # }
                'webServer_totalIncomingConnections' : int(datos['webServer']['totalIncomingConnections']),

                # "xmppServer": {
                #     "totalIncomingConnections": "0",
                #     "authenticationFailures": "0"
                # }
                'xmppServer_totalIncomingConnections' : int(datos['xmppServer']['totalIncomingConnections']),
                'xmppServer_authenticationFailures'   : int(datos['xmppServer']['authenticationFailures']),

                # "received": {
                #     "count": "47350",
                #     "volume": {
                #         "value": 2986,
                #         "units": "MegaBytes"
                #     },
                #     "recipients": "49460"
                # },
                #TODO: Controlar las unidades
                'received_count'      : int(datos['received']['count']),
                'received_recipients' : int(datos['received']['recipients']),
                'received_volume'     : int(datos['received']['volume']['value']),
                                
                # "storedInQueue": {
                #     "count": "0",
                #     "volume": {
                #         "value": 0,
                #         "units": "Bytes"
                #     },
                #     "recipients": "0"
                # },
                #TODO: Controlar las unidades
                'storedInQueue_count'      : int(datos['storedInQueue']['count']),
                'storedInQueue_recipients' : int(datos['storedInQueue']['recipients']),
                'storedInQueue_volume'     : int(datos['storedInQueue']['volume']['value']),

                # "transmitted": {
                #     "count": "48941",
                #     "volume": {
                #         "value": 3087,
                #         "units": "MegaBytes"
                #     },
                #     "recipients": "48941"
                # },
                #TODO: Controlar las unidades
                'transmitted_count'      : int(datos['transmitted']['count']),
                'transmitted_recipients' : int(datos['transmitted']['recipients']),
                'transmitted_volume'     : int(datos['transmitted']['volume']['value']),

                # "deliveredToLocals": {
                #     "count": "47967",
                #     "volume": {
                #         "value": 2632,
                #         "units": "MegaBytes"
                #     },
                #     "recipients": "47967"
                # },
                #TODO: Controlar las unidades
                'deliveredToLocals_count'      : int(datos['deliveredToLocals']['count']),
                'deliveredToLocals_recipients' : int(datos['deliveredToLocals']['recipients']),
                'deliveredToLocals_volume'     : int(datos['deliveredToLocals']['volume']['value']),

                # "mx": {
                #     "count": "0",
                #     "volume": {
                #         "value": 0,
                #         "units": "Bytes"
                #     },
                #     "recipients": "0"
                # },
                #TODO: Controlar las unidades
                'mx_count'      : int(datos['mx']['count']),
                'mx_recipients' : int(datos['mx']['recipients']),
                'mx_volume'     : int(datos['mx']['volume']['value']),


                # "relay": {
                #     "count": "974",
                #     "volume": {
                #         "value": 465322,
                #         "units": "KiloBytes"
                #     },
                #     "recipients": "974"
                # },
                #TODO: Controlar las unidades
                'relay_count'      : int(datos['relay']['count']),
                'relay_recipients' : int(datos['relay']['recipients']),
                'relay_volume'     : int(datos['relay']['volume']['value']),














            }
            # print(data_return)
            # data_return = dict()
            self._logout()

        return data_return
        
    
            







# "failures": {
#     "transientFailures": "93",
#     "permanentFailures": "4"
# },


# "other": {
#     "largest": {
#         "value": 34994,
#         "units": "KiloBytes"
#     },
#     "loops": "0"
# },

# "greylisting": {
#     "messagesAccepted": "0",
#     "messagesDelayed": "0",
#     "messagesSkipped": "0"
# }
   