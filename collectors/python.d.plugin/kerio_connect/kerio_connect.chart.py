# -*- coding: utf-8 -*-
# Description: kerio connect netdata python.d module
# Author: vsc55 (vsc55@cerebelum.net)
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from requests import session
from bases.FrameworkServices.UrlService import UrlService

KERIO_CONNECT_STATISTICS = [
    'start',
    'uptime.days',
    'uptime.hours',
    'uptime.minutes',
    'antivirus.checkedAttachments',
    'antivirus.foundViruses',
    'antivirus.prohibitedTypes',
    'spam.checked',
    'spam.tagged',
    'spam.rejected',
    'spam.markedAsSpam',
    'spam.markedAsNotSpam',
    'deliveryStatus.success',
    'deliveryStatus.delay',
    'deliveryStatus.failure',
    'antibombing.rejectedConnections',
    'antibombing.rejectedMessages',
    'antibombing.rejectedHarvestAttacks',            
    'dnsResolver.hostnameQueries',
    'dnsResolver.cachedHostnameQueries',
    'dnsResolver.mxQueries',
    'dnsResolver.cachedMxQueries',
    'smtpClient.connectionAttempts',
    'smtpClient.dnsFailures',
    'smtpClient.connectionFailures',
    'smtpClient.connectionLosses',
    'pop3Client.connectionAttempts',
    'pop3Client.connectionFailures',
    'pop3Client.authenticationFailures',
    'pop3Client.totalDownloads',
    'smtpServer.totalIncomingConnections',
    'smtpServer.lostConnections',
    'smtpServer.rejectedByBlacklist',
    'smtpServer.authenticationAttempts',
    'smtpServer.authenticationFailures',
    'smtpServer.rejectedRelays',
    'smtpServer.acceptedMessages',
    'pop3Server.totalIncomingConnections',
    'pop3Server.authenticationFailures',
    'pop3Server.sentMessages',
    'imapServer.totalIncomingConnections',
    'imapServer.authenticationFailures',
    'ldapServer.totalIncomingConnections',
    'ldapServer.authenticationFailures',
    'ldapServer.totalSearchRequests',
    'webServer.totalIncomingConnections',
    'xmppServer.totalIncomingConnections',
    'xmppServer.authenticationFailures',
    'failures.transientFailures',
    'failures.permanentFailures',
    'greylisting.messagesAccepted',
    'greylisting.messagesDelayed',
    'greylisting.messagesSkipped',
    
    'other.loops',
    # 'other.largest.value',
    # 'other.largest.units',

    'storage.percentage',
    # 'storage.total.value',
    # 'storage.total.units',
    # 'storage.occupied.value',
    # 'storage.occupied.units',

    'received.count',
    'received.recipients',
    # 'received.volume.value',
    # 'received.volume.units',
    
    'storedInQueue.count',
    'storedInQueue.recipients',
    # 'storedInQueue.volume.value',
    # 'storedInQueue.volume.units',
 
    'transmitted.count',
    'transmitted.recipients',
    # 'transmitted.volume.value',
    # 'transmitted.volume.units',
    
    'deliveredToLocals.count',
    'deliveredToLocals.recipients',
    # 'deliveredToLocals.volume.value',
    # 'deliveredToLocals.volume.units',

    'mx.count',
    'mx.recipients',
    # 'mx.volume.value',
    # 'mx.volume.units',

    'relay.count',
    'relay.recipients',
    # 'relay.volume.value',
    # 'relay.volume.units',
]

VOLUME_STATISTICS = [
    'received.volume',
    'storedInQueue.volume',
    'transmitted.volume',
    'deliveredToLocals.volume',
    'mx.volume',
    'relay.volume',
    'other.largest',
]

ORDER = [
    'uptime',
    'storage',
    'antivirus',
    'spam',
    'greylisting',
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
    'other_largest',
]

CHARTS = {
    'uptime': {
        'options': [None, 'Service Uptime', 'minuts', 'Server Uptime', 'kerio_connect.uptime', 'line'],
        'lines': [
            ['uptime_all', 'uptime', 'absolute']
        ]
    },

    'storage': {
        'options': [None, 'Disk Space Usage', 'B', 'Storage', 'kerio_connect.storage', 'stacked'],
        'lines': [
            ['storage_avail', 'avail', 'absolute'],
            ['storage_occupied', 'used', 'absolute'],
        ]
    },

    'antivirus': {
        'options': [None, 'Virus', 'count', 'Antivirus', 'kerio_connect.antivirus', 'line'],
        'lines': [
            ['antivirus_checkedAttachments', 'Attachments', 'incremental'],
            ['antivirus_foundViruses', 'Viruses found', 'incremental'],
            ['antivirus_prohibitedTypes', 'Prohibited filename/MIME types found', 'incremental'],
        ]
    },

    'spam': {
        'options': [None, 'Messages Spam', 'count', 'Spam', 'kerio_connect.spam', 'line'],
        'lines': [
            ['spam_checked', 'Msg Checked', 'incremental'],
            ['spam_tagged', 'Tagged', 'incremental'],
            ['spam_rejected', 'Rejected', 'incremental'],
            ['spam_markedAsSpam', 'Spam Marked', 'incremental'],
            ['spam_markedAsNotSpam', 'non-spam Marked', 'incremental'],
        ]
    },

    'greylisting': {
        'options': [None, 'Messages', 'count', 'Greylisting Messages', 'kerio_connect.greylisting', 'line'],
        'lines': [
            ['greylisting_messagesAccepted', 'Accepted', 'incremental'],
            ['greylisting_messagesDelayed', 'Delayed', 'incremental'],
            ['greylisting_messagesSkipped', 'Skipped', 'incremental'],
        ]
    },

    'deliveryStatus': {
        'options': [None, 'Notifications sent', 'count', 'Delivery notifications', 'kerio_connect.deliveryStatus', 'line'],
        'lines': [
            ['deliveryStatus_success', 'Success', 'incremental'],
            ['deliveryStatus_delay', 'Delay', 'incremental'],
            ['deliveryStatus_failure', 'Failure', 'incremental'],
        ]
    },

    'antibombing': {
        'options': [None, 'Number Total', 'count', 'Antibombing', 'kerio_connect.antibombing', 'line'],
        'lines': [
            ['antibombing_rejectedConnections', 'Connections rejected', 'incremental'],
            ['antibombing_rejectedMessages', 'Rejected Messages', 'incremental'],
            ['antibombing_rejectedHarvestAttacks', 'Harvest Attacks detected', 'incremental'],
        ]
    },

    'dnsResolver': {
        'options': [None, 'Number Total', 'Record Queries', 'DNS Resolvers', 'kerio_connect.dnsResolver', 'line'],
        'lines': [
            ['dnsResolver_hostnameQueries', 'A (hostnames)', 'incremental'],
            ['dnsResolver_cachedHostnameQueries', 'A Cached', 'incremental'],
            ['dnsResolver_mxQueries', 'MX', 'incremental'],
            ['dnsResolver_cachedMxQueries', 'MX Cache', 'incremental'],
        ]
    },

    'smtpClient': {
        'options': [None, 'Number Total', 'Count', 'SMTP Client', 'kerio_connect.smtpClient', 'line'],
        'lines': [
            ['smtpClient_connectionAttempts', 'Connect attempts', 'incremental'],
            ['smtpClient_dnsFailures', 'DNS lookup failure', 'incremental'],
            ['smtpClient_connectionFailures', 'Connect failed', 'incremental'],
            ['smtpClient_connectionLosses', 'Connect lost', 'incremental'],
        ]
    },

    'pop3Client': {
        'options': [None, 'Number Total', 'Count', 'POP3 Client', 'kerio_connect.pop3Client', 'line'],
        'lines': [
            ['pop3Client_connectionAttempts', 'Connect attempts', 'incremental'],
            ['pop3Client_connectionFailures', 'Connect failed', 'incremental'],
            ['pop3Client_authenticationFailures', 'Authentication failure', 'incremental'],
            ['pop3Client_totalDownloads', 'Messeages downloaded', 'incremental'],
        ]
    },

    'serversTotalIncomingConnections': {
        'options': [None, 'Incoming Connections', 'connections', 'Incoming Connections', 'kerio_connect.serversTotalIncomingConnections', 'line'],
        'lines': [
            ['smtpServer_totalIncomingConnections', 'SMTP', 'incremental'],
            ['pop3Server_totalIncomingConnections', 'POP3', 'incremental'],
            ['imapServer_totalIncomingConnections', 'IMAP', 'incremental'],
            ['xmppServer_totalIncomingConnections', 'XMPP', 'incremental'],
            ['ldapServer_totalIncomingConnections', 'LDAP', 'incremental'],
            ['webServer_totalIncomingConnections', 'Web', 'incremental'],
        ]
    },

    'serversAuthenticationFailures': {
        'options': [None, 'Authentication Failures', 'count', 'Authentication Failures', 'kerio_connect.serversAuthenticationFailures', 'line'],
        'lines': [
            ['smtpServer_authenticationFailures', 'SMTP', 'incremental'],
            ['pop3Server_authenticationFailures', 'POP3', 'incremental'],
            ['imapServer_authenticationFailures', 'IMAP', 'incremental'],
            ['xmppServer_authenticationFailures', 'XMPP', 'incremental'],
            ['ldapServer_authenticationFailures', 'LDAP', 'incremental'],
        ]
    },

    'ldapServer': {
        'options': [None, 'Searchs', 'count', 'LDAP Server', 'kerio_connect.ldapServer', 'line'],
        'lines': [
            ['ldapServer_totalSearchRequests', 'Searchs', 'incremental'],
        ]
    },

    'smtpServer': {
        'options': [None, 'Connections', 'Connections', 'SMTP Server', 'kerio_connect.smtpServer', 'line'],
        'lines': [
            ['smtpServer_authenticationAttempts', 'Incomming', 'incremental'],
            ['smtpServer_lostConnections', 'Lost', 'incremental'],
            ['smtpServer_rejectedByBlacklist', 'Rejected by blacklist', 'incremental'],
            ['smtpServer_rejectedRelays', 'Relay attempts rejected by antispam', 'incremental'],
        ]
    },

    'messages': {
        'options': [None, 'Messages', 'count', 'Messages', 'kerio_connect.messages', 'line'],
        'lines': [
            ['pop3Server_sentMessages', 'POP3 Sent', 'incremental'],
            ['smtpServer_acceptedMessages', 'SMTP Accepted', 'incremental'],
        ]
    },

    'other_largest': {
        'options': [None, 'Largest message size received', 'B', 'Others/Message Size', 'kerio_connect.other_largest', 'line'],
        'lines': [
            ['other.largest', 'Size', 'absolute'],
        ]
    },


# 'storedInQueue.volume',
# 'transmitted.volume',
# 'deliveredToLocals.volume',
# 'mx.volume',
# 'relay.volume',

# # "received": {
# #     "count": "47350",
# #     "volume": {
# #         "value": 2986,
# #         "units": "MegaBytes"
# #     },
# #     "recipients": "49460"
# # },
# # "storedInQueue": {
# #     "count": "0",
# #     "volume": {
# #         "value": 0,
# #         "units": "Bytes"
# #     },
# #     "recipients": "0"
# # },

# # "transmitted": {
# #     "count": "48941",
# #     "volume": {
# #         "value": 3087,
# #         "units": "MegaBytes"
# #     },
# #     "recipients": "48941"
# # },

# # "deliveredToLocals": {
# #     "count": "47967",
# #     "volume": {
# #         "value": 2632,
# #         "units": "MegaBytes"
# #     },
# #     "recipients": "47967"
# # },

# # "mx": {
# #     "count": "0",
# #     "volume": {
# #         "value": 0,
# #         "units": "Bytes"
# #     },
# #     "recipients": "0"
# # },

# # "relay": {
# #     "count": "974",
# #     "volume": {
# #         "value": 465322,
# #         "units": "KiloBytes"
# #     },
# #     "recipients": "974"
# # },

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
            headers, raw = self._get_raw_data_with_headers()
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
            raw = self._get_raw_data()
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
            _, raw = self._get_raw_data_with_headers()
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

    def _conversor_units(self, size_in):
        value = int(size_in['value'])
        unit = str(size_in['units'])

        ls_units = {
            'Bytes'     : 0,
            'KiloBytes' : 1,
            'MegaBytes' : 2,
            'GigaBytes' : 3,
            'TeraBytes' : 4,
        }
        if unit and unit in ls_units:
            data_return = int(value) * (1024 ** ls_units[unit])
        else:
            data_return = -1

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

            data_return = fetch_data(raw_data=datos, metrics=KERIO_CONNECT_STATISTICS)
            data_return.update( fetch_data(raw_data=datos, metrics=VOLUME_STATISTICS, fun_process=self._conversor_units) )
            
            uptime_fix = {
                # "uptime": {
                #     "days": 2,
                #     "hours": 4,
                #     "minutes": 41
                # }
                'uptime_all': int( datos['uptime']['minutes'] + (datos['uptime']['hours'] * 60) + ( (datos['uptime']['days'] * 60) * 24 ) ),
            }
            data_return.update(uptime_fix)

            storage_fix_total    = self._conversor_units( datos['storage']['total'] )
            storage_fix_occupied = self._conversor_units( datos['storage']['occupied'] )
            storage_fix = {
                # "storage": {
                #     "total": {
                #         "value": 10717,
                #         "units": "GigaBytes"
                #     },
                #     "occupied": {
                #         "value": 9834,
                #         "units": "GigaBytes"
                #     },
                # }
                'storage_total' : storage_fix_total,
                'storage_occupied' : storage_fix_occupied,
                'storage_avail' : storage_fix_total - storage_fix_occupied,
            }
            data_return.update(storage_fix)

            # print(data_return)
            self._logout()

        return data_return


def fetch_data(raw_data, metrics, fun_process = None):
    data = dict()
    for metric in metrics:
        value = raw_data
        metrics_list = metric.split('.')
        try:
            for m in metrics_list:
                value = value[m]
        except (KeyError, TypeError):
            continue

        if fun_process:
            value = fun_process(value)
        data['_'.join(metrics_list)] = value
    return data





# # "start": 1555847378,
# # INFO: Fecha y hora en formato UNIX del inicio de las estadisticas.

# # "other": {
# #     "largest": {
# #         "value": 34994,
# #         "units": "KiloBytes"
# #     },
# #     "loops": "0"
# # }

# # "failures": {
# #     "transientFailures": "93",
# #     "permanentFailures": "4"
# # }

# # "greylisting": {
# #     "messagesAccepted": "0",
# #     "messagesDelayed": "0",
# #     "messagesSkipped": "0"
# # }

# # "uptime": {
# #     "days": 2,
# #     "hours": 4,
# #     "minutes": 41
# # }

# # "storage": {
# #     "total": {
# #         "value": 10717,
# #         "units": "GigaBytes"
# #     },
# #     "occupied": {
# #         "value": 9834,
# #         "units": "GigaBytes"
# #     },
# #     "percentage": "91"
# # }

# # "received": {
# #     "count": "47350",
# #     "volume": {
# #         "value": 2986,
# #         "units": "MegaBytes"
# #     },
# #     "recipients": "49460"
# # }
                
# # "storedInQueue": {
# #     "count": "0",
# #     "volume": {
# #         "value": 0,
# #         "units": "Bytes"
# #     },
# #     "recipients": "0"
# # }

# # "transmitted": {
# #     "count": "48941",
# #     "volume": {
# #         "value": 3087,
# #         "units": "MegaBytes"
# #     },
# #     "recipients": "48941"
# # }

# # "deliveredToLocals": {
# #     "count": "47967",
# #     "volume": {
# #         "value": 2632,
# #         "units": "MegaBytes"
# #     },
# #     "recipients": "47967"
# # }

# # "mx": {
# #     "count": "0",
# #     "volume": {
# #         "value": 0,
# #         "units": "Bytes"
# #     },
# #     "recipients": "0"
# # }

# # "relay": {
# #     "count": "974",
# #     "volume": {
# #         "value": 465322,
# #         "units": "KiloBytes"
# #     },
# #     "recipients": "974"
# # }

# # "antivirus": {
# #     "checkedAttachments": "0",
# #     "foundViruses": "0",
# #     "prohibitedTypes": "0"
# # }

# # "spam": {
# #     "checked": "46942",
# #     "tagged": "17",
# #     "rejected": "0",
# #     "markedAsSpam": "1",
# #     "markedAsNotSpam": "2"
# # }

# # "deliveryStatus": {
# #     "success": "1",
# #     "delay": "2",
# #     "failure": "4"
# # }

# # "antibombing": {
# #     "rejectedConnections": "0",
# #     "rejectedMessages": "0",
# #     "rejectedHarvestAttacks": "0"
# # }

# # "dnsResolver": {
# #     "hostnameQueries": "5753836",
# #     "cachedHostnameQueries": "5555652",
# #     "mxQueries": "0",
# #     "cachedMxQueries": "0"
# # }

# # "smtpClient": {
# #     "connectionAttempts": "1048",
# #     "dnsFailures": "0",
# #     "connectionFailures": "56",
# #     "connectionLosses": "10"
# # }

# #  "pop3Client": {
# #     "connectionAttempts": "5752784",
# #     "connectionFailures": "0",
# #     "authenticationFailures": "1383",
# #     "totalDownloads": "19707"
# # }

# # "smtpServer": {
# #     "totalIncomingConnections": "28083",
# #     "lostConnections": "718",
# #     "rejectedByBlacklist": "0",
# #     "authenticationAttempts": "30",
# #     "authenticationFailures": "27",
# #     "rejectedRelays": "0",
# #     "acceptedMessages": "26789"
# # }

# # "pop3Server": {
# #     "totalIncomingConnections": "0",
# #     "authenticationFailures": "0",
# #     "sentMessages": "0"
# # }

# # "imapServer": {
# #     "totalIncomingConnections": "3",
# #     "authenticationFailures": "1"
# # }

# # "ldapServer": {
# #     "totalIncomingConnections": "6",
# #     "authenticationFailures": "0",
# #     "totalSearchRequests": "96"
# # }

# # "webServer": {
# #     "totalIncomingConnections": "2440141"
# # }

# # "xmppServer": {
# #     "totalIncomingConnections": "0",
# #     "authenticationFailures": "0"
# # }