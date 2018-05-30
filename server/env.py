# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling environment configuration and defaults.'''


import re
import resource
from collections import namedtuple
from ipaddress import ip_address

from lib.coins import Coin
from lib.env_base import EnvBase
import lib.util as lib_util


NetIdentity = namedtuple('NetIdentity', 'host tcp_port ssl_port nick_suffix') #返回一个类（包含属性：tcp_port，host，ssl_port，nick_suffix）


class Env(EnvBase):
    '''Wraps environment configuration.'''

    # Peer discovery
    PD_OFF, PD_SELF, PD_ON = range(3)

    def __init__(self):
        super().__init__()
        self.obsolete(['UTXO_MB', 'HIST_MB', 'NETWORK']) #检查环境变量（？过时）
        self.db_dir = self.required('DB_DIRECTORY') #获取DB_DIRECTORY环境变量
        self.db_engine = self.default('DB_ENGINE', 'leveldb') #获取DB_DIRECTORY环境变量，如果‘DB_ENGINE’不存在就返回默认的‘leveldb’
        self.daemon_url = self.required('DAEMON_URL')
        coin_name = self.required('COIN').strip() #获取环境变量COIN，调用字符串方法strip去除首尾的空格
        network = self.default('NET', 'mainnet').strip()
        self.coin = Coin.lookup_coin_class(coin_name, network) #返回类似 -》 {'NAME':coin_name,'NET':network,'TX_COUNT':'','TX_COUNT_HEIGHT':'','TX_PER_BLOCK':'',REORG_LIMIT:''}
        self.cache_MB = self.integer('CACHE_MB', 1200) #获取CACHE_MB环境变量，如果‘CACHE_MB’不存在就返回默认的‘1200’[是一个整型]
        self.host = self.default('HOST', 'localhost')
        self.reorg_limit = self.integer('REORG_LIMIT', self.coin.REORG_LIMIT)
        # Server stuff
        self.tcp_port = self.integer('TCP_PORT', None)
        self.ssl_port = self.integer('SSL_PORT', None)
        if self.ssl_port:
            self.ssl_certfile = self.required('SSL_CERTFILE')
            self.ssl_keyfile = self.required('SSL_KEYFILE')
        self.rpc_port = self.integer('RPC_PORT', 8000)
        self.max_subscriptions = self.integer('MAX_SUBSCRIPTIONS', 10000)
        self.banner_file = self.default('BANNER_FILE', None)
        self.tor_banner_file = self.default('TOR_BANNER_FILE',
                                            self.banner_file)
        self.anon_logs = self.boolean('ANON_LOGS', False) #获取系统是否存在环境变量‘ANON_LOGS’【boolean】
        self.log_sessions = self.integer('LOG_SESSIONS', 3600) #获取系统是否存在环境变量‘ANON_LOGS’【boolean -> true】
        # Peer discovery
        self.peer_discovery = self.peer_discovery_enum() #返回环境变量PEER_DISCOVERY的状态，默认返回2
        self.peer_announce = self.boolean('PEER_ANNOUNCE', True)
        self.force_proxy = self.boolean('FORCE_PROXY', False)
        self.tor_proxy_host = self.default('TOR_PROXY_HOST', 'localhost')
        self.tor_proxy_port = self.integer('TOR_PROXY_PORT', None)
        # The electrum client takes the empty string as unspecified
        self.donation_address = self.default('DONATION_ADDRESS', '')
        # Server limits to help prevent DoS
        self.max_send = self.integer('MAX_SEND', 1000000)
        self.max_subs = self.integer('MAX_SUBS', 250000)
        self.max_sessions = self.sane_max_sessions() #返回获取环境变量MAX_SESSIONS的值，获取Python（库）配置文件中nofile_limit的值（-350）；返回二者最小值【或者0】。
        self.max_session_subs = self.integer('MAX_SESSION_SUBS', 50000)
        self.bandwidth_limit = self.integer('BANDWIDTH_LIMIT', 2000000)
        self.session_timeout = self.integer('SESSION_TIMEOUT', 600)
        self.drop_client = self.custom("DROP_CLIENT", None, re.compile) # 如果环境变量DROP_CLIENT不存在，就返回None，否则返回re.compile(os.environ.get('DROP_CLIENT'))[是一个正则]

        # Identities
        clearnet_identity = self.clearnet_identity()  #返回NetIdentity(host=host, tcp_port=tcp_port, ssl_port=ssl_port, nick_suffix='') -> 类
        tor_identity = self.tor_identity(clearnet_identity)  #返回NetIdentity(host=host, tcp_port=tcp_port, ssl_port=ssl_port, nick_suffix='_tor') -> 类
        self.identities = [identity
                           for identity in (clearnet_identity, tor_identity)
                           if identity is not None] #两个类(class1[clearnet_identity],class2[tor_identity])

    def sane_max_sessions(self): #返回获取环境变量MAX_SESSIONS的值，获取Python配置文件中nofile_limit的值（减去350）；返回二者最小值【或者0】。
        '''Return the maximum number of sessions to permit.  Normally this
        is MAX_SESSIONS.  However, to prevent open file exhaustion, ajdust
        downwards if running with a small open file rlimit.'''
        env_value = self.integer('MAX_SESSIONS', 1000)
        nofile_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        # We give the DB 250 files; allow ElectrumX 100 for itself
        value = max(0, min(env_value, nofile_limit - 350))
        if value < env_value:
            self.logger.warning('lowered maximum sessions from {:,d} to {:,d} '
                                'because your open file limit is {:,d}'
                                .format(env_value, value, nofile_limit))
        return value

    def clearnet_identity(self): #返回NetIdentity(host=host, tcp_port=None, ssl_port=None, nick_suffix='') -> 类
        host = self.default('REPORT_HOST', None) #环境变量REPORT_HOST的值
        if host is None:
            return None
        try:
            ip = ip_address(host) #IP地址进制间相互转换（点分十进制，十进制，十六进制，二进制，字节）
        except ValueError:
            bad = (not lib_util.is_valid_hostname(host)
                   or host.lower() == 'localhost')
        else:
            bad = (ip.is_multicast or ip.is_unspecified
                   or (ip.is_private and self.peer_announce))
        if bad:
            raise self.Error('"{}" is not a valid REPORT_HOST'.format(host))
        tcp_port = self.integer('REPORT_TCP_PORT', self.tcp_port) or None
        ssl_port = self.integer('REPORT_SSL_PORT', self.ssl_port) or None
        if tcp_port == ssl_port:
            raise self.Error('REPORT_TCP_PORT and REPORT_SSL_PORT '
                             'both resolve to {}'.format(tcp_port))
        return NetIdentity(
            host,
            tcp_port,
            ssl_port,
            ''
        )

    def tor_identity(self, clearnet):#返回NetIdentity(host=host, tcp_port=None, ssl_port=None, nick_suffix='_tor') -> 类
        host = self.default('REPORT_HOST_TOR', None)
        if host is None:
            return None
        if not host.endswith('.onion'):
            raise self.Error('tor host "{}" must end with ".onion"'
                             .format(host))

        def port(port_kind):
            '''Returns the clearnet identity port, if any and not zero,
            otherwise the listening port.'''
            result = 0
            if clearnet:
                result = getattr(clearnet, port_kind)
            return result or getattr(self, port_kind)

        tcp_port = self.integer('REPORT_TCP_PORT_TOR', port('tcp_port')) or None
        ssl_port = self.integer('REPORT_SSL_PORT_TOR', port('ssl_port')) or None
        if tcp_port == ssl_port:
            raise self.Error('REPORT_TCP_PORT_TOR and REPORT_SSL_PORT_TOR '
                             'both resolve to {}'.format(tcp_port))

        return NetIdentity(
            host,
            tcp_port,
            ssl_port,
            '_tor',
        )

    def hosts_dict(self): #返回host类的tcp_port和ssl_port
        return {identity.host: {'tcp_port': identity.tcp_port, #identity.host是一个ip
                                'ssl_port': identity.ssl_port}
                for identity in self.identities}

    def peer_discovery_enum(self): # 返回环境变量PEER_DISCOVERY的状态，默认返回2
        pd = self.default('PEER_DISCOVERY', 'on').strip().lower() # 环境变量PEER_DISCOVERY的value(去掉空格后的小写)[默认value = on]
        if pd in ('off', ''):
            return self.PD_OFF # return 0
        elif pd == 'self':
            return self.PD_SELF # return 1
        else:
            return self.PD_ON # return 2
