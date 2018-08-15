# 海康威视IP摄像机扫描类
# 1. 官方SDAP扫描方式：发送组播UDP报文
# 	目的地址：239.255.255.250
# 	目的端口37020
# 	构造XML作为UDP负载，具体形式由官方SDAP工具逆向得到
# 	在本机37020端口监听回复包，解析UDP负载中的XML内容
# 2. HTTP80端口扫描：判断HTTP响应的Server字段

import uuid
from scapy.all import *
from xml.dom import minidom
from AbstractScanner import *


# 扫描方式1
class HikvisionUDPScanner(AbstractScanner):

    def _get_discover_xml(self):
        # 标准XML声明
        standard = '<?xml version="1.0" encoding="utf-8"?>'
        # 创建XML根节点Probe
        impl = minidom.getDOMImplementation()
        dom = impl.createDocument(None, 'Probe', None)
        root = dom.documentElement
        # 创建子结点Uuid
        uuid_e = dom.createElement('Uuid')
        uuid_t = dom.createTextNode(str(uuid.uuid1()).upper())
        uuid_e.appendChild(uuid_t)
        root.appendChild(uuid_e)
        # 创建子结点Types
        types_e = dom.createElement('Types')
        types_t = dom.createTextNode('inquiry')
        types_e.appendChild(types_t)
        root.appendChild(types_e)
        # 合成标准XML字符串
        result = standard + root.toxml()
        return result

    def get_discover_pkg(self):
        # 封装UDP报文
        xml_str = self._get_discover_xml()
        pkg = IP() / UDP() / xml_str
        # 目的地址为组播地址
        pkg.dst = '239.255.255.250'
        # 源端口37020
        pkg.sport = 37020
        # 目的端口37020
        pkg.dport = 37020
        return pkg

    def send(self, pkg, time):
        if time <= 0:
            return
        for i in range(time):
            # verbose参数控制是否显示发送回显
            send(pkg, 1, verbose=1)


# 扫描方式2
class HikvisionHTTPScanner(AbstractScanner):

    def get_discover_pkg(self):
        pkg = IP() / TCP() / HTTP()
        pkg.dst = '1.1.1.1'
        pkg.dport = 80

    def send(self, pkg, time):
        for i in range(time):
            # verbose参数控制是否显示发送回显
            send(pkg, 1, verbose=1)
