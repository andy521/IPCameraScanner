# 海康威视IP摄像机扫描类
# 1. 官方SDAP扫描方式：发送组播UDP报文
# 	目的地址：239.255.255.250
# 	目的端口37020
# 	构造XML作为UDP负载，具体形式由官方SDAP工具逆向得到
# 	在本机37020端口监听回复包，解析UDP负载中的XML内容
# 2. HTTP80端口扫描：判断HTTP响应的Server字段

import uuid
from scapy.all import *
from socket import *
from xml.dom import minidom
from AbstractScanner import *


# 扫描方式1
class HikvisionUDPScanner(AbstractScanner):

    def getDiscoverXml(self):
        # 标准XML声明
        standard = '<?xml version="1.0" encoding="utf-8"?>'
        # 创建XML根节点Probe
        impl = minidom.getDOMImplementation()
        dom = impl.createDocument(None, 'Probe', None)
        root = dom.documentElement
        # 创建子结点Uuid
        uuidE = dom.createElement('Uuid')
        uuidT = dom.createTextNode(str(uuid.uuid1()).upper())
        uuidE.appendChild(uuidT)
        root.appendChild(uuidE)
        # 创建子结点Types
        typesE = dom.createElement('Types')
        typesT = dom.createTextNode('inquiry')
        typesE.appendChild(typesT)
        root.appendChild(typesE)
        # 合成标准XML字符串
        discoverXmlString = standard + root.toxml()
        return discoverXmlString

    def getDiscoverPackage(self):
        # 封装UDP报文
        discoverXmlString = self.getDiscoverXml()
        pkg = IP() / UDP() / discoverXmlString
        # 目的地址为组播地址
        pkg.dst = '239.255.255.250'
        # 源端口37020
        pkg.sport = 37020
        # 目的端口37020
        pkg.dport = 37020
        return pkg

    def sendPackage(self, pkg, time):
        for i in range(time):
            # verbose参数控制是否显示发送回显
            send(pkg, 1, verbose=1)

    def bindUDPPort(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 37020))


# 扫描方式2
class HikvisionHTTPScanner(AbstractScanner):
    def getDiscoverPackage(self):
        pkg = IP() / TCP() / HTTP()
		pkg.dst = '1.1.1.1'
		pkg.dport = 80

    def sendPackage(self, pkg, time):
        for i in range(time):
            # verbose参数控制是否显示发送回显
            send(pkg, 1, verbose=1)
