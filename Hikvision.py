# 海康威视IP摄像机扫描类
# 1. 官方SDAP扫描方式：发送组播UDP报文
# 	目的地址：239.255.255.250（组播地址）
# 	目的端口：37020
#   运输层协议：UDP
# 	构造XML作为UDP负载，具体形式通过对官方SDAP工具进行流量分析得到
# 	在本机任一端口（最好是37020）监听回复包，解析UDP负载中的XML内容
# 2. HTTP 80端口扫描：判断HTTP响应的Server字段
import uuid
import socketserver
import requests
from scapy.all import *
from xml.dom import minidom
from AbstractScanner import *


# 官方SDAP扫描方式：发送组播UDP报文
class HikvisionUDPScanner(AbstractScanner):
    port: int = 37020
    flag: bool = 0

    @staticmethod
    def get_discover_xml():
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
        xml_str = self.get_discover_xml()
        pkg = IP() / UDP() / xml_str
        # 目的地址为组播地址
        pkg.dst = self.dstIP
        # 源端口37020
        pkg.sport = self.port
        # 目的端口37020
        pkg.dport = self.port
        return pkg

    def start(self, repeats):
        assert isinstance(repeats, int)
        if repeats <= 0:
            print('Warning: The value of repeats is above zero, skipped.')
            return
        # 获得发现数据包
        pkg = self.get_discover_pkg()
        # 显示数据包并确定校验和
        pkg.show2()
        # 开始监听接收
        self.listen()
        for i in range(repeats):
            # verbose参数控制是否显示发送回显
            send(pkg, 1, verbose=1)

    def listen(self):
        # 创建socketserver对象，使用多线程UDP服务器
        server = socketserver.ThreadingUDPServer(('', self.port), self.UDPScanHandler)
        server.serve_forever()
        server.server_close()

    class UDPScanHandler(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                data = self.request.recv(4096).strip()
                print(self.request + ' ' + data)

    def report(self):
        if self.flag is True:
            return ''
        else:
            return 'Still running'


# HTTP 80端口扫描：判断HTTP响应的Server字段
class HikvisionHTTPScanner(AbstractScanner):
    dport: int = 0
    header_server: str = ''
    use_ssl: bool = 0
    flag: bool = 0

    def __init__(self, dst_ip, dport, use_ssl=False):
        assert isinstance(dst_ip, str)
        assert isinstance(dport, int)
        assert isinstance(use_ssl, bool)
        super.__init__(dst_ip=dst_ip)
        self.dport = dport
        self.use_ssl = use_ssl

    def start(self, repeats):
        assert isinstance(repeats, int)
        self.flag = 0
        if repeats <= 0:
            return
        for i in range(repeats):
            if self.dport == 80 and self.use_ssl is False:
                response = requests.get(url='http://' + self.dstIP)
            elif self.dport == 443 and self.use_ssl is True:
                response = requests.get(url='https://' + self.dstIP)
            elif self.use_ssl is False:
                response = requests.get(url='http://' + self.dstIP + ':' + self.dport)
            elif self.use_ssl is True:
                response = requests.get(url='https://' + self.dstIP + ':' + self.dport)

            if response.status_code == 200:
                self.header_server = response.headers.get('Server')
            else:
                print('Receive HTTP Status ' + response.status_code)

        self.flag = 1

    def report(self):
        if self.flag is True:
            if self.header_server == '':
                return 'Destination: ' + self.dstIP + ' Type: ' + self.header_server
            else:
                return 'Not found'
        else:
            return 'Still running'
