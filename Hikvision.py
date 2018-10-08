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
    listenthread: threading.Thread

    @staticmethod
    def get_discover_xml():
        # 标准XML声明
        standard = '<?xml version="1.0" encoding="utf-8"?>'
        # 创建XML根节点Probe
        dom_impl = minidom.getDOMImplementation()
        send_document = dom_impl.createDocument(None, 'Probe', None)
        send_root = send_document.documentElement
        # 创建子结点Uuid
        uuid_e = send_document.createElement('Uuid')
        uuid_t = send_document.createTextNode(str(uuid.uuid1()).upper())
        uuid_e.appendChild(uuid_t)
        send_root.appendChild(uuid_e)
        # 创建子结点Types
        types_e = send_document.createElement('Types')
        types_t = send_document.createTextNode('inquiry')
        types_e.appendChild(types_t)
        send_root.appendChild(types_e)
        # 合成标准XML字符串
        result = standard + send_root.toxml()
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
        # 创建监听线程
        self.listenthread = threading.Thread(target=self.listen(), name='ListenThread')
        # 设置为后台线程
        self.listenthread.setDaemon(True)
        # 启动监听线程
        self.listenthread.start()
        for i in range(repeats):
            # verbose参数控制是否显示发送回显
            send(pkg, 1, verbose=1)

    def listen(self):
        # 创建ThreadingUDPServer对象，也就是多线程UDP服务器
        server = socketserver.ThreadingUDPServer(('', self.port), UDPScanHandler(delegate=self))
        # UDP服务器开始服务
        server.serve_forever()

    def report(self):
        # 读取结果时，首先阻塞线程，再进行读取
        self.listenthread.join(15)
        if self.flag is True:
            return ''
        else:
            return 'Still running'


class UDPScanHandler(socketserver.BaseRequestHandler):
    delegate: HikvisionUDPScanner

    def __init__(self, delegate):
        self.delegate = delegate

    # 服务代码，由ThreadingUDPServer自动进行多线程托管
    def handle(self):
        data = self.request[0].strip()
        print(data)
        self.delegate.parser(data)

    # 解析XML文本
    @staticmethod
    def parser(data):
        assert isinstance(data, str)
        recv_xml = minidom.parseString(data)
        recv_document = recv_xml.documentElement
        if recv_document.hasAttribute('Probe'):
            return recv_document.getAttribute('Probe')
        else:
            return 'error'


# HTTP 80端口扫描：判断HTTP响应的Server字段
class HikvisionHTTPScanner(AbstractScanner):
    dport: int = 0
    header_server: str = ''
    use_ssl: bool = 0
    flag: bool = 0

    def __init__(self, dst_ip, dport, use_ssl=False):
        assert isinstance(dport, int)
        assert isinstance(use_ssl, bool)
        AbstractScanner.__init__(self, dst_ip)
        self.dport = dport
        self.use_ssl = use_ssl

    def start(self, repeats):
        assert isinstance(repeats, int)
        self.flag = 0
        if repeats <= 0:
            return
        for i in range(repeats):
            try:
                if self.dport == 80 and self.use_ssl is False:
                    response = requests.get(url='http://' + self.dstIP)
                elif self.dport == 443 and self.use_ssl is True:
                    response = requests.get(url='https://' + self.dstIP)
                elif self.use_ssl is False:
                    response = requests.get(url='http://' + self.dstIP + ':' + self.dport)
                elif self.use_ssl is True:
                    response = requests.get(url='https://' + self.dstIP + ':' + self.dport)
            except requests.exceptions.ConnectionError as e:
                print('The target server seems down, details:')
                print(e)
            else:
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
