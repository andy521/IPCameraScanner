# 海康威视IP摄像机扫描类
# 1. 官方SDAP扫描方式：发送组播UDP报文
# 	目的地址：239.255.255.250（组播地址）
# 	目的端口：37020
#   运输层协议：UDP
# 	构造XML作为UDP负载，具体形式通过对官方SDAP工具进行流量分析得到
# 	在本机任一端口（最好是37020）监听回复包，解析UDP负载中的XML内容
# 2. HTTP 80端口扫描：判断HTTP响应的Server字段
import uuid
import requests
from scapy.all import *
from xml.dom import minidom
from AbstractScanner import *


# 官方SDAP扫描方式：发送组播UDP报文
class HikvisionUDPScanner(AbstractScanner):
    port: int = 37020
    result: list = []
    finish_flag: bool = False
    listen_thread: threading.Thread
    stop_sniff = threading.Event()

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

    def start(self):
        self.finish_flag = False
        # 获得发现数据包
        pkg = self.get_discover_pkg()
        # 显示数据包并确定校验和
        pkg.show2()
        # 创建监听线程
        self.listen_thread = threading.Thread(target=self.listen, name='Thread-Listen')
        # 设置为后台线程
        self.listen_thread.setDaemon(True)
        # 启动监听线程
        self.listen_thread.start()
        # verbose参数控制是否显示发送回显
        send(pkg, 1, verbose=0)
        self.finish_flag = True

    def listen(self):
        test = IP()
        local_ip = test.src
        sniff(prn=lambda x: self.handler(x),
              filter='Dst host '+local_ip+' and Udp port 37020',
              stop_filter=lambda x: self.stop_sniff.is_set())

    def handler(self, pkg):
        data = str(pkg.load, 'utf-8')
        try:
            dev_dict = HikvisionUDPScanner.parser(data)
            self.result.append(dev_dict)
        except TypeError as error:
            print(error)

    @staticmethod
    def parser(data) -> dict:
        assert isinstance(data, str)
        # 去除前面的XML描述符
        data = data[38:]
        print(data)
        recv_xml = minidom.parseString(data)
        recv_root = recv_xml.documentElement
        dev_dict = {}
        if recv_root.nodeName == 'ProbeMatch':
            recv_childnodes = recv_root.childNodes
            for childnode in recv_childnodes:
                dev_dict[childnode.nodeName] = childnode.childNodes[0].data
            return dev_dict
        else:
            raise TypeError('不是探测包的返回包，返回包的根结点名称必须是ProbeMatch')

    def report(self) -> (bool, list):
        if self.finish_flag is True:
            # 读取结果时，首先设置信号量，停止sniff函数抓取包
            self.stop_sniff.set()
            return True, self.result
        else:
            return False, []


# HTTP 80端口扫描：判断HTTP响应的Server字段
class HikvisionHTTPScanner(AbstractScanner):
    dport: int = 0
    result: list = []
    use_ssl: bool = 0
    finish_flag: bool = False

    def __init__(self, dst_ip, dport, use_ssl=False):
        assert isinstance(dport, int)
        assert isinstance(use_ssl, bool)
        AbstractScanner.__init__(self, dst_ip)
        self.dport = dport
        self.use_ssl = use_ssl

    def start(self):
        self.finish_flag = False
        try:
            if self.dport == 80 and self.use_ssl is False:
                response = requests.get(url='http://' + self.dstIP)
            elif self.dport == 443 and self.use_ssl is True:
                response = requests.get(url='https://' + self.dstIP)
            elif self.use_ssl is False:
                response = requests.get(url='http://' + self.dstIP + ':' + self.dport)
            elif self.use_ssl is True:
                response = requests.get(url='https://' + self.dstIP + ':' + self.dport)
        except requests.exceptions.ConnectionError as error:
            print('The target server seems down, details:')
            print(error)
        else:
            if response.status_code == 200:
                self.result.append({'IP': self.dstIP,
                                    'Port': self.dport,
                                    'Server Header': response.headers.get('Server')})
            else:
                print('Receive HTTP Status ' + response.status_code)

        self.finish_flag = True

    def report(self) -> (bool, list):
        if self.finish_flag is True:
            if self.result == 'App-webs/':
                return True, self.result
            else:
                return True, []
        else:
            return False, []
