# 海康威视IP摄像机扫描类
# 1. 官方SDAP扫描方式：发送组播UDP报文
#   目的地址：239.255.255.250（组播地址）
#   目的端口：37020
#   运输层协议：UDP
#   构造XML作为UDP负载，具体形式通过对官方SDAP工具进行流量分析得到
#   在本机任一端口（最好是37020）监听回复包，解析UDP负载中的XML内容
# 2. HTTP 80端口扫描：判断HTTP响应的Server字段
#   该方法检查HTTP响应包中的Server字段（HTTP Banner），此方法源于乌云漏洞平台2015年的文章：
#   https://www.secpulse.com/archives/39342.html

import uuid
import requests
from scapy.all import *
from xml.dom import minidom
from AbstractScanner import *


# 官方SDAP扫描方式：发送组播UDP报文
class HikvisionUDPScanner(AbstractScanner):
    # 本地IP地址，可以通过Scapy获取
    local_ip: str = '127.0.0.1'
    # 扫描端口，该方式下固定为37020
    port: int = 37020
    # 结果列表，元素类型为字典类型
    result: list = []
    # sniff监听线程
    listen_thread: threading.Thread
    # 监听线程停止标志
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
        # 获得发现数据包
        pkg = self.get_discover_pkg()
        # 显示数据包并确定校验和
        pkg.show2()
        # 设置本机IP
        self.local_ip = pkg.src
        # 创建监听线程
        self.listen_thread = threading.Thread(target=self.listen, name='Thread-Listen')
        # 设置为后台线程
        self.listen_thread.setDaemon(True)
        # 启动监听线程
        self.listen_thread.start()
        # verbose参数控制是否显示发送回显
        send(pkg, 1, verbose=0)

    def listen(self):
        # Scapy捕获函数，过滤条件：目的主机为本机且UDP端口号为37020
        sniff(prn=lambda x: self.handler(x),
              filter='Dst host '+self.local_ip+' and Udp port 37020',
              stop_filter=lambda x: self.stop_sniff.is_set())

    def handler(self, pkg):
        # 过滤掉非UDP报文
        if 'UDP' not in pkg:
            return
        # 判断目的IP和UDP端口是否符合条件
        if pkg[IP].dst != self.local_ip or pkg[UDP].dport != self.port or pkg[UDP].sport != self.port:
            return
        # 取出UDP负载，转换为字符串类型
        data = str(pkg.load, 'utf-8')
        try:
            # 将UDP负载格式化为字典类型
            dev_dict = HikvisionUDPScanner.parser(data)
            # 加入结果列表
            self.result.append(dev_dict)
        except TypeError as error:
            print(error)
            return

    @staticmethod
    def parser(data) -> dict:
        assert isinstance(data, str)
        # 去除前面的XML描述符
        data = data[38:]
        # 接收到的XML对象
        recv_xml = minidom.parseString(data)
        # 获取XML对象的根结点
        recv_root = recv_xml.documentElement
        # 设备信息字典类型
        dev_dict = {}
        # 判断根结点名称是否为ProbeMatch
        if recv_root.nodeName == 'ProbeMatch':
            # 获得根结点的所有子结点
            recv_childnodes = recv_root.childNodes
            for childnode in recv_childnodes:
                # 过滤掉内容仅为\n的结点
                if isinstance(childnode.childNodes, list) is True:
                    # 设置字典，Key为字段名称，Value为字段的值
                    dev_dict[childnode.nodeName] = childnode.childNodes[0].data
            return dev_dict
        else:
            raise TypeError('不是探测包的返回包，返回包的根结点名称必须是ProbeMatch')

    def report(self) -> (bool, list):
        # 如果有结果返回True，并返回结果列表
        if len(self.result) > 0:
            return True, self.result
        else:
            return False, []

    def stop(self):
        if self.stop_sniff.is_set() is False:
            self.stop_sniff.set()


# HTTP 80端口扫描：判断HTTP响应的Server字段
class HikvisionHTTPScanner(AbstractScanner):
    dport: int = 0
    result: list = []
    header_list = ['App-webs/', 'DVRDVS-Webs/', 'DNVRS-Webs/', 'Hikvision-Webs/']
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
            # 端口为80，且不使用SSL（标准HTTP端口）
            if self.dport == 80 and self.use_ssl is False:
                response = requests.get(url='http://' + self.dstIP)
            # 端口为443，且使用SSL（标准HTTPS端口）
            elif self.dport == 443 and self.use_ssl is True:
                response = requests.get(url='https://' + self.dstIP)
            # 不使用SSL（非标准HTTP端口）
            elif self.use_ssl is False:
                response = requests.get(url='http://' + self.dstIP + ':' + self.dport)
            # 使用SSL（非标准HTTPS端口）
            elif self.use_ssl is True:
                response = requests.get(url='https://' + self.dstIP + ':' + self.dport)
        except requests.exceptions.ConnectionError as error:
            # 目标无法连接
            print('The target server seems down, details:')
            print(error)
        else:
            # HTTP响应码为200
            if response.status_code == 200:
                # 检查是否命中想要的Server字段
                for header in self.header_list:
                    if response.headers.get('Server') == header:
                        self.result.append({'IP': self.dstIP,
                                            'Port': self.dport,
                                            'ServerHeader': header})
                        break
            else:
                print('Receive HTTP Status ' + response.status_code)

        self.finish_flag = True

    def report(self) -> (bool, list):
        if self.finish_flag is True:
            return True, self.result
        else:
            return False, []
