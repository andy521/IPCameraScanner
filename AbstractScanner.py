from abc import ABCMeta, abstractmethod

# 抽象类，定义一个设备扫描器所需接口


class AbstractScanner:
    __metaclass__ = ABCMeta
    # 目的IP地址，目标设备的IP地址，也可以是广播地址或组播地址
    dstIP: str = '255.255.255.255'

    def __init__(self, dst_ip):
        self.dstIP = dst_ip

    # 发送探测报文
    @abstractmethod
    def send(self, pkg, repeats):
        pass

    # 接收目标设备的信息
    @abstractmethod
    def receive(self):
        pass
