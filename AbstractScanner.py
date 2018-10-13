from abc import ABCMeta, abstractmethod


# 抽象类，定义一个设备扫描器所需接口
class AbstractScanner:
    __metaclass__ = ABCMeta
    # 目的IP地址，目标设备的IP地址，也可以是广播地址或组播地址
    dstIP: str = '255.255.255.255'

    def __init__(self, dst_ip):
        assert isinstance(dst_ip, str)
        self.dstIP = dst_ip

    # 启动扫描
    @abstractmethod
    def start(self):
        pass

    # 显示目标设备的信息
    @abstractmethod
    def report(self) -> (bool, list):
        pass
