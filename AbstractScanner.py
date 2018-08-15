# 抽象类，定义扫描器所需接口

from abc import ABCMeta, abstractmethod


class AbstractScanner:
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_discover_pkg(self):
        pass

    @abstractmethod
    def send(self, pkg, time):
        pass
