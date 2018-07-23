# 抽象类，定义扫描器所需接口

from abc import ABCMeta, abstractmethod


class AbstractScanner:
    __metaclass__ = ABCMeta

    @abstractmethod
    def getDiscoverPackage(self):
        pass

    @abstractmethod
    def sendPackage(self, pkg, time):
        pass
