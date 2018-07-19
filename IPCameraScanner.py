
from scapy.all import *
from Hikvision import *

if __name__ == '__main__':
	scanner = HikvisionUDPScanner()
#	获得发现数据包
	pkg = scanner.getDiscoverPackage()
#	显示数据包并确定校验和
	pkg.show2()
	scanner.sendPackage(pkg,10)
	