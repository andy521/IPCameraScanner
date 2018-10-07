from Hikvision import *

if __name__ == '__main__':
    scanner = HikvisionUDPScanner('239.255.255.250')
    # 获得发现数据包
    pkg = scanner.get_discover_pkg()
    # 显示数据包并确定校验和
    pkg.show2()
    scanner.send(pkg, 10)
