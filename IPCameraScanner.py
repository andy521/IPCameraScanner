from Hikvision import *

if __name__ == '__main__':
    scanner = HikvisionUDPScanner(dst_ip='239.255.255.250')
    scanner.start(repeats=1)
    scanner = HikvisionHTTPScanner(dst_ip='127.0.0.1', dport=80, use_ssl=False)
    scanner.start(repeats=1)
