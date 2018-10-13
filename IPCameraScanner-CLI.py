from Hikvision import *

if __name__ == '__main__':
    scanner = HikvisionUDPScanner(dst_ip='239.255.255.250')
    scanner.start()
    scanner = HikvisionHTTPScanner(dst_ip='172.16.0.2', dport=80, use_ssl=False)
    scanner.start()
    while True:
        if scanner.report() == 'Still running':
            continue
        else:
            print(scanner.report())
            break
