from Hikvision import *


def udp_scan():
    s = HikvisionUDPScanner(dst_ip='239.255.255.250')
    s.start()
    while True:
        time.sleep(2)
        is_finished, result = s.report()
        if is_finished is True:
            for item in result:
                print(item)
            break


def http_scan(ip, port, use_ssl):
    s = HikvisionHTTPScanner(dst_ip=ip, dport=port, use_ssl=use_ssl)
    s.start()
    while True:
        time.sleep(2)
        is_finished, result = s.report()
        if is_finished is True:
            for item in result:
                print(item)
            break


if __name__ == '__main__':
    udp_scan()
    http_scan(ip='172.16.0.2', port=80, use_ssl=False)
