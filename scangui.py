import tkinter
from tkinter.filedialog import *
from tkinter.ttk import Treeview
from Hikvision import *


def start_udp_scan():
    pass


def start_http_scan():
    pass


def udp_scan_handler():
    result = udp_scan()
    i = 1
    for item in result:
        packet_list_tree.insert(str(i), 'end', i, text='1', values=(
            item[''], 2, 3, 4, 5, 6, 7, 999))
        i = i + 1
    packet_list_tree.update_idletasks()


def http_scan_handler():
    result = http_scan()


def udp_scan():
    s = HikvisionUDPScanner(dst_ip='239.255.255.250')
    s.start()
    while True:
        is_finished, result = s.report()
        if is_finished is True:
            return result


def http_scan(ip, port, use_ssl):
    s = HikvisionHTTPScanner(dst_ip=ip, dport=port, use_ssl=use_ssl)
    s.start()
    while True:
        is_finished, result = s.report()
        if is_finished is True:
            return result


def clear():
    pass


def quit_program():
    exit(0)


def on_click_packet_list_tree():
    pass


class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


if __name__ == '__main__':
    tk = tkinter.Tk()
    tk.title("摄像机扫描器")
    main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)
    toolbar = Frame(tk)
    start_udp_scan_button = Button(toolbar, width=8, text="UDP扫描", command=start_udp_scan)
    start_http_scan_button = Button(toolbar, width=8, text="HTTP扫描", command=start_http_scan)
    clear_button = Button(toolbar, width=8, text="清空", command=clear)
    quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
    start_udp_scan_button.pack(side=LEFT, padx=5)
    start_http_scan_button.pack(side=LEFT, after=start_udp_scan_button, padx=10, pady=10)
    clear_button.pack(side=LEFT, after=start_http_scan_button, padx=10, pady=10)
    quit_button.pack(side=LEFT, after=clear_button, padx=10, pady=10)
    toolbar.pack(side=TOP, fill=X)
    packet_list_frame = Frame()
    packet_list_sub_frame = Frame(packet_list_frame)
    packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
    packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
    packet_list_vscrollbar = Scrollbar(packet_list_sub_frame,
                                       orient="vertical", command=packet_list_tree.yview)
    packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
    packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
    packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
    packet_list_hscrollbar = Scrollbar(packet_list_frame,
                                       orient="horizontal", command=packet_list_tree.xview)
    packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
    packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
    packet_list_tree['columns'] = (
        "DeviceDescription", "DeviceSN", "CommandPort", "HttpPort",
        "MAC", "IPv4Address", "SoftwareVersion", "DSPVersion")
    packet_list_column_width = [180, 180, 160, 160, 100, 100, 160, 100]
    packet_list_tree['show'] = 'headings'
    for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
        packet_list_tree.column(column_name, width=column_width, anchor='w')
        packet_list_tree.heading(column_name, text=column_name)

    packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
    packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
    main_panedwindow.add(packet_list_frame)
    main_panedwindow.pack(fill=BOTH, expand=1)
    status_bar = StatusBar(tk)
    status_bar.pack(side=BOTTOM, fill=X)
    tk.mainloop()
