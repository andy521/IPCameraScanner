import tkinter
from tkinter.filedialog import *
from tkinter.ttk import Treeview
from Hikvision import *

result = []


def start_udp_scan():
    udp_scan_thread = threading.Thread(target=udp_scan_handler, name='Thread-UDP-Scan')
    udp_scan_thread.setDaemon(True)
    udp_scan_thread.start()


def start_http_scan():
    http_scan_thread = threading.Thread(target=http_scan_handler, name='Thread-UDP-Scan')
    http_scan_thread.setDaemon(True)
    http_scan_thread.start()


def udp_scan_handler():
    global result
    result = udp_scan()
    i = 1
    for item in result:
        packet_list_tree.insert(str(i), 'end', i, text='1', values=(
            item['DeviceDescription'],
            item['DeviceSN'],
            item['CommandPort'],
            item['HttpPort'],
            item['MAC'],
            item['IPv4Address'],
            item['SoftwareVersion'],
            item['DSPVersion']
        ))
        i = i + 1
    packet_list_tree.update_idletasks()


def http_scan_handler():
    global result
    result = http_scan()
    i = 1
    for item in result:
        # packet_list_tree.insert(str(i), 'end', i, text='1', values=())
        i = i + 1
    packet_list_tree.update_idletasks()


def udp_scan():
    s = HikvisionUDPScanner(dst_ip='239.255.255.250')
    s.start()
    while True:
        is_finished, res = s.report()
        if is_finished is True:
            return res


def http_scan(ip, port, use_ssl):
    s = HikvisionHTTPScanner(dst_ip=ip, dport=port, use_ssl=use_ssl)
    s.start()
    while True:
        is_finished, res = s.report()
        if is_finished is True:
            return res


def clear():
    global result
    result = []
    for widget in packet_list_tree.winfo_children():
        widget.destroy()


def quit_program():
    exit(0)


def on_click_packet_list_tree(event):
    global result
    selected_item = event.widget.selection()
    select_res_item = result[int(selected_item[0]) - 1]
    details_window = tkinter.Tk()
    details_window.title('扫描结果详细信息')
    details_window.resizable(width=False, height=True)
    for item in select_res_item:
        row = Frame(details_window)
        label = Label(row, width=15, text=item, anchor='e')
        entry = Entry(row, font=('Courier', '12', 'bold'), state='disable')
        entry.insert(0, select_res_item[item])
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
    details_window.mainloop()


def create_protocol_editor(root, field_names):
    entries = []
    for field in field_names:
        row = Frame(root)
        label = Label(row, width=15, text=field, anchor='e')
        # 设置编辑框为等宽字体
        entry = Entry(row, font=('Courier', '12', 'bold'), state='normal')
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
        entries.append(entry)
    return entries


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
    tk.title('摄像机扫描器')
    tk.resizable(width=False, height=True)
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
