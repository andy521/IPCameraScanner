import tkinter
from tkinter.filedialog import *
from tkinter.ttk import Treeview
from Hikvision import *

result = []


def start_udp_scan():
    clear()
    udp_scan_thread = threading.Thread(target=udp_scan_handler, name='Thread-UDP-Scan')
    udp_scan_thread.setDaemon(True)
    udp_scan_thread.start()


def start_http_scan():
    clear()
    http_scan_thread = threading.Thread(target=http_scan_handler, name='Thread-UDP-Scan')
    http_scan_thread.setDaemon(True)
    http_scan_thread.start()


def udp_scan_handler():
    global result
    result = udp_scan()
    i = 1
    for item in result:
        print(item)
        # 将结果插入界面的列表中
        dev_list_tree.insert('', 'end', i, text=i, values=(
            '海康威视',
            item['DeviceDescription'],
            item['CommandPort'],
            item['HttpPort'],
            item['MAC'],
            item['IPv4Address'],
            item['SoftwareVersion'],
            item['DSPVersion']
        ))
        # 更新界面
        dev_list_tree.update_idletasks()
        i = i + 1


def http_scan_handler():
    global result
    result = http_scan()
    i = 1
    for item in result:
        # dev_list_tree.insert(str(i), 'end', i, text='1', values=())
        i = i + 1
        dev_list_tree.update_idletasks()


def udp_scan():
    s = HikvisionUDPScanner(dst_ip='239.255.255.250')
    s.start()
    while True:
        time.sleep(2)
        is_finished, res = s.report()
        if is_finished is True:
            s.stop()
            return res


def http_scan(ip, port, use_ssl):
    s = HikvisionHTTPScanner(dst_ip=ip, dport=port, use_ssl=use_ssl)
    s.start()
    while True:
        time.sleep(2)
        is_finished, res = s.report()
        if is_finished is True:
            return res


def on_click_dev_list_tree(event):
    global result
    selected_item = event.widget.selection()
    select_res_item = result[int(selected_item[0]) - 1]
    details_window = tkinter.Tk()
    details_window.title('扫描结果详细信息')
    details_window.resizable(width=False, height=True)
    for item in select_res_item:
        if item == 'Uuid' or item == 'Types':
            continue
        row = Frame(details_window)
        label = Label(row, width=15, text=item, anchor='e')
        entry = Entry(row, state='normal')
        entry.insert(0, select_res_item[item])
        entry['state'] = 'disable'
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
    details_window.mainloop()


def clear():
    global result
    result = []
    dev_list_tree.delete(*dev_list_tree.get_children())


def quit_program():
    exit(0)


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
    start_udp_scan_button = Button(toolbar, width=8, text='开始扫描', command=start_udp_scan)
    clear_button = Button(toolbar, width=8, text='清空', command=clear)
    quit_button = Button(toolbar, width=8, text='退出', command=quit_program)
    start_udp_scan_button.pack(side=LEFT, padx=5)
    clear_button.pack(side=LEFT, after=start_udp_scan_button, padx=10, pady=10)
    quit_button.pack(side=LEFT, after=clear_button, padx=10, pady=10)
    toolbar.pack(side=TOP, fill=X)
    dev_list_frame = Frame()
    dev_list_sub_frame = Frame(dev_list_frame)
    dev_list_tree = Treeview(dev_list_sub_frame, selectmode='browse')
    dev_list_tree.bind('<<TreeviewSelect>>', on_click_dev_list_tree)
    dev_list_vscrollbar = Scrollbar(dev_list_sub_frame,
                                       orient='vertical', command=dev_list_tree.yview)
    dev_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
    dev_list_tree.configure(yscrollcommand=dev_list_vscrollbar.set)
    dev_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
    dev_list_hscrollbar = Scrollbar(dev_list_frame,
                                       orient='horizontal', command=dev_list_tree.xview)
    dev_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
    dev_list_tree.configure(xscrollcommand=dev_list_hscrollbar.set)
    dev_list_tree['columns'] = (
        '设备品牌', '设备描述', '命令端口', 'HTTP端口',
        'MAC地址', 'IPv4地址', '软件版本', 'DSP版本')
    dev_list_column_width = [100, 160, 100, 100, 160, 120, 160, 160]
    dev_list_tree['show'] = 'headings'
    for column_name, column_width in zip(dev_list_tree['columns'], dev_list_column_width):
        dev_list_tree.column(column_name, width=column_width, anchor='w')
        dev_list_tree.heading(column_name, text=column_name)
    dev_list_tree.pack(side=LEFT, fill=X, expand=YES)
    dev_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
    main_panedwindow.add(dev_list_frame)
    main_panedwindow.pack(fill=BOTH, expand=1)
    status_bar = StatusBar(tk)
    status_bar.pack(side=BOTTOM, fill=X)
    tk.mainloop()
