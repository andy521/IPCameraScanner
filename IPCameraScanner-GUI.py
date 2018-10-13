
import tkinter
from tkinter.filedialog import *
from tkinter.ttk import Treeview
from scapy.layers.l2 import *


# 状态栏类
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


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def show_result():
    packet_list_tree.insert("", 'end', 1, text='1', values=(1, 2, 3, 4, 5, 6, 7))
    packet_list_tree.insert("", 'end', 2, text='2', values=(8, 9, 10, 11, 12, 13, 14))
    packet_list_tree.update_idletasks()


def quit_program():
    pass


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


"""
数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
:param event: TreeView单击事件
:return: None
"""


def on_click_packet_list_tree(event):
    pass


# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=show_result)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
quit_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)

packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)
main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
tk.mainloop()
