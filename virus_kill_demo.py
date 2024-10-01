import hashlib
import os
from tkinter import *
from tkinter import messagebox, filedialog, ttk
import threading

def read_virus_database(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Virus database file '{file_path}' not found.")
        return []

def get_md5_from_file(filepath):
    try:
        with open(filepath, 'rb') as file:
            md5_hash = hashlib.md5()
            for chunk in iter(lambda: file.read(4096), b""):
                md5_hash.update(chunk)
            return md5_hash.hexdigest()
    except (OSError, PermissionError):
        return None

def scan_directory(path, virus_hashes, progress_var, total_files, processed_files):
    try:
        files = os.listdir(path)
    except OSError:
        return

    for file in files:
        new_path = os.path.join(path, file)

        # Update the label with the current file being scanned
        scanned_file_var.set(f"正在扫描: {new_path}")
        window.update_idletasks()

        if os.path.isdir(new_path):
            scan_directory(new_path, virus_hashes, progress_var, total_files, processed_files)
        else:
            file_md5 = get_md5_from_file(new_path)
            if file_md5 and file_md5 in virus_hashes:
                try:
                    os.remove(new_path)
                    print(f"已经删除病毒文件: {new_path}")
                except OSError:
                    continue

        processed_files[0] += 1
        progress_var.set((processed_files[0] / total_files[0]) * 100)
        window.update_idletasks()  # Ensure the UI updates

def scan_c_drive():
    virus_database_path = 'c:\\病毒.txt'
    病毒库 = read_virus_database(virus_database_path)
    if not 病毒库:
        messagebox.showerror("错误", "无法读取病毒数据库")
        return

    virus_hashes = set(病毒库)

    total_files = [0]
    for root, dirs, files in os.walk('C:\\'):
        total_files[0] += len(files)

    processed_files = [0]
    progress_var.set(0)
    scanned_file_var.set("开始扫描...")

    scan_directory('C:\\', virus_hashes, progress_var, total_files, processed_files)

    messagebox.showinfo("扫描结果", "C盘扫描完成")

def check_file(file_path, virus_hashes):
    file_md5 = get_md5_from_file(file_path)
    if file_md5 and file_md5 in virus_hashes:
        try:
            os.remove(file_path)
            print(f"已经删除病毒文件: {file_path}")
        except OSError:
            pass

def ts(bt, text):
    messagebox.showinfo(bt, text)

def xz(bt, text):
    result = messagebox.askokcancel(title=bt, message=text)
    return result

def thread_it(func, *args):
    t = threading.Thread(target=func, args=args)
    t.daemon = True
    t.start()

def xzwj():
    fn = filedialog.askopenfilename(title='请选择需要查杀的文件', filetypes=[('所有文件', '.*')])
    return fn

def cs():
    lujing = xzwj()
    FileMD5 = get_md5_from_file(lujing)
    virus_hashes = read_virus_database('c:\\病毒.txt')

    if FileMD5 in virus_hashes:
        ts('查杀结果', '发现恶搞程序！！！类型：Trojan.Win32.FormatAll.V')
        xuan = xz('处理方式', "是否直接处理")

        if xuan:
            try:
                os.remove(lujing)
                os.system('taskkill /f /im %s' % 'ZhuYao.bat')
                os.remove(r'C:\GYF\*')
                os.system('reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" /f')
            except Exception as e:
                print(f"Error handling file: {e}")
        else:
            os.remove(lujing)
    else:
        ts('查杀结果', '并未发现病毒')

if __name__ == '__main__':
    window = Tk()

    window.title("杀毒软件")
    screenwidth = window.winfo_screenwidth()
    screenheight = window.winfo_screenheight()
    width = 600
    height = 400
    x = int((screenwidth - width) / 2)
    y = int((screenheight - height) / 2)
    window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    window.resizable(width=False, height=False)

    window.configure(bg='orange')

    huanying = Label(window, text="欢迎来到杀毒软件！", font=("微软雅黑", 18), bg='orange', fg='white')
    huanying.pack(pady=20)

    csan = Button(window, text="扫描C盘", command=lambda: thread_it(scan_c_drive), font=("微软雅黑", 14), bg='white', fg='black')
    csan.place(x=250, y=100)

    progress_var = DoubleVar()
    progress_bar = ttk.Progressbar(window, variable=progress_var, maximum=100)
    progress_bar.place(x=150, y=200, width=300, height=30)

    scanned_file_var = StringVar()
    scanned_file_label = Label(window, textvariable=scanned_file_var, font=("微软雅黑", 12), bg='orange', fg='white', wraplength=580, justify=LEFT)
    scanned_file_label.place(x=10, y=250, width=580, height=60)

    window.mainloop()