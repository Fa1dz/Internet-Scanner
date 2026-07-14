from tkinter import filedialog, messagebox


def ask_save_csv_path():
    return filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])


def ask_save_json_path():
    return filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json')])


def ask_full_port_scan(ip):
    return messagebox.askyesno('Full Port Scan', f'Run full port scan on {ip}?\nThis may take several minutes.')


def show_info(title, text):
    messagebox.showinfo(title, text)


def show_error(title, text):
    messagebox.showerror(title, text)
