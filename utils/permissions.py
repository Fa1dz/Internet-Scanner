import ctypes
import os
import sys

from tkinter import messagebox


def is_admin():
    try:
        if sys.platform.startswith('win'):
            return ctypes.windll.shell32.IsUserAnAdmin()
        return os.geteuid() == 0
    except Exception:
        return False


def restart_as_admin(script_path):
    if not is_admin():
        try:
            abs_script_path = os.path.abspath(script_path)
            script_dir = os.path.dirname(abs_script_path)
            parameters = f'"{abs_script_path}"'
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, parameters, script_dir, 1)
            if result <= 32:
                raise OSError(f'ShellExecuteW failed with code {result}')
            sys.exit(0)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to restart with admin rights: {e}')
            sys.exit(1)
