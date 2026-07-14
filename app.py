import sys
import traceback
from pathlib import Path
from tkinter import messagebox

from gui.window import run_gui
from utils.permissions import is_admin, restart_as_admin


def _show_startup_failure(exc):
    error_text = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        messagebox.showerror('Network Scanner failed to start', error_text)
    except Exception:
        pass
    log_path = Path(__file__).with_name('startup_error.log')
    log_path.write_text(error_text, encoding='utf-8')

def main():
    try:
        if sys.platform.startswith('win'):
            if not is_admin():
                restart_as_admin(__file__)
                return
        run_gui()
    except Exception as exc:
        _show_startup_failure(exc)
        raise


if __name__ == '__main__':
    main()
