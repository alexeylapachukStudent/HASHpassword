import tkinter as tk
from app.gui import HASHapp

def run_app():
    root = tk.Tk()
    app = HASHapp(root)
    root.mainloop()

if __name__ == "__main__":
    run_app()