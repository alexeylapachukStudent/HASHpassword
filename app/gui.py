import tkinter as tk
from tkinter import messagebox
from auth import login, register, is_admin, change_password, enable_2fa, verify_2fa

class HASHapp:
    def __init__(self, root):
        self.root = root
        self.root.title("HASHapp")
        
        self.main_menu()
        
        def main_widgets_destriy():
            for widget in self.root.winfo_childre():
                widget.destroy()
        