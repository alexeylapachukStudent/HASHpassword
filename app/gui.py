import tkinter as tk
from tkinter import messagebox
from PIL import Image
import pyotp
import qrcode
from app.auth import register, login, change_password, enable_2fa, verify_2fa


# GUI Application
class HASHapp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentication System")
        self.create_widgets()

    def create_widgets(self):
        # Tabs for different actions
        self.tabs = tk.Frame(self.root)
        self.tabs.pack(fill=tk.X)

        self.register_btn = tk.Button(self.tabs, text="Register", command=self.show_register)
        self.register_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.login_btn = tk.Button(self.tabs, text="Login", command=self.show_login)
        self.login_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.change_password_btn = tk.Button(self.tabs, text="Change Password", command=self.show_change_password)
        self.change_password_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.enable_2fa_btn = tk.Button(self.tabs, text="Enable 2FA", command=self.show_enable_2fa)
        self.enable_2fa_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.verify_2fa_btn = tk.Button(self.tabs, text="Verify 2FA", command=self.show_verify_2fa)
        self.verify_2fa_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Frame for dynamic content
        self.content_frame = tk.Frame(self.root)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        self.show_register()

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_register(self):
        self.clear_content()

        tk.Label(self.content_frame, text="Register", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.content_frame, text="Username:").pack(anchor="w")
        self.reg_username = tk.Entry(self.content_frame)
        self.reg_username.pack(fill="x")

        tk.Label(self.content_frame, text="Password:").pack(anchor="w")
        self.reg_password = tk.Entry(self.content_frame, show="*")
        self.reg_password.pack(fill="x")

        tk.Label(self.content_frame, text="Email:").pack(anchor="w")
        self.reg_email = tk.Entry(self.content_frame)
        self.reg_email.pack(fill="x")

        tk.Button(self.content_frame, text="Register", command=self.register_user).pack(pady=10)

    def register_user(self):
        username = self.reg_username.get()
        password = self.reg_password.get()
        email = self.reg_email.get()

        # Call register function
        result = register(username, password, email)
        if result:
            messagebox.showinfo("Success", "Registration successful!")
        else:
            messagebox.showerror("Error", "Registration failed!")

    def show_login(self):
        self.clear_content()

        tk.Label(self.content_frame, text="Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.content_frame, text="Username:").pack(anchor="w")
        self.login_username = tk.Entry(self.content_frame)
        self.login_username.pack(fill="x")

        tk.Label(self.content_frame, text="Password:").pack(anchor="w")
        self.login_password = tk.Entry(self.content_frame, show="*")
        self.login_password.pack(fill="x")

        tk.Button(self.content_frame, text="Login", command=self.login_user).pack(pady=10)

    def login_user(self):
        username = self.login_username.get()
        password = self.login_password.get()

        # Call login function
        result = login(username, password)
        if result:
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Login failed!")

    def show_change_password(self):
        self.clear_content()

        tk.Label(self.content_frame, text="Change Password", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.content_frame, text="Username:").pack(anchor="w")
        self.change_username = tk.Entry(self.content_frame)
        self.change_username.pack(fill="x")

        tk.Label(self.content_frame, text="Old Password:").pack(anchor="w")
        self.old_password = tk.Entry(self.content_frame, show="*")
        self.old_password.pack(fill="x")

        tk.Label(self.content_frame, text="New Password:").pack(anchor="w")
        self.new_password = tk.Entry(self.content_frame, show="*")
        self.new_password.pack(fill="x")

        tk.Button(self.content_frame, text="Change Password", command=self.change_user_password).pack(pady=10)

    def change_user_password(self):
        username = self.change_username.get()
        old_password = self.old_password.get()
        new_password = self.new_password.get()

        # Call change_password function
        result = change_password(username, old_password, new_password)
        messagebox.showinfo("Result", result)

    def show_enable_2fa(self):
        self.clear_content()

        tk.Label(self.content_frame, text="Enable 2FA", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.content_frame, text="Username:").pack(anchor="w")
        self.otp_username = tk.Entry(self.content_frame)
        self.otp_username.pack(fill="x")

        tk.Button(self.content_frame, text="Enable 2FA", command=self.enable_2fa_user).pack(pady=10)

    def enable_2fa_user(self):
        username = self.otp_username.get()

        # Call enable_2fa function
        secret = enable_2fa(username)
        
        
        if secret:
            totp = pyotp.TOTP(secret)
            qr_url = totp.provisioning_uri(username, issuer_name="HASHpassword")
            
            qr = qrcode.make(qr_url)
            qr_file = "qrcode.png"
            qr.save(qr_file)
            
            
            # Loading the QR code image
            qr_img = Image.open(qr_file)
            qr_img = qr_img.resize((200, 200))
            self.qr_photo = tk.PhotoImage(file=qr_file)
            
            qr_label = tk.Label(self.content_frame, image=self.qr_photo)
            qr_label.pack(pady=10)
            
            
        else:
            messagebox.showerror("Error", "Failed to enable 2FA")

    def show_verify_2fa(self):
        self.clear_content()

        tk.Label(self.content_frame, text="Verify 2FA", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.content_frame, text="Username:").pack(anchor="w")
        self.verify_username = tk.Entry(self.content_frame)
        self.verify_username.pack(fill="x")

        tk.Label(self.content_frame, text="OTP Code:").pack(anchor="w")
        self.verify_code = tk.Entry(self.content_frame)
        self.verify_code.pack(fill="x")

        tk.Button(self.content_frame, text="Verify 2FA", command=self.verify_2fa_user).pack(pady=10)

    def verify_2fa_user(self):
        username = self.verify_username.get()
        otp_code = self.verify_code.get()

        # Call verify_2fa function
        result = verify_2fa(username, otp_code)
        if result:
            messagebox.showinfo("Success", "2FA verified successfully!")
        else:
            messagebox.showerror("Error", "Failed to verify 2FA")



