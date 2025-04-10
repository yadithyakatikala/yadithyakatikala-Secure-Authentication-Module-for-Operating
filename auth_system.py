import tkinter as tk
from tkinter import simpledialog, messagebox
import hashlib
import os
import json
import time
import subprocess
import logging
import random

# Setup Logging
logging.basicConfig(filename='auth.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Constants
USERS_FILE = 'users.json'
FAILED_ATTEMPTS_LIMIT = 3

# Load or initialize users
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
else:
    users = {}

failed_attempts = 0

# Hashing password
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# Save users to disk
def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# MFA (OTP Simulation)
def perform_mfa():
    otp = str(random.randint(1000, 9999))
    messagebox.showinfo("MFA Required", f"Your OTP is: {otp}")
    user_otp = simpledialog.askstring("MFA", "Enter OTP:")
    return user_otp == otp

# Simulated fingerprint check (replaceable with real system API)
def fingerprint_check():
    result = messagebox.askyesno("Fingerprint", "Simulate fingerprint scan?\n(Press Yes for success)")
    return result

# Safe mode subprocess
def enter_safe_mode():
    logging.warning("Too many failed attempts. Entering Safe Mode.")
    subprocess.Popen(["/usr/bin/open", "-a", "TextEdit"])  # Simulate restricted access

# GUI
class AuthApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure OS Auth System")

        self.label = tk.Label(master, text="Secure Authentication Flow", font=('Arial', 14))
        self.label.pack(pady=10)

        self.flow_status = tk.Label(master, text="Current Stage: Idle", fg="blue")
        self.flow_status.pack(pady=5)

        self.register_btn = tk.Button(master, text="Create Account", command=self.register)
        self.register_btn.pack(pady=5)

        self.login_btn = tk.Button(master, text="Login", command=self.login)
        self.login_btn.pack(pady=5)

        self.quit_btn = tk.Button(master, text="Exit", command=master.quit)
        self.quit_btn.pack(pady=10)

    def update_flow(self, step):
        self.flow_status.config(text=f"Current Stage: {step}")
        logging.info(f"Flow moved to: {step}")

    def register(self):
        self.update_flow("Registration")
        username = simpledialog.askstring("Register", "Enter Username:")
        if not username:
            return
        password = simpledialog.askstring("Register", "Enter Password:", show="*")
        if not password:
            return
        if not fingerprint_check():
            messagebox.showerror("Fingerprint", "Fingerprint authentication failed.")
            return
        users[username] = hash_password(password)
        save_users()
        messagebox.showinfo("Success", "Account created successfully!")
        logging.info(f"New user registered: {username}")

    def login(self):
        global failed_attempts
        self.update_flow("Login")
        username = simpledialog.askstring("Login", "Enter Username:")
        password = simpledialog.askstring("Login", "Enter Password:", show="*")
        if username in users and users[username] == hash_password(password):
            self.update_flow("Fingerprint Auth")
            if not fingerprint_check():
                messagebox.showerror("Auth Failed", "Fingerprint mismatch.")
                failed_attempts += 1
            else:
                messagebox.showinfo("Welcome", f"Login successful! Welcome {username}.")
                logging.info(f"User logged in: {username}")
                failed_attempts = 0
                self.update_flow("Authenticated")
        else:
            failed_attempts += 1
            logging.warning(f"Login failed for user: {username}")
            messagebox.showerror("Login Failed", f"Incorrect credentials. Attempt {failed_attempts}/{FAILED_ATTEMPTS_LIMIT}")
            if failed_attempts >= FAILED_ATTEMPTS_LIMIT:
                self.update_flow("MFA Required")
                if perform_mfa():
                    messagebox.showinfo("MFA", "MFA successful. You're in.")
                    logging.info("MFA succeeded after failed attempts.")
                    failed_attempts = 0
                else:
                    messagebox.showerror("MFA", "MFA failed. Entering Safe Mode.")
                    enter_safe_mode()
                    self.update_flow("Safe Mode")
                    failed_attempts = 0

# Launch App
root = tk.Tk()
app = AuthApp(root)
root.mainloop()
