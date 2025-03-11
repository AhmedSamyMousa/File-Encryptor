import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import subprocess
from PIL import Image, ImageTk
import webbrowser
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import shutil
import json

FILE_TYPES = {
    "Image": [".png", ".jpg", ".bmp"],
    "Video": [".mp4", ".avi", ".mov"],
    "3D Model": [".obj", ".fbx", ".stl"],
    "Audio": [".mp3", ".wav", ".flac"],
    "Text Document": [".txt", ".md", ".log"],
    "Spreadsheet": [".csv", ".xlsx"],
    "Executable": [".exe", ".bin"]
}

ENCRYPTED_EXTENSION = ".encrypted"

class FileExtensionChanger:
    def __init__(self):
        self.new_file_path = ""
        self.original_file_path = ""
        self.original_extension = ""
        self.app_version = "1.0.0"
        self.encrypted_files_db = self.load_encrypted_files_db()

        self.setup_ui()

    def load_encrypted_files_db(self):
        db_path = os.path.join(os.path.expanduser("~"), ".file_encryptor_db.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_encrypted_files_db(self):
        db_path = os.path.join(os.path.expanduser("~"), ".file_encryptor_db.json")
        with open(db_path, 'w') as f:
            json.dump(self.encrypted_files_db, f)

    def setup_ui(self):

        ctk.set_appearance_mode("System")  
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("File Encryptor & Extension Changer")
        self.root.geometry("540x780")
        self.root.resizable(False, False)

        self.content_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.header_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=20, pady=(20, 10))

        header_label = ctk.CTkLabel(
            self.header_frame, 
            text="File Encryptor", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        header_label.pack(side="left")

        self.theme_button = ctk.CTkButton(
            self.header_frame,
            text="🌙",
            width=40,
            command=self.toggle_theme,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "gray90")
        )
        self.theme_button.pack(side="right")

        description = ctk.CTkLabel(
            self.content_frame,
            text="Encrypt files by changing their extension. Password protected.",
            font=ctk.CTkFont(size=14),
            text_color=("gray60", "gray70")
        )
        description.pack(padx=20, pady=(0, 20), anchor="w")

        self.tabview = ctk.CTkTabview(self.content_frame)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)

        self.encrypt_tab = self.tabview.add("Encrypt")
        self.decrypt_tab = self.tabview.add("Decrypt")

        self.tabview.set("Encrypt")

        self.file_section = self.create_section(self.encrypt_tab, "File Selection")

        self.file_path_var = tk.StringVar(value="No file selected")
        self.file_path_display = ctk.CTkLabel(
            self.file_section,
            textvariable=self.file_path_var,
            font=ctk.CTkFont(size=12),
            anchor="w",
            wraplength=440
        )
        self.file_path_display.pack(fill="x", padx=15, pady=(5, 15))

        self.choose_file_btn = ctk.CTkButton(
            self.file_section,
            text="Choose File",
            command=self.select_file,
            height=38,
            corner_radius=8,
            border_width=0,
            font=ctk.CTkFont(weight="bold")
        )
        self.choose_file_btn.pack(fill="x", padx=15, pady=(0, 15))

        self.ext_section = self.create_section(self.encrypt_tab, "Custom Extension (Optional)")

        self.ext_prefix_frame = ctk.CTkFrame(self.ext_section, fg_color="transparent")
        self.ext_prefix_frame.pack(fill="x", padx=15, pady=(5, 15))

        self.ext_prefix = ctk.CTkLabel(
            self.ext_prefix_frame,
            text=".",
            width=20,
            font=ctk.CTkFont(size=16)
        )
        self.ext_prefix.pack(side="left")

        self.ext_entry = ctk.CTkEntry(
            self.ext_prefix_frame,
            height=38,
            corner_radius=8,
            border_width=1,
            placeholder_text="Leave empty to use default (.encrypted)",
            font=ctk.CTkFont(size=13)
        )
        self.ext_entry.pack(side="left", fill="x", expand=True)

        self.password_section = self.create_section(self.encrypt_tab, "Encryption Password")

        self.password_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(
            self.password_section,
            height=38,
            corner_radius=8,
            border_width=1,
            placeholder_text="Enter password",
            font=ctk.CTkFont(size=13),
            show="•",
            textvariable=self.password_var
        )
        self.password_entry.pack(fill="x", padx=15, pady=(5, 10))

        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ctk.CTkEntry(
            self.password_section,
            height=38,
            corner_radius=8,
            border_width=1,
            placeholder_text="Confirm password",
            font=ctk.CTkFont(size=13),
            show="•",
            textvariable=self.confirm_password_var
        )
        self.confirm_password_entry.pack(fill="x", padx=15, pady=(0, 15))

        self.show_password_var = tk.IntVar(value=0)
        self.show_password_checkbox = ctk.CTkCheckBox(
            self.password_section,
            text="Show password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            font=ctk.CTkFont(size=12)
        )
        self.show_password_checkbox.pack(padx=15, pady=(0, 15), anchor="w")

        self.encrypt_btn = ctk.CTkButton(
            self.encrypt_tab,
            text="Encrypt File",
            command=self.encrypt_file,
            height=42,
            corner_radius=8,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#2e7d32",
            hover_color="#1b5e20"
        )
        self.encrypt_btn.pack(fill="x", padx=20, pady=(20, 10))

        self.decrypt_file_section = self.create_section(self.decrypt_tab, "Encrypted File Selection")

        self.decrypt_file_path_var = tk.StringVar(value="No file selected")
        self.decrypt_file_path_display = ctk.CTkLabel(
            self.decrypt_file_section,
            textvariable=self.decrypt_file_path_var,
            font=ctk.CTkFont(size=12),
            anchor="w",
            wraplength=440
        )
        self.decrypt_file_path_display.pack(fill="x", padx=15, pady=(5, 15))

        self.decrypt_choose_file_btn = ctk.CTkButton(
            self.decrypt_file_section,
            text="Choose Encrypted File",
            command=self.select_encrypted_file,
            height=38,
            corner_radius=8,
            border_width=0,
            font=ctk.CTkFont(weight="bold")
        )
        self.decrypt_choose_file_btn.pack(fill="x", padx=15, pady=(0, 15))

        self.decrypt_password_section = self.create_section(self.decrypt_tab, "Decryption Password")

        self.decrypt_password_var = tk.StringVar()
        self.decrypt_password_entry = ctk.CTkEntry(
            self.decrypt_password_section,
            height=38,
            corner_radius=8,
            border_width=1,
            placeholder_text="Enter password",
            font=ctk.CTkFont(size=13),
            show="•",
            textvariable=self.decrypt_password_var
        )
        self.decrypt_password_entry.pack(fill="x", padx=15, pady=(5, 15))

        self.decrypt_show_password_var = tk.IntVar(value=0)
        self.decrypt_show_password_checkbox = ctk.CTkCheckBox(
            self.decrypt_password_section,
            text="Show password",
            variable=self.decrypt_show_password_var,
            command=self.toggle_decrypt_password_visibility,
            font=ctk.CTkFont(size=12)
        )
        self.decrypt_show_password_checkbox.pack(padx=15, pady=(0, 15), anchor="w")

        self.decrypt_btn = ctk.CTkButton(
            self.decrypt_tab,
            text="Decrypt File",
            command=self.decrypt_file,
            height=42,
            corner_radius=8,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#1976d2",
            hover_color="#0d47a1"
        )
        self.decrypt_btn.pack(fill="x", padx=20, pady=(20, 10))

        self.status_frame = ctk.CTkFrame(self.content_frame, corner_radius=8, fg_color=("gray90", "gray20"))
        self.status_frame.pack(fill="x", padx=20, pady=(15, 5))

        self.status_var = tk.StringVar(value="Ready to use")
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            textvariable=self.status_var,
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray70")
        )
        self.status_label.pack(padx=10, pady=10)

        self.footer_frame = ctk.CTkFrame(self.root, fg_color="transparent", height=30)
        self.footer_frame.pack(fill="x", padx=20, pady=(0, 10))

        version_label = ctk.CTkLabel(
            self.footer_frame,
            text=f"Version {self.app_version}",
            font=ctk.CTkFont(size=11),
            text_color=("gray60", "gray70")
        )
        version_label.pack(side="left")

        warning_label = ctk.CTkLabel(
            self.footer_frame,
            text="⚠️ Remember your password, files cannot be recovered without it!",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#d32f2f", "#f44336")
        )
        warning_label.pack(side="right")

    def create_section(self, parent, title):
        section_frame = ctk.CTkFrame(parent, corner_radius=8)
        section_frame.pack(fill="x", padx=0, pady=10)

        title_label = ctk.CTkLabel(
            section_frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        title_label.pack(anchor="w", padx=15, pady=(15, 5))

        return section_frame

    def toggle_theme(self):
        current_mode = ctk.get_appearance_mode()
        if current_mode == "Dark":
            ctk.set_appearance_mode("Light")
            self.theme_button.configure(text="🌙")
        else:
            ctk.set_appearance_mode("Dark")
            self.theme_button.configure(text="☀️")

    def toggle_password_visibility(self):
        if self.show_password_var.get() == 1:
            self.password_entry.configure(show="")
            self.confirm_password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")
            self.confirm_password_entry.configure(show="•")

    def toggle_decrypt_password_visibility(self):
        if self.decrypt_show_password_var.get() == 1:
            self.decrypt_password_entry.configure(show="")
        else:
            self.decrypt_password_entry.configure(show="•")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        if file_path.lower().endswith(ENCRYPTED_EXTENSION) or self.is_file_encrypted(file_path):
            self.show_notification("This file appears to be already encrypted. Use the Decrypt tab.", "warning")
            self.tabview.set("Decrypt")
            return

        self.original_file_path = file_path
        self.original_extension = os.path.splitext(file_path)[1].lower()

        filename = os.path.basename(file_path)

        self.file_path_var.set(filename)
        self.status_var.set(f"Selected: {filename}")

    def select_encrypted_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_hash = self.get_file_hash(file_path)
        if file_hash not in self.encrypted_files_db and not file_path.lower().endswith(ENCRYPTED_EXTENSION):
            self.show_notification("This file doesn't appear to be encrypted with this application.", "warning")
            return

        self.encrypted_file_path = file_path

        filename = os.path.basename(file_path)

        self.decrypt_file_path_var.set(filename)
        self.status_var.set(f"Selected encrypted file: {filename}")

    def get_file_hash(self, file_path):
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def is_file_encrypted(self, file_path):
        file_hash = self.get_file_hash(file_path)
        return file_hash in self.encrypted_files_db

    def generate_key_from_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_file(self):
        if not self.original_file_path:
            self.show_notification("Please select a file first", "error")
            return

        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()

        if not password:
            self.show_notification("Please enter a password", "error")
            return

        if password != confirm_password:
            self.show_notification("Passwords do not match", "error")
            return

        custom_ext = self.ext_entry.get().strip()
        if custom_ext:
            if not custom_ext.startswith("."):
                custom_ext = f".{custom_ext}"
            extension = custom_ext
        else:
            extension = ENCRYPTED_EXTENSION

        try:

            salt = os.urandom(16)
            key, salt = self.generate_key_from_password(password, salt)
            fernet = Fernet(key)

            with open(self.original_file_path, 'rb') as f:
                data = f.read()

            encrypted_data = fernet.encrypt(data)

            self.new_file_path = os.path.splitext(self.original_file_path)[0] + extension

            if os.path.exists(self.new_file_path):
                result = messagebox.askquestion(
                    "File Exists", 
                    f"A file with this name already exists.\nDo you want to overwrite it?",
                    icon="warning"
                )
                if result != "yes":
                    return
                os.remove(self.new_file_path)

            with open(self.new_file_path, 'wb') as f:
                f.write(encrypted_data)

            file_hash = self.get_file_hash(self.new_file_path)
            self.encrypted_files_db[file_hash] = {
                'original_extension': self.original_extension,
                'salt': base64.b64encode(salt).decode(),
                'date_encrypted': os.path.getmtime(self.new_file_path)
            }

            self.save_encrypted_files_db()

            os.remove(self.original_file_path)

            new_filename = os.path.basename(self.new_file_path)
            self.file_path_var.set(new_filename)
            self.show_notification(f"File encrypted successfully with {extension} extension", "success")

            self.password_var.set("")
            self.confirm_password_var.set("")

        except Exception as e:
            self.show_notification(f"Error during encryption: {str(e)}", "error")

    def decrypt_file(self):
        if not hasattr(self, 'encrypted_file_path') or not self.encrypted_file_path:
            self.show_notification("Please select an encrypted file first", "error")
            return

        password = self.decrypt_password_var.get()

        if not password:
            self.show_notification("Please enter the decryption password", "error")
            return

        try:

            file_hash = self.get_file_hash(self.encrypted_file_path)

            if file_hash in self.encrypted_files_db:
                metadata = self.encrypted_files_db[file_hash]
                original_extension = metadata['original_extension']
                salt = base64.b64decode(metadata['salt'])
            else:

                if self.encrypted_file_path.lower().endswith(ENCRYPTED_EXTENSION):

                    extension_dialog = ctk.CTkToplevel(self.root)
                    extension_dialog.title("Original Extension")
                    extension_dialog.geometry("400x200")
                    extension_dialog.resizable(False, False)
                    extension_dialog.transient(self.root)
                    extension_dialog.grab_set()

                    ctk.CTkLabel(
                        extension_dialog,
                        text="File metadata not found. Please enter the original file extension:",
                        wraplength=350
                    ).pack(padx=20, pady=(20, 10))

                    ext_var = tk.StringVar()
                    ext_entry = ctk.CTkEntry(extension_dialog, textvariable=ext_var)
                    ext_entry.pack(fill="x", padx=20, pady=10)

                    extension_result = [None]  

                    def set_extension():
                        ext = ext_var.get().strip()
                        if not ext.startswith("."):
                            ext = f".{ext}"
                        extension_result[0] = ext
                        extension_dialog.destroy()

                    ctk.CTkButton(
                        extension_dialog,
                        text="OK",
                        command=set_extension
                    ).pack(pady=20)

                    self.root.wait_window(extension_dialog)

                    if extension_result[0] is None:
                        return

                    original_extension = extension_result[0]
                    salt = None  
                else:
                    self.show_notification("This file doesn't appear to be encrypted with this application.", "error")
                    return

            key, _ = self.generate_key_from_password(password, salt)
            fernet = Fernet(key)

            with open(self.encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()

            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception:
                self.show_notification("Incorrect password or corrupted file", "error")
                return

            decrypted_file_path = os.path.splitext(self.encrypted_file_path)[0] + original_extension

            if os.path.exists(decrypted_file_path):
                result = messagebox.askquestion(
                    "File Exists", 
                    f"A file with this name already exists.\nDo you want to overwrite it?",
                    icon="warning"
                )
                if result != "yes":
                    return
                os.remove(decrypted_file_path)

            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            os.remove(self.encrypted_file_path)

            if file_hash in self.encrypted_files_db:
                del self.encrypted_files_db[file_hash]
                self.save_encrypted_files_db()

            decrypted_filename = os.path.basename(decrypted_file_path)
            self.decrypt_file_path_var.set("No file selected")
            self.decrypt_password_var.set("")
            self.show_notification(f"File decrypted successfully: {decrypted_filename}", "success")

            result = messagebox.askquestion(
                "Open File", 
                "Would you like to open the decrypted file?",
                icon="question"
            )

            if result == "yes":
                self.open_file(decrypted_file_path)

        except Exception as e:
            self.show_notification(f"Error during decryption: {str(e)}", "error")

    def open_file(self, file_path):
        if not file_path or not os.path.exists(file_path):
            self.show_notification("File doesn't exist", "error")
            return

        try:
            if os.name == 'nt':  
                os.startfile(file_path)
            elif os.name == 'posix':  
                if os.uname().sysname == 'Darwin':  
                    subprocess.run(['open', file_path])
                else:  
                    subprocess.run(['xdg-open', file_path])

        except Exception as e:
            self.show_notification(f"Failed to open file: {e}", "error")

    def show_notification(self, message, level="info"):
        self.status_var.set(message)

        if level == "error":
            self.status_frame.configure(fg_color=("#ffebee", "#411c1c"))
            self.status_label.configure(text_color=("#d32f2f", "#f44336"))
        elif level == "success":
            self.status_frame.configure(fg_color=("#e8f5e9", "#1c3a1c"))
            self.status_label.configure(text_color=("#2e7d32", "#4caf50"))
        elif level == "warning":
            self.status_frame.configure(fg_color=("#fff8e1", "#3a3118"))
            self.status_label.configure(text_color=("#f57c00", "#ff9800"))
        else:  
            self.status_frame.configure(fg_color=("#e3f2fd", "#1a2c3d"))
            self.status_label.configure(text_color=("#1976d2", "#2196f3"))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = FileExtensionChanger()
    app.run()
