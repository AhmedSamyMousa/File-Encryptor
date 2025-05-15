import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import subprocess
from PIL import Image, ImageTk 
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import re 

BG_COLOR = "#09090B" 
BTNS_COLOR = "#FAFAFA" 
BTNS_HOVER_COLOR = "#E2E2E2"
ERROR_COLOR = "red"

COLOR_VERY_WEAK = ("#FF5252", "#FF5252") 
COLOR_WEAK = ("#FF9800", "#FF9800")   
COLOR_MEDIUM = ("#FFC107", "#FFC107") 
COLOR_GOOD = ("#8BC34A", "#8BC34A")   
COLOR_STRONG = ("#4CAF50", "#4CAF50") 
COLOR_DEFAULT_TEXT = ctk.ThemeManager.theme["CTkLabel"]["text_color"] 

FILE_TYPES = {
    "Image": [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp", ".svg"],
    "Video": [".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv"],
    "3D Model": [".obj", ".fbx", ".stl", ".blend", ".dae", ".gltf"],
    "Audio": [".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a"],
    "Text Document": [".txt", ".md", ".log", ".rtf", ".doc", ".docx", ".pdf", ".odt", ".tex"],
    "Spreadsheet": [".csv", ".xlsx", ".xls", ".ods"],
    "Presentation": [".ppt", ".pptx", ".odp", ".key"],
    "Archive": [".zip", ".rar", ".tar", ".gz", ".7z", ".bz2"],
    "Executable": [".exe", ".bin", ".app", ".sh", ".bat", ".msi"],
    "Code": [".py", ".js", ".html", ".css", ".java", ".c", ".cpp", ".cs", ".php", ".rb", ".swift", ".kt", ".go", ".rs"],
    "Font": [".ttf", ".otf", ".woff", ".woff2"]
}

ENCRYPTED_EXTENSION = ".encrypted"

class FileExtensionChanger:
    def __init__(self):
        self.new_file_path = ""
        self.original_file_path = ""
        self.original_extension = ""
        self.encrypted_file_path = ""

        self.app_version = "1.1.1" 
        self.encrypted_files_db = self.load_encrypted_files_db()

        self.setup_ui()

    def load_encrypted_files_db(self):
        db_path = os.path.join(os.path.expanduser("~"), ".file_encryptor_db.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Database Error", "Failed to load encrypted file database: file is corrupted or not valid JSON.")
                return {}
            except Exception as e:
                 messagebox.showerror("Database Error", f"An unexpected error occurred while loading database: {e}")
                 return {}
        return {}

    def save_encrypted_files_db(self):
        db_path = os.path.join(os.path.expanduser("~"), ".file_encryptor_db.json")
        try:
            with open(db_path, 'w') as f:
                json.dump(self.encrypted_files_db, f, indent=4) 
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to save encrypted file database: {e}")

    def create_section(self, parent, title, description=None):
        section_fg_color = ("gray92", "gray18") 

        section_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color=section_fg_color)
        section_frame.pack(fill="x", padx=0, pady=(0,12)) 

        title_label = ctk.CTkLabel(
            section_frame,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        title_label.pack(anchor="w", padx=15, pady=(15, 5 if description else 10))

        if description:
            desc_label = ctk.CTkLabel(
                section_frame,
                text=description,
                font=ctk.CTkFont(size=12),
                text_color=("gray25", "gray75"), 
                anchor="w",
                wraplength=parent.winfo_width() - 60 if parent.winfo_width() > 60 else 400 
            )
            desc_label.pack(anchor="w", fill="x", padx=15, pady=(0, 10))

        return section_frame

    def setup_ui(self):
        ctk.set_appearance_mode("Dark") 
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title(f"File Encryptor v{self.app_version}")
        self.root.geometry("540x780") 
        self.root.resizable(False, False)

        self.root.configure(fg_color=BG_COLOR)

        self.footer_frame = ctk.CTkFrame(self.root, fg_color="transparent", height=30)
        self.footer_frame.pack(side=tk.BOTTOM, fill="x", padx=15, pady=(0, 10))
        ctk.CTkLabel(self.footer_frame, text=f"v{self.app_version}", font=ctk.CTkFont(size=11), text_color=("gray50", "gray50")).pack(side="left")
        ctk.CTkLabel(
            self.footer_frame, text="⚠️ Lost password = File lost forever!",
            font=ctk.CTkFont(size=11, weight="bold"), text_color=(ERROR_COLOR, ERROR_COLOR)
        ).pack(side="right")

        self.status_frame = ctk.CTkFrame(self.root, corner_radius=8, fg_color=("gray85", "gray22")) 
        self.status_frame.pack(side=tk.BOTTOM, fill="x", padx=15, pady=(5, 5)) 
        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = ctk.CTkLabel(
            self.status_frame, textvariable=self.status_var, font=ctk.CTkFont(size=13),
            wraplength=500 
        )
        self.status_label.pack(padx=10, pady=8, anchor="w")
        self.show_notification("Ready.", "info") 

        self.content_frame = ctk.CTkScrollableFrame(self.root, corner_radius=10, fg_color="transparent") 
        self.content_frame.pack(fill="both", expand=True, padx=15, pady=(15, 0)) 

        self.header_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=10, pady=(10, 5)) 

        ctk.CTkLabel(
            self.header_frame, 
            text="File Encryptor", 
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(side="left")

        self.theme_button = ctk.CTkButton(
            self.header_frame, text="🌙", width=40, height=40,
            font=ctk.CTkFont(size=20), command=self.toggle_theme,
            fg_color=BTNS_COLOR, hover_color=BTNS_HOVER_COLOR,
            border_width=1, text_color=("#000000", "#000000") 
        )
        self.theme_button.pack(side="right", padx=(0,5))

        self.description_label = ctk.CTkLabel( 
            self.content_frame,
            text="Secure your files with strong AES-256 encryption and password protection. Remember your password!",
            font=ctk.CTkFont(size=14), text_color=("gray40", "gray60"), 
            wraplength=480 
        )
        self.description_label.pack(padx=10, pady=(0, 15), anchor="w") 
        self.root.update_idletasks() 
        self.description_label.configure(wraplength=self.content_frame.winfo_width() - 40 if self.content_frame.winfo_width() > 40 else 400)

        self.tabview = ctk.CTkTabview(self.content_frame, corner_radius=8) 
        self.tabview.pack(fill="both", expand=True, padx=10, pady=5) 
        self.encrypt_tab = self.tabview.add("Encrypt")
        self.decrypt_tab = self.tabview.add("Decrypt")

        self.setup_encrypt_tab()

        self.setup_decrypt_tab()

        self.tabview.set("Encrypt")
        self._update_file_display(None, self.file_name_label, self.file_size_label, self.file_type_label)
        self._update_file_display(None, self.decrypt_file_name_label, self.decrypt_file_size_label, self.decrypt_file_type_label, is_encrypted_selection=True)

    def setup_encrypt_tab(self):

        file_section_enc = self.create_section(
            self.encrypt_tab, 
            "1. Select File to Encrypt",
            "Choose the file you want to secure. The original file will be replaced by its encrypted version upon successful encryption."
        )

        for child in file_section_enc.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "Choose the file" in child.cget("text"):
                self.root.update_idletasks()
                child.configure(wraplength=self.encrypt_tab.winfo_width() - 60 if self.encrypt_tab.winfo_width() > 60 else 380)

        file_info_frame_enc = ctk.CTkFrame(file_section_enc, fg_color="transparent")
        file_info_frame_enc.pack(fill="x", padx=15, pady=(0, 10))
        self.file_name_label = ctk.CTkLabel(file_info_frame_enc, text="File: No file selected.", font=ctk.CTkFont(size=12), anchor="w", wraplength=380)
        self.file_name_label.pack(fill="x", pady=(5,0))
        self.file_size_label = ctk.CTkLabel(file_info_frame_enc, text="Size: ", font=ctk.CTkFont(size=12), anchor="w")
        self.file_size_label.pack(fill="x")
        self.file_type_label = ctk.CTkLabel(file_info_frame_enc, text="Type: ", font=ctk.CTkFont(size=12), anchor="w")
        self.file_type_label.pack(fill="x")
        ctk.CTkButton(
            file_section_enc, text="Browse File...", command=self.select_file, height=38, corner_radius=8,
            font=ctk.CTkFont(weight="bold"), fg_color=BTNS_COLOR, hover_color=BTNS_HOVER_COLOR, text_color="#000000"
        ).pack(fill="x", padx=15, pady=(5, 15))

        ext_section_enc = self.create_section(
            self.encrypt_tab, 
            "2. Custom Encrypted Extension (Optional)",
            f"Set a unique extension for the encrypted file (e.g., '.mydata'). If empty, '{ENCRYPTED_EXTENSION}' will be used."
        )
        for child in ext_section_enc.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "Set a unique extension" in child.cget("text"):
                self.root.update_idletasks()
                child.configure(wraplength=self.encrypt_tab.winfo_width() - 60 if self.encrypt_tab.winfo_width() > 60 else 380)

        ext_prefix_frame_enc = ctk.CTkFrame(ext_section_enc, fg_color="transparent")
        ext_prefix_frame_enc.pack(fill="x", padx=15, pady=(5, 15))
        ctk.CTkLabel(ext_prefix_frame_enc, text=".", width=10, font=ctk.CTkFont(size=16)).pack(side="left")
        self.ext_entry = ctk.CTkEntry(
            ext_prefix_frame_enc, height=38, corner_radius=8, border_width=1,
            placeholder_text="e.g., secret, data (no dot needed)", font=ctk.CTkFont(size=13)
        )
        self.ext_entry.pack(side="left", fill="x", expand=True)

        password_section_enc = self.create_section(
            self.encrypt_tab, "3. Set Encryption Password",
            "Choose a strong, unique password. This is vital for decrypting your file later."
        )
        for child in password_section_enc.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "Choose a strong" in child.cget("text"):
                self.root.update_idletasks()
                child.configure(wraplength=self.encrypt_tab.winfo_width() - 60 if self.encrypt_tab.winfo_width() > 60 else 380)

        self.password_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(
            password_section_enc, textvariable=self.password_var, height=38, corner_radius=8, border_width=1,
            placeholder_text="Enter password", font=ctk.CTkFont(size=13), show="•"
        )
        self.password_entry.pack(fill="x", padx=15, pady=(5, 10))
        self.password_entry.bind("<KeyRelease>", lambda event: self.update_password_strength_display())
        self.password_strength_label = ctk.CTkLabel(password_section_enc, text="", font=ctk.CTkFont(size=11), anchor="w")
        self.password_strength_label.pack(fill="x", padx=15, pady=(0, 5))
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ctk.CTkEntry(
            password_section_enc, textvariable=self.confirm_password_var, height=38, corner_radius=8, border_width=1,
            placeholder_text="Confirm password", font=ctk.CTkFont(size=13), show="•"
        )
        self.confirm_password_entry.pack(fill="x", padx=15, pady=(0, 10))
        self.show_password_var = tk.IntVar(value=0)
        ctk.CTkCheckBox(
            password_section_enc, text="Show password", variable=self.show_password_var,
            command=self.toggle_password_visibility, font=ctk.CTkFont(size=12)
        ).pack(padx=15, pady=(0, 15), anchor="w")

        self.encrypt_btn = ctk.CTkButton(
            self.encrypt_tab, text="🔒 Encrypt File", command=self.encrypt_file,
            height=42, corner_radius=8, font=ctk.CTkFont(size=15, weight="bold")
        )
        self.encrypt_btn.pack(fill="x", padx=10, pady=(10, 5))

    def setup_decrypt_tab(self):

        file_section_dec = self.create_section(
            self.decrypt_tab, "1. Select Encrypted File",
            "Choose a file that was previously encrypted using this application."
        )
        for child in file_section_dec.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "Choose a file that was previously" in child.cget("text"):
                self.root.update_idletasks()
                child.configure(wraplength=self.decrypt_tab.winfo_width() - 60 if self.decrypt_tab.winfo_width() > 60 else 380)

        file_info_frame_dec = ctk.CTkFrame(file_section_dec, fg_color="transparent")
        file_info_frame_dec.pack(fill="x", padx=15, pady=(0, 10))
        self.decrypt_file_name_label = ctk.CTkLabel(file_info_frame_dec, text="File: No file selected.", font=ctk.CTkFont(size=12), anchor="w", wraplength=380)
        self.decrypt_file_name_label.pack(fill="x", pady=(5,0))
        self.decrypt_file_size_label = ctk.CTkLabel(file_info_frame_dec, text="Size: ", font=ctk.CTkFont(size=12), anchor="w")
        self.decrypt_file_size_label.pack(fill="x")
        self.decrypt_file_type_label = ctk.CTkLabel(file_info_frame_dec, text="Type: ", font=ctk.CTkFont(size=12), anchor="w")
        self.decrypt_file_type_label.pack(fill="x")
        ctk.CTkButton(
            file_section_dec, text="Browse Encrypted File...", command=self.select_encrypted_file,
            height=38, corner_radius=8, font=ctk.CTkFont(weight="bold"),
            fg_color=BTNS_COLOR, hover_color=BTNS_HOVER_COLOR, text_color="#000000"
        ).pack(fill="x", padx=15, pady=(5, 15))

        password_section_dec = self.create_section(
            self.decrypt_tab, "2. Enter Decryption Password",
            "Enter the exact password used during the file's encryption."
        )
        for child in password_section_dec.winfo_children():
            if isinstance(child, ctk.CTkLabel) and "Enter the exact password" in child.cget("text"):
                self.root.update_idletasks()
                child.configure(wraplength=self.decrypt_tab.winfo_width() - 60 if self.decrypt_tab.winfo_width() > 60 else 380)

        self.decrypt_password_var = tk.StringVar()
        self.decrypt_password_entry = ctk.CTkEntry(
            password_section_dec, textvariable=self.decrypt_password_var, height=38, corner_radius=8, border_width=1,
            placeholder_text="Enter password", font=ctk.CTkFont(size=13), show="•"
        )
        self.decrypt_password_entry.pack(fill="x", padx=15, pady=(5, 10))
        self.decrypt_show_password_var = tk.IntVar(value=0)
        ctk.CTkCheckBox(
            password_section_dec, text="Show password", variable=self.decrypt_show_password_var,
            command=self.toggle_decrypt_password_visibility, font=ctk.CTkFont(size=12)
        ).pack(padx=15, pady=(0, 15), anchor="w")

        self.decrypt_btn = ctk.CTkButton(
            self.decrypt_tab, text="🔓 Decrypt File", command=self.decrypt_file,
            height=42, corner_radius=8, font=ctk.CTkFont(size=15, weight="bold")
        )
        self.decrypt_btn.pack(fill="x", padx=10, pady=(10, 5))

    def toggle_theme(self):
        current_mode = ctk.get_appearance_mode()
        new_mode = "Light" if current_mode == "Dark" else "Dark"
        ctk.set_appearance_mode(new_mode)
        self.theme_button.configure(text="☀️" if new_mode == "Light" else "🌙")

    def toggle_password_visibility(self):
        show = "" if self.show_password_var.get() else "•"
        self.password_entry.configure(show=show)
        self.confirm_password_entry.configure(show=show)

    def toggle_decrypt_password_visibility(self):
        self.decrypt_password_entry.configure(show="" if self.decrypt_show_password_var.get() else "•")

    def _format_file_size(self, size_bytes):
        if not isinstance(size_bytes, (int, float)) or size_bytes < 0: return "N/A"
        if size_bytes == 0: return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = 0
        while size_bytes >= 1024 and i < len(size_name) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.2f} {size_name[i]}"

    def _get_file_type(self, extension): 
        for type_name, extensions_list in FILE_TYPES.items():
            if extension in extensions_list:
                return type_name
        return "Generic File" if extension else "Unknown Type"

    def _update_file_display(self, file_path, name_label, size_label, type_label, is_encrypted_selection=False):
        if not file_path or not os.path.exists(file_path):
            name_text = "File: No file selected." if not is_encrypted_selection else "File: No encrypted file selected."
            name_label.configure(text=name_text)
            size_label.configure(text="Size: ")
            type_label.configure(text="Type: ")
            if is_encrypted_selection: self.encrypted_file_path = ""
            else: self.original_file_path = ""; self.original_extension = ""
            return

        try:
            filename = os.path.basename(file_path)
            filesize = os.path.getsize(file_path)
            _, extension = os.path.splitext(file_path)

            self.root.update_idletasks()
            parent_width = name_label.master.winfo_width() 
            name_label.configure(text="File: " + filename, wraplength=parent_width - 30 if parent_width > 30 else 350) 
            size_label.configure(text="Size: " + self._format_file_size(filesize))

            status_message = f"Selected: {filename}"
            if is_encrypted_selection:
                type_label.configure(text="Type: Encrypted File")
            else:
                type_label.configure(text="Type: " + self._get_file_type(extension.lower()))

            self.show_notification(status_message, "info") 

        except Exception as e:
            self.show_notification(f"Error accessing file info: {e}", "error")
            name_label.configure(text="File: Error reading file details.")
            size_label.configure(text="Size: N/A")
            type_label.configure(text="Type: N/A")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            self._update_file_display(None, self.file_name_label, self.file_size_label, self.file_type_label)
            return

        if self.is_file_encrypted(file_path) or file_path.lower().endswith(ENCRYPTED_EXTENSION):
            self.show_notification("This file appears encrypted. Use the Decrypt tab.", "warning")
            self.tabview.set("Decrypt")
            return

        self.original_file_path = file_path
        self.original_extension = os.path.splitext(file_path)[1].lower()
        self._update_file_display(file_path, self.file_name_label, self.file_size_label, self.file_type_label)

    def select_encrypted_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            self._update_file_display(None, self.decrypt_file_name_label, self.decrypt_file_size_label, self.decrypt_file_type_label, is_encrypted_selection=True)
            return

        file_ext_lower = os.path.splitext(file_path)[1].lower()
        is_known_plain_type = any(file_ext_lower in ext_list for ext_list in FILE_TYPES.values())

        if not self.is_file_encrypted(file_path) and not file_ext_lower.endswith(ENCRYPTED_EXTENSION) and is_known_plain_type:
             self.show_notification("This file doesn't seem encrypted by this app. Use Encrypt tab if needed.", "warning")
             self.tabview.set("Encrypt")
             return

        self.encrypted_file_path = file_path
        self._update_file_display(file_path, self.decrypt_file_name_label, self.decrypt_file_size_label, self.decrypt_file_type_label, is_encrypted_selection=True)

    def get_file_hash(self, file_path):
        hash_obj = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''): 
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError: return None 
        except Exception: return None

    def is_file_encrypted(self, file_path):
        file_hash = self.get_file_hash(file_path)
        return file_hash in self.encrypted_files_db if file_hash else False

    def generate_key_from_password(self, password, salt=None):
        if salt is None: salt = os.urandom(16)
        elif isinstance(salt, str): salt = base64.b64decode(salt) 

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=390000, 
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key, salt

    def check_password_strength(self, password):
        length = len(password)
        score = 0
        if not password: return {"level": "", "color": COLOR_DEFAULT_TEXT}

        if length >= 8: score += 1
        if length >= 12: score += 1
        if length >= 16: score +=1 

        if re.search(r"[a-z]", password): score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"\d", password): score += 1
        if re.search(r"[^a-zA-Z\d\s]", password): score += 1 

        if score <= 2: return {"level": "Very Weak", "color": COLOR_VERY_WEAK}
        if score <= 3: return {"level": "Weak", "color": COLOR_WEAK}
        if score <= 5: return {"level": "Medium", "color": COLOR_MEDIUM} 
        if score <= 6: return {"level": "Good", "color": COLOR_GOOD}
        return {"level": "Strong", "color": COLOR_STRONG}

    def update_password_strength_display(self):
        password = self.password_var.get()
        strength_info = self.check_password_strength(password)
        display_text = f"Strength: {strength_info['level']}" if strength_info['level'] else ""
        self.password_strength_label.configure(text=display_text, text_color=strength_info['color'])

    def encrypt_file(self):
        if not self.original_file_path:
            self.show_notification("Please select a file to encrypt.", "error")
            return

        password = self.password_var.get()
        if not password:
            self.show_notification("Password cannot be empty.", "error")
            return
        if password != self.confirm_password_var.get():
            self.show_notification("Passwords do not match.", "error")
            return

        strength_details = self.check_password_strength(password)
        if strength_details["level"] in ["Very Weak", "Weak"]:
            if not messagebox.askyesno("Weak Password", 
                f"The chosen password is {strength_details['level']}. This is not recommended.\nAre you sure you want to continue?",
                icon="warning"):
                return

        custom_ext_part = self.ext_entry.get().strip().lower()
        if custom_ext_part:
            if not re.match(r"^[a-z0-9]+$", custom_ext_part): 
                self.show_notification("Custom extension part must be lowercase letters/numbers.", "error")
                return
            if len(custom_ext_part) > 10:
                self.show_notification("Custom extension part is too long (max 10 chars).", "error")
                return
            final_extension = f".{custom_ext_part}"
            if final_extension in [item for sublist in FILE_TYPES.values() for item in sublist]:
                self.show_notification(f"Extension '{final_extension}' conflicts with known types. Choose another.", "error")
                return
        else:
            final_extension = ENCRYPTED_EXTENSION

        try:
            key, salt_bytes = self.generate_key_from_password(password) 
            fernet = Fernet(key)

            with open(self.original_file_path, 'rb') as f_in: data = f_in.read()
            encrypted_data = fernet.encrypt(data)

            base_path, _ = os.path.splitext(self.original_file_path)
            self.new_file_path = base_path + final_extension

            if os.path.exists(self.new_file_path):
                if not messagebox.askyesno("Confirm Overwrite", 
                    f"'{os.path.basename(self.new_file_path)}' already exists. Overwrite it?", icon="warning"):
                    self.show_notification("Encryption cancelled.", "info"); return
                try: os.remove(self.new_file_path)
                except Exception as e: self.show_notification(f"Error removing existing file: {e}", "error"); return

            with open(self.new_file_path, 'wb') as f_out: f_out.write(encrypted_data)

            original_mtime = os.path.getmtime(self.original_file_path)
            try: os.remove(self.original_file_path)
            except Exception as e: self.show_notification(f"Encrypted, but failed to remove original: {e}", "warning")

            new_file_hash = self.get_file_hash(self.new_file_path)
            if new_file_hash:
                self.encrypted_files_db[new_file_hash] = {
                    'original_extension': self.original_extension,
                    'salt': base64.b64encode(salt_bytes).decode('utf-8'),
                    'date_encrypted': original_mtime,
                    'custom_encrypted_extension': final_extension if final_extension != ENCRYPTED_EXTENSION else None
                }
                self.save_encrypted_files_db()

            self.show_notification(f"File encrypted: {os.path.basename(self.new_file_path)}", "success")
            self._update_file_display(None, self.file_name_label, self.file_size_label, self.file_type_label)
            self.password_var.set(""); self.confirm_password_var.set(""); self.ext_entry.delete(0, tk.END)
            self.update_password_strength_display()

        except Exception as e:
            self.show_notification(f"Encryption error: {e}", "error")
            if hasattr(self, 'new_file_path') and os.path.exists(self.new_file_path) and not new_file_hash : 
                 try: os.remove(self.new_file_path)
                 except: pass

    def decrypt_file(self):
        if not self.encrypted_file_path or not os.path.exists(self.encrypted_file_path):
            self.show_notification("Please select a valid encrypted file.", "error"); return

        password = self.decrypt_password_var.get()
        if not password: self.show_notification("Decryption password cannot be empty.", "error"); return

        try:
            file_hash = self.get_file_hash(self.encrypted_file_path)
            original_ext, salt_b64 = None, None

            if file_hash and file_hash in self.encrypted_files_db:
                metadata = self.encrypted_files_db[file_hash]
                original_ext = metadata['original_extension']
                salt_b64 = metadata['salt']
            else: 
                self.show_notification("File not in local database. Attempting manual decryption.", "warning")
                input_dialog = ctk.CTkInputDialog(
                    text="Enter original file extension (e.g., .txt, .jpg).\nNote: Decryption may fail if metadata is lost.",
                    title="Original Extension Needed"
                )
                user_input_ext = input_dialog.get_input()
                if user_input_ext is None: self.show_notification("Decryption cancelled.", "info"); return

                original_ext = user_input_ext.strip().lower()
                if not original_ext.startswith("."): original_ext = "." + original_ext

            salt_bytes = base64.b64decode(salt_b64) if salt_b64 else None
            key, _ = self.generate_key_from_password(password, salt_bytes)
            fernet = Fernet(key)

            with open(self.encrypted_file_path, 'rb') as f_in: encrypted_data = f_in.read()

            try: decrypted_data = fernet.decrypt(encrypted_data)
            except Exception: 
                self.show_notification("Decryption failed: Incorrect password or corrupted file/metadata.", "error"); return

            base_path, _ = os.path.splitext(self.encrypted_file_path)
            decrypted_file_path = base_path + original_ext

            if os.path.exists(decrypted_file_path):
                if not messagebox.askyesno("Confirm Overwrite", 
                    f"Decrypted file '{os.path.basename(decrypted_file_path)}' already exists. Overwrite?", icon="warning"):
                    self.show_notification("Decryption cancelled.", "info"); return
                try: os.remove(decrypted_file_path)
                except Exception as e: self.show_notification(f"Error removing existing decrypted file: {e}", "error"); return

            with open(decrypted_file_path, 'wb') as f_out: f_out.write(decrypted_data)

            try: os.remove(self.encrypted_file_path)
            except Exception as e: self.show_notification(f"Decrypted, but failed to remove encrypted file: {e}", "warning")

            if file_hash and file_hash in self.encrypted_files_db:
                del self.encrypted_files_db[file_hash]
                self.save_encrypted_files_db()

            self.show_notification(f"File decrypted: {os.path.basename(decrypted_file_path)}", "success")
            self._update_file_display(None, self.decrypt_file_name_label, self.decrypt_file_size_label, self.decrypt_file_type_label, is_encrypted_selection=True)
            self.decrypt_password_var.set("")

            if messagebox.askyesno("Open File", "Open the decrypted file?", icon="question"):
                self.open_file(decrypted_file_path)

        except Exception as e:
            self.show_notification(f"Decryption error: {e}", "error")

    def open_file(self, file_path):
        if not file_path or not os.path.exists(file_path):
            self.show_notification("Cannot open: File does not exist.", "error"); return
        try:
            if os.name == 'nt': os.startfile(os.path.normpath(file_path))
            elif os.name == 'posix':
                opener = 'open' if os.uname().sysname == 'Darwin' else 'xdg-open'
                subprocess.run([opener, file_path], check=True)
            else: self.show_notification(f"Unsupported OS ({os.name}) for auto-opening files.", "warning")
        except FileNotFoundError: self.show_notification(f"No application found for this file type.", "error")
        except subprocess.CalledProcessError as e: self.show_notification(f"Error opening file: {e}", "error")
        except Exception as e: self.show_notification(f"Failed to open file: {e}", "error")

    def show_notification(self, message, level="info"):
        self.status_var.set(message)
        fg, tc = None, None 
        if level == "error":   fg, tc = ("#ffebee", "#411c1c"), (ERROR_COLOR, "#FF8A80")
        elif level == "success": fg, tc = ("#e8f5e9", "#1c3a1c"), ("#2e7d32", "#AED581")
        elif level == "warning": fg, tc = ("#fff8e1", "#3a3118"), ("#f57c00", "#FFB74D")
        else:                    fg, tc = ("#e3f2fd", "#1a2c3d"), ("#1976d2", "#90CAF9") 

        self.status_frame.configure(fg_color=fg)
        self.status_label.configure(text_color=tc)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = FileExtensionChanger()
    app.run()
