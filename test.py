import os
import pickle
import time
import random
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import io
import logging
import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip

# Thiết lập logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Định nghĩa phạm vi truy cập Google Drive
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# File lưu trữ danh sách video đã upload
VIDEO_LIST_FILE = 'uploaded_videos.json'

class GoogleDriveVideoManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Google Drive Video Manager")
        self.root.geometry("700x800")
        
        # Sử dụng theme ttkbootstrap
        self.style = ttk.Style('flatly')
        
        # Biến lưu trữ service
        self.service = None
        
        # Tạo giao diện
        self.create_widgets()
        
        # Load danh sách video đã upload
        self.load_video_list()
        
        # Khởi tạo Google Drive service
        self.init_drive_service()
    
    def create_widgets(self):
        # Frame chính
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Tiêu đề
        title_label = ttk.Label(
            main_frame, 
            text="Google Drive Video Manager",
            font=("Helvetica", 20, "bold"),
            bootstyle=PRIMARY
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 30))
        
        # Frame Upload
        upload_frame = ttk.LabelFrame(
            main_frame, 
            text="Upload Video", 
            padding="15",
            bootstyle=INFO
        )
        upload_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        
        # Chọn file
        self.file_path_var = tk.StringVar()
        ttk.Label(
            upload_frame, 
            text="Select Video File:",
            font=("Helvetica", 10)
        ).grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        file_frame = ttk.Frame(upload_frame)
        file_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.file_entry = ttk.Entry(
            file_frame, 
            textvariable=self.file_path_var, 
            width=50,
            bootstyle=SECONDARY
        )
        self.file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        select_btn = ttk.Button(
            file_frame, 
            text="Browse",
            command=self.select_file,
            bootstyle=(INFO, OUTLINE),
            width=10
        )
        select_btn.grid(row=0, column=1)
        ToolTip(select_btn, text="Choose a video file to upload")
        
        # Nút upload
        self.upload_btn = ttk.Button(
            upload_frame, 
            text="Upload Video",
            command=self.upload_video,
            bootstyle=SUCCESS,
            width=15
        )
        self.upload_btn.grid(row=2, column=0, columnspan=2, pady=15)
        ToolTip(self.upload_btn, text="Upload selected video to Google Drive")
        
        # Progress bar cho upload
        self.upload_progress = ttk.Progressbar(
            upload_frame, 
            mode='indeterminate',
            bootstyle=SUCCESS
        )
        self.upload_progress.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Frame Download
        download_frame = ttk.LabelFrame(
            main_frame, 
            text="Download Video", 
            padding="15",
            bootstyle=INFO
        )
        download_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        
        # Danh sách video
        ttk.Label(
            download_frame, 
            text="Select Video to Download:",
            font=("Helvetica", 10)
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Listbox với scrollbar
        list_frame = ttk.Frame(download_frame)
        list_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.video_listbox = tk.Listbox(
            list_frame, 
            height=10,
            font=("Helvetica", 10),
            selectmode=tk.SINGLE,
            relief="flat",
            bd=1
        )
        self.video_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        scrollbar = ttk.Scrollbar(
            list_frame, 
            orient="vertical", 
            command=self.video_listbox.yview,
            bootstyle=SECONDARY
        )
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.video_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Nút download
        self.download_btn = ttk.Button(
            download_frame, 
            text="Download Video",
            command=self.download_video,
            bootstyle=PRIMARY,
            width=15
        )
        self.download_btn.grid(row=2, column=0, columnspan=2, pady=15)
        ToolTip(self.download_btn, text="Download selected video from Google Drive")
        
        # Progress bar cho download
        self.download_progress = ttk.Progressbar(
            download_frame, 
            mode='determinate',
            bootstyle=PRIMARY
        )
        self.download_progress.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(
            main_frame, 
            text="Ready", 
            bootstyle=SUCCESS,
            font=("Helvetica", 10)
        )
        self.status_label.grid(row=3, column=0, columnspan=2, pady=20)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        file_frame.columnconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        download_frame.columnconfigure(0, weight=1)
        download_frame.columnconfigure(1, weight=1)
    
    def init_drive_service(self):
        """Khởi tạo Google Drive service"""
        try:
            self.service = self.get_gdrive_service()
            self.status_label.config(text="Connected to Google Drive", bootstyle=SUCCESS)
        except Exception as e:
            self.status_label.config(text=f"Google Drive connection error: {str(e)}", bootstyle=DANGER)
            logging.error(f"Drive service initialization error: {e}")
    
    def get_gdrive_service(self):
        """Xác thực OAuth 2.0 và tạo service Google Drive"""
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        return build('drive', 'v3', credentials=creds)
    
    def select_file(self):
        """Chọn file video"""
        file_path = filedialog.askopenfilename(
            title="Select Video File",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mkv *.mov *.wmv *.flv"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def encrypt_file(self, file_path, key):
        """Mã hóa file bằng AES-CBC"""
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        with open(file_path, 'rb') as f:
            data = f.read()
        data_padded = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(data_padded)
        return iv, ciphertext
    
    def decrypt_file(self, iv, ciphertext, key):
        """Giải mã file bằng AES-CBC"""
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data_padded = cipher.decrypt(ciphertext)
            data = unpad(data_padded, AES.block_size)
            return data
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            return None
    
    def upload_to_drive(self, file_path, file_name):
        """Upload file lên Google Drive"""
        file_metadata = {'name': file_name}
        media = MediaFileUpload(file_path, mimetype='application/octet-stream')
        file = self.service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        return file.get('id')
    
    def download_from_drive(self, file_id, output_file, progress_callback=None):
        """Tải file từ Google Drive với retry mechanism"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Mô phỏng lỗi mạng
                if random.random() < 0.1:
                    logging.warning("Simulated error: Packet loss!")
                    raise Exception("Packet loss")
                
                request = self.service.files().get_media(fileId=file_id)
                fh = io.FileIO(output_file, 'wb')
                downloader = MediaIoBaseDownload(fh, request)
                
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                    if progress_callback:
                        progress_callback(int(status.progress() * 100))
                
                logging.info("File download successful!")
                return True
            
            except Exception as e:
                retry_count += 1
                logging.error(f"Download error (attempt {retry_count}/{max_retries}): {e}")
                if retry_count < max_retries:
                    logging.info("Retrying in 2 seconds...")
                    time.sleep(2)
                else:
                    logging.error("Max retries reached. Download failed!")
                    return False
    
    def load_video_list(self):
        """Load danh sách video đã upload"""
        try:
            if os.path.exists(VIDEO_LIST_FILE):
                with open(VIDEO_LIST_FILE, 'r', encoding='utf-8') as f:
                    self.video_list = json.load(f)
            else:
                self.video_list = {}
            self.update_video_listbox()
        except Exception as e:
            logging.error(f"Error loading video list: {e}")
            self.video_list = {}
    
    def save_video_list(self):
        """Lưu danh sách video đã upload"""
        try:
            with open(VIDEO_LIST_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.video_list, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.error(f"Error saving video list: {e}")
    
    def update_video_listbox(self):
        """Cập nhật listbox với danh sách video"""
        self.video_listbox.delete(0, tk.END)
        for video_name in self.video_list.keys():
            self.video_listbox.insert(tk.END, video_name)
    
    def upload_video(self):
        """Upload video được chọn"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a video file!")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File does not exist!")
            return
        
        if not self.service:
            messagebox.showerror("Error", "Not connected to Google Drive!")
            return
        
        # Chạy upload trong thread riêng
        self.upload_btn.config(state='disabled')
        self.upload_progress.start()
        self.status_label.config(text="Uploading...", bootstyle=INFO)
        
        thread = threading.Thread(target=self._upload_thread, args=(file_path,))
        thread.daemon = True
        thread.start()
    
    def _upload_thread(self, file_path):
        """Thread function cho upload"""
        try:
            # Tạo khóa mã hóa
            key = os.urandom(32)
            
            # Mã hóa file
            iv, ciphertext = self.encrypt_file(file_path, key)
            
            # Tạo file mã hóa tạm thời
            encrypted_file = 'temp_encrypted.bin'
            with open(encrypted_file, 'wb') as f:
                f.write(iv + ciphertext)
            
            # Upload lên Google Drive
            file_id = self.upload_to_drive(encrypted_file, 'encrypted_video.bin')
            
            # Lưu thông tin video
            video_name = os.path.basename(file_path)
            self.video_list[f"{video_name} (ID: {file_id})"] = {
                'file_id': file_id,
                'key': base64.b64encode(key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'original_name': video_name
            }
            
            # Lưu danh sách video
            self.save_video_list()
            
            # Cập nhật giao diện
            self.root.after(0, self._upload_complete, video_name, file_id)
            
            # Xóa file tạm
            os.remove(encrypted_file)
            
        except Exception as e:
            self.root.after(0, self._upload_error, str(e))
    
    def _upload_complete(self, video_name, file_id):
        """Hoàn thành upload"""
        self.upload_progress.stop()
        self.upload_btn.config(state='normal')
        self.status_label.config(text=f"Uploaded successfully: {video_name}", bootstyle=SUCCESS)
        self.update_video_listbox()
        messagebox.showinfo("Success", f"Upload successful!\nVideo: {video_name}\nID: {file_id}")
    
    def _upload_error(self, error_msg):
        """Lỗi upload"""
        self.upload_progress.stop()
        self.upload_btn.config(state='normal')
        self.status_label.config(text=f"Upload error: {error_msg}", bootstyle=DANGER)
        messagebox.showerror("Error", f"Upload failed: {error_msg}")
    
    def download_video(self):
        """Download video được chọn"""
        selection = self.video_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a video to download!")
            return
        
        video_key = self.video_listbox.get(selection[0])
        video_info = self.video_list.get(video_key)
        
        if not video_info:
            messagebox.showerror("Error", "Video information not found!")
            return
        
        # Chọn nơi lưu file
        output_file = filedialog.asksaveasfilename(
            title="Save Video",
            defaultextension=".mp4",
            initialfile=video_info['original_name'],
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mkv *.mov *.wmv *.flv"),
                ("All files", "*.*")
            ]
        )
        
        if not output_file:
            return
        
        # Chạy download trong thread riêng
        self.download_btn.config(state='disabled')
        self.download_progress['value'] = 0
        self.status_label.config(text="Downloading...", bootstyle=INFO)
        
        thread = threading.Thread(target=self._download_thread, args=(video_info, output_file))
        thread.daemon = True
        thread.start()
    
    def _download_thread(self, video_info, output_file):
        """Thread function cho download"""
        try:
            encrypted_file = 'temp_download.bin'
            
            # Callback để cập nhật progress bar
            def progress_callback(progress):
                self.root.after(0, lambda: self.download_progress.config(value=progress))
            
            # Download file từ Google Drive
            if self.download_from_drive(video_info['file_id'], encrypted_file, progress_callback):
                # Đọc file mã hóa
                with open(encrypted_file, 'rb') as f:
                    data = f.read()
                    iv_read = data[:16]
                    ciphertext = data[16:]
                
                # Giải mã
                key = base64.b64encode(video_info['key']).decode()
                iv = base64.b64encode(video_info['iv']).decode()
                
                # Kiểm tra IV
                if iv_read != iv:
                    raise Exception("IV mismatch! File may be corrupted.")
                
                decrypted_data = self.decrypt_file(iv, ciphertext, key)
                if decrypted_data:
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_data)
                    
                    self.root.after(0, self._download_complete, output_file)
                else:
                    raise Exception("Decryption failed!")
                
                # Xóa file tạm
                os.remove(encrypted_file)
            else:
                raise Exception("Failed to download file from Google Drive!")
            
        except Exception as e:
            self.root.after(0, self._download_error, str(e))
    
    def _download_complete(self, output_file):
        """Hoàn thành download"""
        self.download_btn.config(state='normal')
        self.download_progress['value'] = 100
        self.status_label.config(text=f"Downloaded successfully: {os.path.basename(output_file)}", bootstyle=SUCCESS)
        messagebox.showinfo("Success", f"Download successful!\nFile saved at: {output_file}")
    
    def _download_error(self, error_msg):
        """Lỗi download"""
        self.download_btn.config(state='normal')
        self.download_progress['value'] = 0
        self.status_label.config(text=f"Download error: {error_msg}", bootstyle=DANGER)
        messagebox.showerror("Error", f"Download failed: {error_msg}")

def main():
    root = ttk.Window(themename="flatly")
    app = GoogleDriveVideoManager(root)
    root.mainloop()

if __name__ == '__main__':
    main()