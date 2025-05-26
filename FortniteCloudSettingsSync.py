#!/usr/bin/env python3
"""
Fortnite Cloud Settings Sync Tool
Download and upload ClientSettings.sav and related files to/from Epic Games cloud storage
"""

import wx
import wx.grid
import requests
import json
import base64
import os
import threading
import re
from pathlib import Path
from typing import List, Dict, Optional
import time
import webbrowser
from urllib.parse import urlparse, parse_qs
from datetime import datetime


class EpicGamesAuth:
    """Handle Epic Games authentication"""
    
    def __init__(self):
        # Fortnite client credentials
        self.client_id = "ec684b8c687f479fadea3cb2ad83f5c6"
        self.client_secret = "e1f31c211f28413186262d37a13fc84d"
        self.access_token = None
        self.account_id = None
        self.refresh_token = None
        
    def get_auth_header(self) -> str:
        """Get base64 encoded auth header"""
        auth_string = f"{self.client_id}:{self.client_secret}"
        return base64.b64encode(auth_string.encode()).decode()
    
    def get_authorization_url(self) -> str:
        """Get the Epic Games authorization URL"""
        return "https://www.epicgames.com/id/logout?redirectUrl=https%3A//www.epicgames.com/id/login%3FredirectUrl%3Dhttps%253A//www.epicgames.com/id/api/redirect%253FclientId%253Dec684b8c687f479fadea3cb2ad83f5c6%2526responseType%253Dcode"
    
    def exchange_code_login(self, exchange_code: str) -> bool:
        """Login using authorization code"""
        url = "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token"
        
        headers = {
            "Authorization": f"basic {self.get_auth_header()}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "grant_type": "authorization_code",
            "code": exchange_code,
            "token_type": "eg1"
        }
        
        try:
            response = requests.post(url, headers=headers, data=data)
            
            if response.status_code == 200:
                result = response.json()
                self.access_token = result.get("access_token")
                self.account_id = result.get("account_id")
                self.refresh_token = result.get("refresh_token")
                
                if self.access_token and self.account_id:
                    return True, f"Authentication successful! Account ID: {self.account_id}"
                else:
                    return False, "Authentication failed: Missing token or account ID"
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('errorMessage', 'Unknown error')
                except:
                    error_msg = response.text
                return False, f"Authentication failed: {response.status_code}\nError: {error_msg}"
                
        except requests.RequestException as e:
            return False, f"Network error during authentication: {e}"
    
    def verify_token(self) -> bool:
        """Verify current access token"""
        if not self.access_token:
            return False
            
        url = "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/verify"
        headers = {"Authorization": f"bearer {self.access_token}"}
        
        try:
            response = requests.get(url, headers=headers)
            return response.status_code == 200
        except requests.RequestException:
            return False


class FortniteCloudStorage:
    """Handle Fortnite cloud storage operations"""
    
    def __init__(self, auth: EpicGamesAuth):
        self.auth = auth
        self.base_url = "https://fortnite-public-service-prod11.ol.epicgames.com"
        # Files known to have permission issues
        self.restricted_files = [
            "ClientSettingsSwitch.Sav"
        ]
        # Regular expression for UUID-pattern files that should be filtered out
        self.uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_r\d+_a\d+\.sav$', re.IGNORECASE)
        # Blacklist of file patterns to filter out
        self.blacklisted_patterns = []
        
    def list_files(self, filter_restricted=True) -> (bool, str, List[Dict]):
        """List all files in cloud storage"""
        if not self.auth.access_token or not self.auth.account_id:
            return False, "Authentication required", []
            
        url = f"{self.base_url}/fortnite/api/cloudstorage/user/{self.auth.account_id}"
        headers = {"Authorization": f"bearer {self.auth.access_token}"}
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            # Handle different response formats
            if isinstance(data, list):
                # Old format - direct array
                files = data
            elif isinstance(data, dict):
                # New format - check for common wrapper keys
                if "files" in data:
                    files = data["files"]
                elif "data" in data:
                    files = data["data"] if isinstance(data["data"], list) else [data["data"]]
                elif "items" in data:
                    files = data["items"]
                else:
                    # Single file object
                    if "uniqueFilename" in data:
                        files = [data]
                    else:
                        return True, f"Unexpected response format: {list(data.keys())}", []
            else:
                return True, f"Unexpected response type: {type(data)}", []
            
            if filter_restricted:
                # Filter out restricted files
                original_count = len(files)
                files = [f for f in files if self.is_file_allowed(f.get('uniqueFilename', ''))]
                filtered_count = original_count - len(files)
                
                if filtered_count > 0:
                    return True, f"Found {len(files)} files in cloud storage (filtered {filtered_count} restricted files)", files
            
            return True, f"Found {len(files)} files in cloud storage", files
            
        except requests.RequestException as e:
            error_msg = f"Failed to list cloud storage files: {e}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f"\nStatus: {e.response.status_code}\nResponse: {e.response.text}"
            return False, error_msg, []
    
    def is_file_allowed(self, filename):
        """Check if a file should be displayed/modified based on filters"""
        # Check explicit restricted list
        if filename in self.restricted_files:
            return False
            
        # Check UUID pattern files
        if self.uuid_pattern.match(filename):
            return False
            
        # Check custom blacklist patterns
        for pattern in self.blacklisted_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return False
                
        return True
    
    def download_file(self, unique_filename: str, local_path: str) -> (bool, str):
        """Download a file from cloud storage"""
        if not self.auth.access_token or not self.auth.account_id:
            return False, "Authentication required"
            
        # Check if file is allowed
        if not self.is_file_allowed(unique_filename):
            return False, f"File {unique_filename} is restricted and cannot be downloaded"
            
        # URL encode filename for safety
        from urllib.parse import quote
        encoded_filename = quote(unique_filename, safe='')
        url = f"{self.base_url}/fortnite/api/cloudstorage/user/{self.auth.account_id}/{encoded_filename}"
        headers = {"Authorization": f"bearer {self.auth.access_token}"}
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            # Save to local file
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            file_size = len(response.content)
            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            elif file_size > 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{size} bytes"
                
            return True, f"Downloaded {unique_filename} ({size_str})\nSaved to: {local_path}"
            
        except requests.RequestException as e:
            return False, f"Download failed: {e}"
        except IOError as e:
            return False, f"Failed to save file: {e}"
    
    def upload_file(self, local_path: str, unique_filename: str) -> (bool, str):
        """Upload a file to cloud storage (replaces existing file if same name)"""
        if not self.auth.access_token or not self.auth.account_id:
            return False, "Authentication required"
        
        if not Path(local_path).exists():
            return False, f"Local file not found: {local_path}"
            
        # Check if file is allowed
        if not self.is_file_allowed(unique_filename):
            return False, f"File {unique_filename} is restricted and cannot be modified"
            
        # URL encode filename for safety
        from urllib.parse import quote
        encoded_filename = quote(unique_filename, safe='')
        url = f"{self.base_url}/fortnite/api/cloudstorage/user/{self.auth.account_id}/{encoded_filename}"
        headers = {
            "Authorization": f"bearer {self.auth.access_token}",
            "Content-Type": "application/octet-stream"
        }
        
        try:
            # Read local file
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            elif file_size > 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size} bytes"
            
            # Check if file already exists
            file_exists = False
            for file in self.list_files(filter_restricted=False)[2]:
                if file.get('uniqueFilename') == unique_filename:
                    file_exists = True
                    break
                
            response = requests.put(url, headers=headers, data=file_data)
            response.raise_for_status()
            
            if file_exists:
                return True, f"Replaced {unique_filename} ({size_str})\nStatus: {response.status_code}"
            else:
                return True, f"Uploaded {unique_filename} ({size_str})\nStatus: {response.status_code}"
            
        except requests.RequestException as e:
            error_msg = f"Upload failed: {e}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f"\nStatus: {e.response.status_code}\nResponse: {e.response.text}"
            return False, error_msg
        except IOError as e:
            return False, f"Failed to read local file: {e}"
    
    def delete_file(self, unique_filename: str) -> (bool, str):
        """Delete a file from cloud storage"""
        if not self.auth.access_token or not self.auth.account_id:
            return False, "Authentication required"
            
        # Check if file is allowed
        if not self.is_file_allowed(unique_filename):
            return False, f"File {unique_filename} is restricted and cannot be deleted"
            
        # URL encode filename for safety
        from urllib.parse import quote
        encoded_filename = quote(unique_filename, safe='')
        url = f"{self.base_url}/fortnite/api/cloudstorage/user/{self.auth.account_id}/{encoded_filename}"
        headers = {"Authorization": f"bearer {self.auth.access_token}"}
        
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return True, f"Deleted {unique_filename}\nStatus: {response.status_code}"
            
        except requests.RequestException as e:
            error_msg = f"Deletion failed: {e}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f"\nStatus: {e.response.status_code}\nResponse: {e.response.text}"
            return False, error_msg


class FortniteCloudApp(wx.Frame):
    """Main application window"""
    
    def __init__(self):
        super().__init__(None, title="Fortnite Cloud Settings Sync", size=(800, 600))
        
        self.auth = EpicGamesAuth()
        self.cloud = FortniteCloudStorage(self.auth)
        self.cloud_files = []
        self.filter_restricted = True  # Default to filtering restricted files
        
        # Set app icon
        self.SetIcon(wx.Icon(wx.ArtProvider.GetBitmap(wx.ART_INFORMATION)))
        
        # Create UI elements
        self.create_ui()
        
        # Center window
        self.Centre()
        self.Show()
        
    def create_ui(self):
        """Create the user interface"""
        # Main panel
        panel = wx.Panel(self)
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Login section
        login_box = wx.StaticBox(panel, label="Epic Games Authentication")
        login_sizer = wx.StaticBoxSizer(login_box, wx.VERTICAL)
        
        login_btn = wx.Button(panel, label="Login with Epic Games")
        login_btn.Bind(wx.EVT_BUTTON, self.on_login)
        
        auth_code_sizer = wx.BoxSizer(wx.HORIZONTAL)
        auth_code_label = wx.StaticText(panel, label="Authorization Code:")
        self.auth_code_input = wx.TextCtrl(panel, size=(400, -1))
        auth_btn = wx.Button(panel, label="Authenticate")
        auth_btn.Bind(wx.EVT_BUTTON, self.on_authenticate)
        auth_code_sizer.Add(auth_code_label, 0, wx.ALIGN_CENTER_VERTICAL|wx.RIGHT, 5)
        auth_code_sizer.Add(self.auth_code_input, 1, wx.EXPAND)
        auth_code_sizer.Add(auth_btn, 0, wx.LEFT, 5)
        
        login_sizer.Add(wx.StaticText(panel, label="1. Click 'Login with Epic Games' to open the login page in your browser"), 0, wx.ALL, 5)
        login_sizer.Add(wx.StaticText(panel, label="2. After logging in, copy the URL or JSON response from your browser"), 0, wx.ALL, 5)
        login_sizer.Add(wx.StaticText(panel, label="3. Paste it below and click 'Authenticate'"), 0, wx.ALL, 5)
        login_sizer.Add(login_btn, 0, wx.ALL|wx.ALIGN_CENTER, 5)
        login_sizer.Add(auth_code_sizer, 0, wx.ALL|wx.EXPAND, 5)
        
        # Files section
        files_box = wx.StaticBox(panel, label="Cloud Files")
        files_sizer = wx.StaticBoxSizer(files_box, wx.VERTICAL)
        
        # Add filter checkbox
        filter_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.filter_check = wx.CheckBox(panel, label="Hide restricted files")
        self.filter_check.SetValue(self.filter_restricted)
        self.filter_check.Bind(wx.EVT_CHECKBOX, self.on_filter_toggle)
        filter_sizer.Add(self.filter_check, 0, wx.ALIGN_LEFT)
        
        # Create grid for file listing
        self.files_grid = wx.grid.Grid(panel)
        self.files_grid.CreateGrid(0, 3)
        self.files_grid.SetColLabelValue(0, "Filename")
        self.files_grid.SetColLabelValue(1, "Size")
        self.files_grid.SetColLabelValue(2, "Modified")
        self.files_grid.SetColSize(0, 400)
        self.files_grid.SetColSize(1, 100)
        self.files_grid.SetColSize(2, 200)
        self.files_grid.Bind(wx.grid.EVT_GRID_SELECT_CELL, self.on_grid_select)
        
        # Buttons for file operations
        file_buttons = wx.BoxSizer(wx.HORIZONTAL)
        
        self.refresh_btn = wx.Button(panel, label="Refresh File List")
        self.refresh_btn.Bind(wx.EVT_BUTTON, self.on_refresh_files)
        self.refresh_btn.Disable()
        
        self.download_btn = wx.Button(panel, label="Download Selected")
        self.download_btn.Bind(wx.EVT_BUTTON, self.on_download)
        self.download_btn.Disable()
        
        self.download_all_btn = wx.Button(panel, label="Download All Files")
        self.download_all_btn.Bind(wx.EVT_BUTTON, self.on_download_all)
        self.download_all_btn.Disable()
        
        self.upload_btn = wx.Button(panel, label="Upload File(s)")
        self.upload_btn.Bind(wx.EVT_BUTTON, self.on_upload)
        self.upload_btn.Disable()
        
        self.delete_btn = wx.Button(panel, label="Delete Selected")
        self.delete_btn.Bind(wx.EVT_BUTTON, self.on_delete)
        self.delete_btn.Disable()
        
        file_buttons.Add(self.refresh_btn, 0, wx.RIGHT, 5)
        file_buttons.Add(self.download_btn, 0, wx.RIGHT, 5)
        file_buttons.Add(self.download_all_btn, 0, wx.RIGHT, 5)
        file_buttons.Add(self.upload_btn, 0, wx.RIGHT, 5)
        file_buttons.Add(self.delete_btn, 0)
        
        files_sizer.Add(filter_sizer, 0, wx.ALL|wx.EXPAND, 5)
        files_sizer.Add(self.files_grid, 1, wx.ALL|wx.EXPAND, 5)
        files_sizer.Add(file_buttons, 0, wx.ALL|wx.ALIGN_RIGHT, 5)
        
        # Status area
        status_box = wx.StaticBox(panel, label="Status")
        status_sizer = wx.StaticBoxSizer(status_box, wx.VERTICAL)
        
        self.status_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE|wx.TE_READONLY|wx.HSCROLL)
        status_sizer.Add(self.status_text, 1, wx.ALL|wx.EXPAND, 5)
        
        # Assemble main layout
        main_sizer.Add(login_sizer, 0, wx.ALL|wx.EXPAND, 10)
        main_sizer.Add(files_sizer, 1, wx.LEFT|wx.RIGHT|wx.BOTTOM|wx.EXPAND, 10)
        main_sizer.Add(status_sizer, 0, wx.LEFT|wx.RIGHT|wx.BOTTOM|wx.EXPAND, 10)
        
        panel.SetSizer(main_sizer)
        main_sizer.Fit(self)
        
        # Add initial status message
        self.log_status("Ready. Please login with your Epic Games account.")
        self.log_status("Note: Uploading files will automatically replace any existing files with the same name.")
        self.log_status("Note: UUID-named files and some platform files (e.g. Switch) are restricted and filtered out by default.")
    
    def log_status(self, message):
        """Add a message to the status area"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.status_text.AppendText(f"[{timestamp}] {message}\n")
    
    def on_login(self, event):
        """Open the Epic Games login page"""
        url = self.auth.get_authorization_url()
        self.log_status("Opening Epic Games login page in your browser...")
        webbrowser.open(url)
    
    def on_filter_toggle(self, event):
        """Handle filter checkbox toggle"""
        self.filter_restricted = self.filter_check.GetValue()
        self.log_status(f"{'Hiding' if self.filter_restricted else 'Showing'} restricted files.")
        self.on_refresh_files(None)
    
    def extract_code_from_url(self, url_or_code):
        """Extract the authorization code from a URL, JSON or direct code"""
        if not url_or_code:
            return None
        
        # Check if it's JSON format
        if url_or_code.strip().startswith('{') and url_or_code.strip().endswith('}'):
            try:
                json_data = json.loads(url_or_code)
                
                # Check for authorizationCode field directly
                if "authorizationCode" in json_data and json_data["authorizationCode"]:
                    return json_data["authorizationCode"]
                
                # Check redirectUrl field
                if "redirectUrl" in json_data and "code=" in json_data["redirectUrl"]:
                    redirect_url = json_data["redirectUrl"]
                    return self.extract_code_from_url(redirect_url)
                
                return None
            except json.JSONDecodeError:
                pass  # Not valid JSON, continue with other checks
        
        # Check if it's a URL with code parameter
        if url_or_code.startswith('http'):
            try:
                parsed_url = urlparse(url_or_code)
                query_params = parse_qs(parsed_url.query)
                if 'code' in query_params:
                    return query_params['code'][0]
                return None
            except:
                return None
        
        # If it looks like a code (alphanumeric string of reasonable length), return it directly
        code_pattern = re.compile(r'^[a-zA-Z0-9]{20,40}$')
        if code_pattern.match(url_or_code.strip()):
            return url_or_code.strip()
            
        return None
    
    def on_authenticate(self, event):
        """Authenticate with Epic Games using the provided code"""
        url_or_code = self.auth_code_input.GetValue().strip()
        auth_code = self.extract_code_from_url(url_or_code)
        
        if not auth_code:
            self.log_status("❌ No authorization code found. Please check your input.")
            self.log_status("   You should paste the URL, JSON response, or the code itself.")
            return
            
        # Show the code that was extracted
        self.log_status(f"🔑 Authorization code extracted: {auth_code[:6]}...{auth_code[-4:]}")
        
        # Start authentication in a separate thread
        self.log_status("🔄 Authenticating with Epic Games...")
        auth_thread = threading.Thread(target=self.do_authenticate, args=(auth_code,))
        auth_thread.daemon = True
        auth_thread.start()
    
    def do_authenticate(self, auth_code):
        """Perform authentication in a separate thread"""
        success, message = self.auth.exchange_code_login(auth_code)
        
        # Update UI from the main thread
        wx.CallAfter(self.after_authenticate, success, message)
    
    def after_authenticate(self, success, message):
        """Handle authentication result"""
        self.log_status(message)
        
        if success:
            self.refresh_btn.Enable()
            self.upload_btn.Enable()
            self.on_refresh_files(None)  # Load files automatically
        
    def on_refresh_files(self, event):
        """Refresh the cloud files list"""
        self.log_status("🔄 Fetching cloud storage file list...")
        
        # Start file listing in a separate thread
        files_thread = threading.Thread(target=self.do_list_files)
        files_thread.daemon = True
        files_thread.start()
    
    def do_list_files(self):
        """Perform file listing in a separate thread"""
        success, message, files = self.cloud.list_files(filter_restricted=self.filter_restricted)
        
        # Update UI from the main thread
        wx.CallAfter(self.after_list_files, success, message, files)
    
    def after_list_files(self, success, message, files):
        """Handle file listing result"""
        self.log_status(message)
        
        if success and files:
            self.cloud_files = files
            self.update_files_grid(files)
            self.download_all_btn.Enable()
        else:
            self.cloud_files = []
            self.update_files_grid([])
            self.download_btn.Disable()
            self.download_all_btn.Disable()
            self.delete_btn.Disable()
    
    def format_date(self, date_str):
        """Format the date string from API response"""
        if not date_str or date_str == 'Unknown':
            return 'Unknown'
        
        try:
            # Try to parse ISO 8601 format
            if 'Z' in date_str:
                dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            else:
                dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%f')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                # Try with different format (no microseconds)
                if 'Z' in date_str:
                    dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ')
                else:
                    dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                # If parsing fails, return the original string
                return date_str
    
    def update_files_grid(self, files):
        """Update the files grid with the latest data"""
        # Clear existing data
        if self.files_grid.GetNumberRows() > 0:
            self.files_grid.DeleteRows(0, self.files_grid.GetNumberRows())
        
        # Add new rows
        self.files_grid.AppendRows(len(files))
        
        for i, file_info in enumerate(files):
            filename = file_info.get('uniqueFilename', 'Unknown')
            size = file_info.get('length', 0)
            
            # Get modified date - properly extract from different possible fields
            modified = 'Unknown'
            if 'lastModified' in file_info:
                modified = file_info['lastModified']
            elif 'uploaded' in file_info:
                modified = file_info['uploaded']
            elif 'updated' in file_info:
                modified = file_info['updated']
            elif 'dateModified' in file_info:
                modified = file_info['dateModified']
            
            # Format size
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} bytes"
            
            # Format date
            date_str = self.format_date(modified)
            
            self.files_grid.SetCellValue(i, 0, filename)
            self.files_grid.SetCellValue(i, 1, size_str)
            self.files_grid.SetCellValue(i, 2, date_str)
        
        self.files_grid.AutoSize()
    
    def on_grid_select(self, event):
        """Handle grid cell selection"""
        self.download_btn.Enable(True)
        self.delete_btn.Enable(True)
        event.Skip()
    
    def on_download(self, event):
        """Download the selected file"""
        row = self.files_grid.GetGridCursorRow()
        if row < 0 or row >= len(self.cloud_files):
            self.log_status("❌ No file selected")
            return
        
        file_info = self.cloud_files[row]
        filename = file_info.get('uniqueFilename', 'Unknown')
        
        # Ask for save location
        with wx.FileDialog(self, f"Save {filename} as", 
                          wildcard="All files (*.*)|*.*",
                          style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as fileDialog:
            
            fileDialog.SetFilename(filename)
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            
            save_path = fileDialog.GetPath()
        
        # Start download in a separate thread
        self.log_status(f"⬇️ Downloading {filename}...")
        download_thread = threading.Thread(target=self.do_download_file, args=(filename, save_path))
        download_thread.daemon = True
        download_thread.start()
    
    def on_download_all(self, event):
        """Download all files"""
        if not self.cloud_files:
            self.log_status("❌ No files available to download")
            return
        
        # Ask for directory to save files
        with wx.DirDialog(self, "Select directory to save all files",
                         style=wx.DD_DEFAULT_STYLE) as dirDialog:
            
            if dirDialog.ShowModal() == wx.ID_CANCEL:
                return
            
            save_dir = dirDialog.GetPath()
        
        # Start downloads in a separate thread
        self.log_status(f"⬇️ Starting download of all {len(self.cloud_files)} files...")
        download_thread = threading.Thread(target=self.do_download_all_files, args=(save_dir,))
        download_thread.daemon = True
        download_thread.start()
    
    def do_download_file(self, filename, save_path):
        """Perform file download in a separate thread"""
        success, message = self.cloud.download_file(filename, save_path)
        
        # Update UI from the main thread
        wx.CallAfter(self.after_download_file, success, message)
    
    def do_download_all_files(self, save_dir):
        """Download all files in a separate thread"""
        total_files = len(self.cloud_files)
        successful = 0
        failed = 0
        
        for i, file_info in enumerate(self.cloud_files):
            filename = file_info.get('uniqueFilename', f'file_{i}')
            save_path = os.path.join(save_dir, filename)
            
            wx.CallAfter(self.log_status, f"⬇️ Downloading {i+1}/{total_files}: {filename}")
            success, message = self.cloud.download_file(filename, save_path)
            
            if success:
                successful += 1
            else:
                failed += 1
                wx.CallAfter(self.log_status, f"❌ Failed to download {filename}: {message}")
        
        # Update UI from the main thread with final status
        wx.CallAfter(self.after_download_all, total_files, successful, failed)
    
    def after_download_file(self, success, message):
        """Handle download result"""
        if success:
            self.log_status(f"✅ {message}")
        else:
            self.log_status(f"❌ {message}")
    
    def after_download_all(self, total, successful, failed):
        """Handle download all result"""
        self.log_status(f"✅ Download complete: {successful}/{total} files downloaded successfully, {failed} failed")
    
    def on_upload(self, event):
        """Upload file(s) to cloud storage"""
        # Ask for file(s) to upload - modified to support multiple selection
        with wx.FileDialog(self, "Select file(s) to upload", 
                          wildcard="All files (*.*)|*.*",
                          style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE) as fileDialog:
            
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            
            # Get selected files
            paths = fileDialog.GetPaths()
            
            if not paths:
                return
                
            # Start uploads in a separate thread
            self.log_status(f"⬆️ Starting upload of {len(paths)} file(s)...")
            upload_thread = threading.Thread(target=self.do_upload_files, args=(paths,))
            upload_thread.daemon = True
            upload_thread.start()
    
    def do_upload_files(self, local_paths):
        """Upload multiple files in a separate thread"""
        total_files = len(local_paths)
        successful = 0
        failed = 0
        
        for i, local_path in enumerate(local_paths):
            # Use the basename of the local file as remote filename
            filename = os.path.basename(local_path)
            
            wx.CallAfter(self.log_status, f"⬆️ Uploading {i+1}/{total_files}: {filename}")
            
            # Check if file is allowed before attempting upload
            if not self.cloud.is_file_allowed(filename):
                wx.CallAfter(self.log_status, f"❌ Skipping restricted file: {filename}")
                failed += 1
                continue
                
            success, message = self.cloud.upload_file(local_path, filename)
            
            if success:
                successful += 1
                wx.CallAfter(self.log_status, f"✅ {message}")
            else:
                failed += 1
                wx.CallAfter(self.log_status, f"❌ {message}")
        
        # Update UI from the main thread with final status
        wx.CallAfter(self.after_upload_files, total_files, successful, failed)
    
    def after_upload_files(self, total, successful, failed):
        """Handle upload all result"""
        self.log_status(f"✅ Upload complete: {successful}/{total} files uploaded successfully, {failed} failed")
        self.on_refresh_files(None)  # Refresh the file list
    
    def on_delete(self, event):
        """Delete the selected file from cloud storage"""
        row = self.files_grid.GetGridCursorRow()
        if row < 0 or row >= len(self.cloud_files):
            self.log_status("❌ No file selected")
            return
        
        file_info = self.cloud_files[row]
        filename = file_info.get('uniqueFilename', 'Unknown')
        
        # Check if file is allowed to be deleted
        if not self.cloud.is_file_allowed(filename):
            self.log_status(f"❌ File {filename} is restricted and cannot be deleted")
            return
            
        # Ask for confirmation before deletion
        confirm_dialog = wx.MessageDialog(
            self,
            f"Are you sure you want to delete '{filename}'?\nThis action cannot be undone!",
            "Confirm Deletion",
            wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING
        )
        
        if confirm_dialog.ShowModal() != wx.ID_YES:
            confirm_dialog.Destroy()
            return
            
        confirm_dialog.Destroy()
        
        # Start deletion in a separate thread
        self.log_status(f"🗑️ Deleting {filename}...")
        delete_thread = threading.Thread(target=self.do_delete_file, args=(filename,))
        delete_thread.daemon = True
        delete_thread.start()
    
    def do_delete_file(self, filename):
        """Delete a file in a separate thread"""
        success, message = self.cloud.delete_file(filename)
        
        # Update UI from the main thread
        wx.CallAfter(self.after_delete_file, success, message)
    
    def after_delete_file(self, success, message):
        """Handle deletion result"""
        if success:
            self.log_status(f"✅ {message}")
            # Refresh file list to reflect changes
            self.on_refresh_files(None)
        else:
            self.log_status(f"❌ {message}")


if __name__ == "__main__":
    app = wx.App()
    frame = FortniteCloudApp()
    app.MainLoop()