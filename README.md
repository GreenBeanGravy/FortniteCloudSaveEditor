# FortniteCloudSettingsSync
A tool used to download or upload Fortnite "ClientSettings.sav" and related files directly to your Epic Games account storage. Can be used to share your settings with others, backup your settings, or apply another persons settings to your own account for the next time you launch Fortnite.

## Setup
- Open the extracted folder in command prompt and run ``pip install -r requirements.txt``
- Once complete, either directly run the ``FortniteCloudSettingsSync.py`` file or run ``py FortniteCloudSettingsSync.py`` in the same command prompt window.

## Usage
- Using the GUI, authenticate with your Epic Games account, and copy the entire JSON response you are given into the input field, and authenticate.
- You should see a list of files in your account Epic Cloud Storage. You can download these to share with others or upload your own. Technically you can upload any file to your account storage, though I'm not sure of the implications of that or the storage limits. The script automatically replaces files already in your cloud storage with the same name when you upload them.
- If you have Fortnite open, you should not be logged out by using this script.
  
