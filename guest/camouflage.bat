@echo off
REM guest/camouflage.bat — Runs at VM startup before agent
REM Sets up anti-detection camouflage (decoy files, mouse movement)

REM Start FakeNet-NG in background (simulates network for malware)
IF EXIST C:\sandbox\tools\fakenet\fakenet.exe (
    start /min "" C:\sandbox\tools\fakenet\fakenet.exe
    timeout /t 3 /nobreak >NUL
)

REM Start camouflage
start /min "" C:\Python37\python.exe C:\sandbox\camouflage.py
