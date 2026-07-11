@echo off
REM guest/install.bat — Run inside the Windows 7 VM after OS install
REM Prerequisites: Copy this entire guest/ folder + installers to C:\sandbox\

echo ===================================
echo  Detonation Sandbox Guest Setup
echo ===================================

REM Create directory structure
mkdir C:\sandbox\submit 2>NUL
mkdir C:\sandbox\results 2>NUL
mkdir C:\sandbox\tools 2>NUL

REM --- 1. Python 3.7 (compatible with Windows 7) ---
echo [1/6] Install Python 3.7...
REM Copy python-3.7.9-amd64.exe to C:\sandbox\tools\ before running
IF EXIST C:\sandbox\tools\python-*.exe (
    C:\sandbox\tools\python-*.exe /quiet InstallAllUsers=1 TargetDir=C:\Python37 PrependPath=1
) ELSE (
    echo SKIP: Python installer not found in C:\sandbox\tools\
)

REM --- 2. Python packages ---
echo [2/6] Install Python packages...
C:\Python37\python.exe -m pip install --no-index --find-links=C:\sandbox\tools\wheels psutil watchdog 2>NUL
IF ERRORLEVEL 1 (
    echo Trying online install...
    C:\Python37\python.exe -m pip install psutil watchdog
)

REM --- 3. Sysmon ---
echo [3/6] Install Sysmon...
IF EXIST C:\sandbox\tools\Sysmon64.exe (
    C:\sandbox\tools\Sysmon64.exe -accepteula -i C:\sandbox\sysmon_config.xml
    echo Sysmon installed with custom config
) ELSE (
    echo SKIP: Sysmon64.exe not found in C:\sandbox\tools\
)

REM --- 4. FakeNet-NG ---
echo [4/6] Setup FakeNet-NG...
IF EXIST C:\sandbox\tools\fakenet (
    echo FakeNet-NG found. To start: C:\sandbox\tools\fakenet\fakenet.exe
) ELSE (
    echo SKIP: FakeNet-NG not found in C:\sandbox\tools\fakenet\
)

REM --- 5. Disable Windows Defender / Updates (reduce noise) ---
echo [5/6] Disabling Windows Update and Defender...
sc config wuauserv start= disabled >NUL 2>&1
sc stop wuauserv >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >NUL 2>&1

REM --- 6. Set camouflage to autostart ---
echo [6/6] Configuring camouflage autostart...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Camouflage /t REG_SZ /d "C:\sandbox\camouflage.bat" /f >NUL

echo.
echo ===================================
echo  Setup complete!
echo ===================================
echo.
echo Next steps:
echo  1. Install Microsoft Office 2010/2013 (for doc/xls detonation)
echo  2. Install Adobe Reader 9 or X (for PDF detonation)
echo  3. Install 7-Zip (for archive detonation)
echo  4. Copy Pafish.exe to C:\sandbox\tools\ and run to test anti-VM
echo  5. Run camouflage.bat to populate desktop/docs
echo  6. Shut down, then take snapshot from host:
echo     VBoxManage snapshot "Detonation-Win7" take "clean-snapshot"
