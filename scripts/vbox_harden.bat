@echo off
REM scripts/vbox_harden.bat — Anti-VM-detection hardening for VirtualBox
REM Run AFTER creating the VM but BEFORE first boot
REM Usage: vbox_harden.bat "Detonation-Win7"

SET VM=%~1
IF "%VM%"=="" SET VM=Detonation-Win7

echo [HARDEN] Applying anti-detection to VM: %VM%

REM === 1. DMI/BIOS strings — replace VirtualBox identifiers ===
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor"        "American Megatrends Inc."
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion"       "F8"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate"   "11/12/2021"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor"  "5"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor"  "17"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor"      "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct"     "20Y3CTO1WW"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion"     "ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial"      "PF2ABC12"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU"         "LENOVO_MT_20Y3_BU_Think_FM_ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily"      "ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid"        "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor"     "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisType"       "10"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion"    "ThinkPad T14 Gen 2"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial"     "PF2ABC12"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor"       "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct"      "20Y3CTO1WW"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion"      "SDK0T76461 WIN"

REM === 2. ACPI table customization ===
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiOemId"       "LENOVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId"   "LNVO"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev"  "20160930"

REM === 3. Hide VirtualBox-specific devices ===
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber"    "WD-WMC4N0K2YPR7"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "01.01A01"
VBoxManage setextradata "%VM%" "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber"      "WDC WD10EZEX-00WN4A0"

REM === 4. MAC address — use a Dell/Lenovo OUI, NOT VirtualBox default 08:00:27 ===
VBoxManage modifyvm "%VM%" --mac-address1 "B8AEED710042"

REM === 5. Disable VirtualBox-detectable features ===
VBoxManage modifyvm "%VM%" --paravirt-provider none
VBoxManage modifyvm "%VM%" --nested-hw-virt off

REM === 6. CPU identity — hide hypervisor bit ===
VBoxManage modifyvm "%VM%" --cpu-profile "Intel Core i7-10750H"

echo [HARDEN] Anti-detection hardening applied to %VM%
echo [HARDEN] IMPORTANT: Do NOT install VirtualBox Guest Additions in this VM!
echo [HARDEN] Run Pafish inside the VM to verify hardening effectiveness.
