# scripts/setup_vm.ps1 — Create and configure the detonation VM
# Usage: powershell -ExecutionPolicy Bypass -File scripts\setup_vm.ps1 -IsoPath "C:\path\to\win7sp1.iso"

param(
    [Parameter(Mandatory=$true)]
    [string]$IsoPath,

    [string]$VMName = "Detonation-Win7",
    [string]$VMDir = "$env:USERPROFILE\VirtualBox VMs",
    [int]$RamMB = 1536,
    [int]$DiskGB = 40,
    [int]$CPUs = 1,
    [int]$VRamMB = 32
)

$VBM = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $VBM)) {
    Write-Error "VBoxManage not found. Install VirtualBox first."
    exit 1
}

if (-not (Test-Path $IsoPath)) {
    Write-Error "ISO not found at: $IsoPath"
    exit 1
}

Write-Host "[SETUP] Creating VM: $VMName" -ForegroundColor Cyan

# Create VM
& $VBM createvm --name $VMName --ostype "Windows7_64" --register --basefolder $VMDir

# Configure hardware
& $VBM modifyvm $VMName `
    --memory $RamMB `
    --cpus $CPUs `
    --vram $VRamMB `
    --graphicscontroller vboxsvga `
    --audio-driver none `
    --usb off `
    --clipboard-mode disabled `
    --drag-and-drop disabled `
    --nic1 intnet `
    --intnet1 "detonation-isolated" `
    --boot1 dvd --boot2 disk --boot3 none --boot4 none

# Create virtual disk
$DiskPath = "$VMDir\$VMName\$VMName.vdi"
& $VBM createmedium disk --filename $DiskPath --size ($DiskGB * 1024) --format VDI

# Add SATA controller and attach disk
& $VBM storagectl $VMName --name "SATA" --add sata --controller IntelAhci --portcount 2
& $VBM storageattach $VMName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $DiskPath

# Attach ISO
& $VBM storagectl $VMName --name "IDE" --add ide
& $VBM storageattach $VMName --storagectl "IDE" --port 0 --device 0 --type dvddrive --medium $IsoPath

Write-Host "[SETUP] Applying anti-detection hardening..." -ForegroundColor Yellow
$hardenScript = Join-Path $PSScriptRoot "vbox_harden.bat"
if (Test-Path $hardenScript) {
    & cmd /c $hardenScript $VMName
} else {
    Write-Warning "vbox_harden.bat not found at $hardenScript — run manually"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " VM '$VMName' created successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Start VM:  VBoxManage startvm `"$VMName`""
Write-Host "  2. Install Windows 7 SP1 from the ISO"
Write-Host "  3. Create user account: analyst / Detonate2026!"
Write-Host "  4. DO NOT install VirtualBox Guest Additions"
Write-Host "  5. Copy guest/ folder to C:\sandbox\ inside the VM"
Write-Host "  6. Copy tools (Python 3.8, Sysmon, FakeNet-NG) to C:\sandbox\tools\"
Write-Host "  7. Run C:\sandbox\install.bat"
Write-Host "  8. Run camouflage.bat to set up anti-detection"
Write-Host "  9. Run Pafish.exe to verify VM is not detectable"
Write-Host " 10. Shut down, then take snapshot:"
Write-Host "     VBoxManage snapshot `"$VMName`" take `"clean-snapshot`""
Write-Host ""
Write-Host "RAM allocation: ${RamMB}MB (leaves ~4.5GB for host)" -ForegroundColor Cyan
