$WshShell = New-Object -ComObject WScript.Shell
$Desktop  = [System.Environment]::GetFolderPath('Desktop')
$Shortcut = $WshShell.CreateShortcut("$Desktop\4eburNet GeoIP Update.lnk")
$Shortcut.TargetPath       = "cmd.exe"
$Shortcut.Arguments        = "/c ""D:\Проекты\4eburNet\geo_update_all.bat"""
$Shortcut.WorkingDirectory = "D:\Проекты\4eburNet"
$Shortcut.WindowStyle      = 1
$Shortcut.Description      = "4eburNet GeoIP: скачать, скомпилировать, запушить"

# Иконка: если есть PNG — конвертировать в ICO, иначе cmd.exe иконка
$IcoPath = "D:\Проекты\4eburNet\4eburNet.ico"
if (Test-Path $IcoPath) {
    $Shortcut.IconLocation = "$IcoPath, 0"
} else {
    $Shortcut.IconLocation = "cmd.exe, 0"
}

$Shortcut.Save()
Write-Host "Ярлык создан: $Desktop\4eburNet GeoIP Update.lnk"
