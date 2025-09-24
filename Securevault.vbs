Set fso = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")

' Récupère le dossier où se trouve le .vbs
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Lance le .bat depuis le même dossier
WshShell.Run Chr(34) & scriptDir & "\SecureVault.bat" & Chr(34), 0

Set WshShell = Nothing
Set fso = Nothing
 Set fso = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")

' Récupère le dossier où se trouve le .vbs
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Lance le .bat depuis le même dossier
WshShell.Run Chr(34) & scriptDir & "\SecureVault.bat" & Chr(34), 0

Set WshShell = Nothing
Set fso = Nothing
