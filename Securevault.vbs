Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & WScript.ScriptFullName & "\..\SecureVault.bat" & Chr(34), 0
Set WshShell = Nothing
