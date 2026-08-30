' ULPF 1-Click Silent Background Launcher
' Starts the ULPF Dashboard backend without popping up any command prompt window
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
ScriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = ScriptDir

WshShell.Run "cmd /c Launch_Dashboard_Silent.bat", 0, False
