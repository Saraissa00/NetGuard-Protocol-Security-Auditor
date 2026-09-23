Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
shell.Run "python web.py", 1, False
WScript.Sleep 2500
shell.Run "http://localhost:5000", 0, False
