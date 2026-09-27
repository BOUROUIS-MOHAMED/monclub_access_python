' MonClub Access watchdog - hidden launcher.
'
' The scheduled task runs this file with wscript.exe so that NO window ever
' appears on the front-desk screen. Starting powershell.exe directly makes
' Windows draw a console window before PowerShell has read -WindowStyle Hidden,
' so a black window flashes at every check.
'
' wscript.exe has no console of its own, and PowerShell is started below with
' window style 0 (hidden), so its console is created hidden and never drawn.
'
' Usage:
'   wscript.exe //B //Nologo monclub_access_watchdog_hidden.vbs <script.ps1> [args...]
' Every argument after the script is passed on to it. Arguments that do not
' start with "-" are quoted, so paths with spaces work.
'
' Exit code: the PowerShell script's own exit code (99 if no script was given).
Option Explicit

Dim sh, psExe, cmd, i, a

If WScript.Arguments.Count < 1 Then
    WScript.Quit 99
End If

Set sh = CreateObject("WScript.Shell")
psExe = sh.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"

cmd = Quote(psExe) & " -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " & Quote(WScript.Arguments(0))
For i = 1 To WScript.Arguments.Count - 1
    a = WScript.Arguments(i)
    If Left(a, 1) = "-" Then
        cmd = cmd & " " & a
    Else
        cmd = cmd & " " & Quote(a)
    End If
Next

' 0 = hidden window. True = wait, so the task stays "Running" while the check
' runs and reports the check's real exit code.
WScript.Quit sh.Run(cmd, 0, True)

Function Quote(s)
    ' Backslashes right before the closing quote must be doubled, or PowerShell
    ' reads "C:\folder\" as an escaped quote and swallows the rest of the line.
    Dim n
    n = 0
    Do While n < Len(s)
        If Mid(s, Len(s) - n, 1) <> "\" Then Exit Do
        n = n + 1
    Loop
    Quote = """" & s & String(n, "\") & """"
End Function
