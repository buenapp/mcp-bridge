; MCP Bridge — NSIS Installer
; Per-user install: %LOCALAPPDATA%\Programs\MCP Bridge (no admin required)

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"

; --- Build-time defines (override with -D on makensis command line) ---
!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef OUTFILE
  !define OUTFILE "mcp-bridge-setup.exe"
!endif

; --- General ---
Name "MCP Bridge"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\MCP Bridge"
InstallDirRegKey HKCU "Software\MCP Bridge" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma

; --- Version info embedded in the installer exe ---
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "MCP Bridge"
VIAddVersionKey "FileDescription" "MCP Bridge Installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "BSD-2-Clause"

; --- MUI settings ---
!define MUI_ICON "mcp-bridge.ico"
!define MUI_UNICON "mcp-bridge.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE

; --- Pages ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; --- Installer section ---
Section "Install"
  SetOutPath "$INSTDIR"
  File "mcp-bridge.exe"
  File /nonfatal "README.md"

  ; Registry: install dir + Add/Remove Programs entry
  WriteRegStr HKCU "Software\MCP Bridge" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "DisplayName" "MCP Bridge"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "Publisher" "The Daniel Morante Company, Inc."
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "DisplayIcon" "$INSTDIR\mcp-bridge.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge" \
    "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Add install dir to the user PATH (so clients can use "mcp-bridge.exe")
  Call AddToUserPath
SectionEnd

; --- Uninstaller ---
Section "Uninstall"
  Call un.RemoveFromUserPath

  Delete "$INSTDIR\mcp-bridge.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge"
  DeleteRegKey HKCU "Software\MCP Bridge"
SectionEnd

; --- StrStr: find needle in haystack ---
; Usage: Push "<needle>" \n Push "<haystack>" \n Call StrStr \n Pop $out ("" if not found)
Function StrStr
  Exch $R0          ; haystack
  Exch
  Exch $R1          ; needle
  Push $R2
  Push $R3
  Push $R4
  StrLen $R2 $R1    ; needle length
  StrLen $R3 $R0    ; haystack length
  ${If} $R2 == 0
    StrCpy $R0 ""
    Goto done
  ${EndIf}
  loop:
    IntCmp $R3 $R2 notfound loop loop   ; remaining < needle len -> not found
    StrCpy $R4 $R0 $R2                  ; first needle-len chars
    ${If} $R4 == $R1
      Goto done                         ; $R0 = haystack at match (non-empty)
    ${EndIf}
    StrCpy $R0 $R0 "" 1                 ; drop first char
    IntOp $R3 $R3 - 1
    Goto loop
  notfound:
    StrCpy $R0 ""
  done:
    Pop $R4
    Pop $R3
    Pop $R2
    Pop $R1
    Exch $R0
FunctionEnd

; --- un.StrRep: remove ALL occurrences of needle from haystack ---
; Usage: Push "<needle>" \n Push "<haystack>" \n Call un.StrRep \n Pop $out
Function un.StrRep
  Exch $R0          ; haystack
  Exch
  Exch $R1          ; needle
  Push $R2
  Push $R3
  Push $R4
  Push $R5
  StrCpy $R5 ""     ; result
  StrLen $R2 $R1
  StrLen $R3 $R0
  ${If} $R2 == 0
    StrCpy $R5 $R0
    Goto done
  ${EndIf}
  loop:
    IntCmp $R3 $R2 tail tail            ; remaining < needle len -> append rest
    StrCpy $R4 $R0 $R2
    ${If} $R4 == $R1
      StrCpy $R0 $R0 "" $R2             ; skip needle
      IntOp $R3 $R3 - $R2
      Goto loop
    ${EndIf}
    StrCpy $R4 $R0 1
    StrCpy $R5 "$R5$R4"
    StrCpy $R0 $R0 "" 1
    IntOp $R3 $R3 - 1
    Goto loop
  tail:
    StrCpy $R5 "$R5$R0"
  done:
    StrCpy $R0 $R5
    Pop $R5
    Pop $R4
    Pop $R3
    Pop $R2
    Pop $R1
    Exch $R0
FunctionEnd

; --- Add $INSTDIR to the user PATH (HKCU\Environment) ---
Function AddToUserPath
  ReadRegExpandStr $0 HKCU "Environment" "Path"
  ${If} $0 == ""
    WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR"
  ${Else}
    Push "$INSTDIR"
    Push $0
    Call StrStr
    Pop $1
    ${If} $1 == ""
      WriteRegExpandStr HKCU "Environment" "Path" "$0;$INSTDIR"
    ${EndIf}
  ${EndIf}
  ; Notify running processes (Explorer picks it up for newly launched apps)
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd

; --- Remove $INSTDIR from the user PATH ---
Function un.RemoveFromUserPath
  ReadRegExpandStr $0 HKCU "Environment" "Path"
  ${If} $0 == ""
    Return
  ${EndIf}
  ; Try ";$INSTDIR" (appended form)
  Push ";$INSTDIR"
  Push $0
  Call un.StrRep
  Pop $1
  ${If} $1 != $0
    WriteRegExpandStr HKCU "Environment" "Path" "$1"
    Goto notify
  ${EndIf}
  ; Try "$INSTDIR;" (was first entry)
  Push "$INSTDIR;"
  Push $0
  Call un.StrRep
  Pop $1
  ${If} $1 != $0
    WriteRegExpandStr HKCU "Environment" "Path" "$1"
    Goto notify
  ${EndIf}
  ; Only entry
  ${If} $0 == $INSTDIR
    DeleteRegValue HKCU "Environment" "Path"
  ${EndIf}
  notify:
    SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd
