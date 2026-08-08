; MCP Bridge — NSIS Installer
; Per-user install: %LOCALAPPDATA%\Programs\MCP Bridge (no admin required)

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "StrFunc.nsh"
${Using:StrFunc} StrStr
${UnStrRep}

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

; --- Add $INSTDIR to the user PATH (HKCU\Environment) ---
Function AddToUserPath
  ReadRegStr $0 HKCU "Environment" "Path"
  ; Drop a trailing ';' so we don't produce a double separator
  ${If} $0 != ""
    StrCpy $1 $0 1 -1
    ${If} $1 == ";"
      StrCpy $0 $0 -1
    ${EndIf}
  ${EndIf}
  ${If} $0 == ""
    WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR"
  ${Else}
    ${StrStr} $1 $0 "$INSTDIR"
    ${If} $1 == ""
      WriteRegExpandStr HKCU "Environment" "Path" "$0;$INSTDIR"
    ${EndIf}
  ${EndIf}
  ; Notify running processes (Explorer picks it up for newly launched apps).
  ; SendNotifyMessage is fire-and-forget: SendMessage broadcast can hang for
  ; minutes when any top-level window's UI thread is wedged.
  System::Call 'user32::SendNotifyMessage(i 0xFFFF, i ${WM_SETTINGCHANGE}, i 0, t "Environment")'
FunctionEnd

; --- Remove $INSTDIR from the user PATH ---
Function un.RemoveFromUserPath
  ReadRegStr $0 HKCU "Environment" "Path"
  ${If} $0 == ""
    Return
  ${EndIf}
  ${UnStrRep} $1 $0 ";$INSTDIR" ""   ; appended form
  ${If} $1 == $0
    ${UnStrRep} $1 $0 "$INSTDIR;" "" ; first-entry form
  ${EndIf}
  ${If} $1 == $0
    ${If} $0 == $INSTDIR              ; only entry
      DeleteRegValue HKCU "Environment" "Path"
      Goto notify
    ${EndIf}
    Return                            ; not present — nothing to do
  ${EndIf}
  WriteRegExpandStr HKCU "Environment" "Path" "$1"
  notify:
    System::Call 'user32::SendNotifyMessage(i 0xFFFF, i ${WM_SETTINGCHANGE}, i 0, t "Environment")'
FunctionEnd
