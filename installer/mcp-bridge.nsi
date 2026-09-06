; MCP Bridge — NSIS Installer
; System-wide install (Program Files, machine PATH) by default, or
; per-user (%LOCALAPPDATA%, user PATH) — the mode page lets the user
; choose; "system" is pre-selected but only available with admin rights.

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "StrFunc.nsh"
!include "nsDialogs.nsh"
${Using:StrFunc} StrStr
${Using:StrFunc} StrRep
${UnStrRep}

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\MCPBridge"
!define PRODUCT_KEY "Software\MCP Bridge"
!define SYSTEM_ENV_KEY "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

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
InstallDir "$PROGRAMFILES64\MCP Bridge"
; 'highest': elevates when the invoker is an administrator, runs
; unelevated otherwise — the mode page decides the actual target.
RequestExecutionLevel highest
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
Page custom ModePageCreate ModePageLeave
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; --- Globals ---
Var InstallMode       ; "system" or "user"
Var IsAdmin           ; 1 when the invoking user has admin rights
Var LegacyDir         ; legacy per-user install dir (<=0.1.2), "" if none
Var ModeDialog
Var ModeSystemRadio
Var ModeUserRadio

; --- Init: detect admin rights; mode/INSTDIR defaults follow ---
Function .onInit
  SetRegView 64
  UserInfo::GetAccountType
  Pop $0
  StrCpy $IsAdmin 0
  ${If} $0 == "Admin"
    StrCpy $IsAdmin 1
  ${EndIf}

  ${If} $IsAdmin == 1
    StrCpy $InstallMode "system"
    ReadRegStr $INSTDIR HKLM "${PRODUCT_KEY}" "InstallDir"
    ${If} $INSTDIR == ""
      StrCpy $INSTDIR "$PROGRAMFILES64\MCP Bridge"
    ${EndIf}
  ${Else}
    StrCpy $InstallMode "user"
    ReadRegStr $INSTDIR HKCU "${PRODUCT_KEY}" "InstallDir"
    ${If} $INSTDIR == ""
      StrCpy $INSTDIR "$LOCALAPPDATA\Programs\MCP Bridge"
    ${EndIf}
  ${EndIf}
FunctionEnd

; --- Mode selection page (before the directory page) ---
Function ModePageCreate
  nsDialogs::Create 1018
  Pop $ModeDialog
  ${If} $ModeDialog == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 12u "Choose how MCP Bridge should be installed:"
  Pop $0

  ${NSD_CreateRadioButton} 8 18u 90% 12u "&System-wide (all users, default)"
  Pop $ModeSystemRadio
  ${NSD_AddStyle} $ModeSystemRadio ${WS_GROUP}
  ${NSD_CreateRadioButton} 8 34u 90% 12u "Current &user only (no admin rights needed)"
  Pop $ModeUserRadio
  ${NSD_RemoveStyle} $ModeUserRadio ${WS_GROUP}

  ${If} $IsAdmin == 1
    SendMessage $ModeSystemRadio ${BM_SETCHECK} ${BST_CHECKED} 0
    ${NSD_CreateLabel} 8 54u 90% 12u "System-wide requires administrator rights."
    Pop $0
  ${Else}
    SendMessage $ModeUserRadio ${BM_SETCHECK} ${BST_CHECKED} 0
    EnableWindow $ModeSystemRadio 0
    ${NSD_CreateLabel} 8 54u 90% 24u "System-wide is unavailable: this installer was not run with administrator rights."
    Pop $0
  ${EndIf}

  nsDialogs::Show
FunctionEnd

Function ModePageLeave
  SendMessage $ModeSystemRadio ${BM_GETCHECK} 0 0 $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $InstallMode "system"
    ; Remember a previous system install dir (sticky), else Program Files
    ReadRegStr $1 HKLM "${PRODUCT_KEY}" "InstallDir"
    ${If} $1 == ""
      StrCpy $1 "$PROGRAMFILES64\MCP Bridge"
    ${EndIf}
  ${Else}
    StrCpy $InstallMode "user"
    ReadRegStr $1 HKCU "${PRODUCT_KEY}" "InstallDir"
    ${If} $1 == ""
      StrCpy $1 "$LOCALAPPDATA\Programs\MCP Bridge"
    ${EndIf}
  ${EndIf}
  StrCpy $INSTDIR $1
FunctionEnd

; --- Legacy per-user install (<=0.1.2) cleanup -------------------------
; The old installer always landed in %LOCALAPPDATA% and left the dir on
; the user PATH. Remove its registration, its PATH entry, and its files
; so an upgrade never leaves a stale binary shadowing the new install.
Function RemoveLegacyUserInstall
  ReadRegStr $LegacyDir HKCU "${PRODUCT_KEY}" "InstallDir"
  ${If} $LegacyDir == ""
    Return
  ${EndIf}

  ; Drop the legacy dir from the user PATH (registration order: appended,
  ; first-entry, or only-entry forms).
  ReadRegStr $0 HKCU "Environment" "Path"
  ${If} $0 != ""
    ${StrRep} $1 $0 ";$LegacyDir" ""
    ${If} $1 == $0
      ${StrRep} $1 $0 "$LegacyDir;" ""
    ${EndIf}
    ${If} $1 != $0
      WriteRegExpandStr HKCU "Environment" "Path" "$1"
    ${ElseIf} $0 == $LegacyDir
      DeleteRegValue HKCU "Environment" "Path"
    ${EndIf}
  ${EndIf}

  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "${PRODUCT_KEY}"

  ; Best effort: in-use files just stay behind.
  Delete "$LegacyDir\mcp-bridge.exe"
  Delete "$LegacyDir\README.md"
  Delete "$LegacyDir\uninstall.exe"
  RMDir "$LegacyDir"
FunctionEnd

; --- Add $INSTDIR to the PATH (mode-rooted) ---
Function AddToPath
  ${If} $InstallMode == "system"
    ReadRegStr $0 HKLM "${SYSTEM_ENV_KEY}" "Path"
  ${Else}
    ReadRegStr $0 HKCU "Environment" "Path"
  ${EndIf}
  ; Drop a trailing ';' so we don't produce a double separator
  ${If} $0 != ""
    StrCpy $1 $0 1 -1
    ${If} $1 == ";"
      StrCpy $0 $0 -1
    ${EndIf}
  ${EndIf}
  ${If} $0 == ""
    Goto add
  ${EndIf}
  ${StrStr} $1 $0 "$INSTDIR"
  ${If} $1 != ""
    Return
  ${EndIf}
  StrCpy $0 "$0;$INSTDIR"
  add:
  ${If} $InstallMode == "system"
    WriteRegExpandStr HKLM "${SYSTEM_ENV_KEY}" "Path" "$0"
  ${Else}
    WriteRegExpandStr HKCU "Environment" "Path" "$0"
  ${EndIf}
FunctionEnd

; --- Installer section ---
Section "Install"
  Call RemoveLegacyUserInstall

  SetOutPath "$INSTDIR"
  File "mcp-bridge.exe"
  File /nonfatal "README.md"

  ; Registry: install dir, mode marker, Add/Remove Programs entry.
  ; The mode marker lets the uninstaller pick the right PATH root.
  ${If} $InstallMode == "system"
    WriteRegStr HKLM "${PRODUCT_KEY}" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "${PRODUCT_KEY}" "InstallMode" "system"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "MCP Bridge"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "The Daniel Morante Company, Inc."
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\mcp-bridge.exe"
    WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${Else}
    WriteRegStr HKCU "${PRODUCT_KEY}" "InstallDir" "$INSTDIR"
    WriteRegStr HKCU "${PRODUCT_KEY}" "InstallMode" "user"
    WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "MCP Bridge"
    WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "The Daniel Morante Company, Inc."
    WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\mcp-bridge.exe"
    WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  ${EndIf}

  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Add install dir to PATH so clients can use "mcp-bridge.exe"
  Call AddToPath

  ; Notify running processes (Explorer picks it up for newly launched
  ; apps). SendNotifyMessage is fire-and-forget: SendMessage broadcast can
  ; hang for minutes when any top-level window's UI thread is wedged.
  System::Call 'user32::SendNotifyMessage(i 0xFFFF, i ${WM_SETTINGCHANGE}, i 0, t "Environment")'
SectionEnd

; --- Uninstaller ---
Function un.onInit
  SetRegView 64
  ReadRegStr $InstallMode HKLM "${PRODUCT_KEY}" "InstallMode"
  ${If} $InstallMode == ""
    ReadRegStr $InstallMode HKCU "${PRODUCT_KEY}" "InstallMode"
  ${EndIf}
  ${If} $InstallMode == ""
    StrCpy $InstallMode "user"  ; legacy per-user uninstallers
  ${EndIf}
FunctionEnd

Function un.RemoveFromPath
  ${If} $InstallMode == "system"
    ReadRegStr $0 HKLM "${SYSTEM_ENV_KEY}" "Path"
  ${Else}
    ReadRegStr $0 HKCU "Environment" "Path"
  ${EndIf}
  ${If} $0 == ""
    Return
  ${EndIf}
  ${UnStrRep} $1 $0 ";$INSTDIR" ""   ; appended form
  ${If} $1 == $0
    ${UnStrRep} $1 $0 "$INSTDIR;" "" ; first-entry form
  ${EndIf}
  ${If} $1 == $0
    ${If} $0 == $INSTDIR              ; only entry
      ${If} $InstallMode == "system"
        DeleteRegValue HKLM "${SYSTEM_ENV_KEY}" "Path"
      ${Else}
        DeleteRegValue HKCU "Environment" "Path"
      ${EndIf}
      Goto notify
    ${EndIf}
    Return                            ; not present — nothing to do
  ${EndIf}
  ${If} $InstallMode == "system"
    WriteRegExpandStr HKLM "${SYSTEM_ENV_KEY}" "Path" "$1"
  ${Else}
    WriteRegExpandStr HKCU "Environment" "Path" "$1"
  ${EndIf}
  notify:
    System::Call 'user32::SendNotifyMessage(i 0xFFFF, i ${WM_SETTINGCHANGE}, i 0, t "Environment")'
FunctionEnd

Section "Uninstall"
  Call un.RemoveFromPath

  Delete "$INSTDIR\mcp-bridge.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  ${If} $InstallMode == "system"
    DeleteRegKey HKLM "${UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_KEY}"
  ${Else}
    DeleteRegKey HKCU "${UNINST_KEY}"
    DeleteRegKey HKCU "${PRODUCT_KEY}"
  ${EndIf}
SectionEnd
