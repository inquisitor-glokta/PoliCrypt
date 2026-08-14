; ============================================================
; PoliCrypt Installer
; ============================================================

[Setup]

; ------------------------------------------------------------
; Application
; ------------------------------------------------------------

AppId={{8B4E4E6D-5F6A-4D9D-9C9D-8A8C7A6F1234}
AppName=PoliCrypt
AppVersion=1.0.0
AppPublisher=Šamec Uglješa

; ------------------------------------------------------------
; Installation directory
; ------------------------------------------------------------

DefaultDirName={pf64}\PoliCrypt
DefaultGroupName=PoliCrypt

; ------------------------------------------------------------
; Installer output
; ------------------------------------------------------------

OutputDir=installer
OutputBaseFilename=PoliCrypt_Setup

; ------------------------------------------------------------
; Compression
; ------------------------------------------------------------

Compression=lzma
SolidCompression=yes

; ------------------------------------------------------------
; Administrator privileges
; ------------------------------------------------------------

PrivilegesRequired=admin

; ------------------------------------------------------------
; 64-bit Windows
; ------------------------------------------------------------

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; ------------------------------------------------------------
; Installer appearance
; ------------------------------------------------------------

WizardStyle=modern
SetupIconFile=PoliCrypt.ico

; ------------------------------------------------------------
; Uninstaller
; ------------------------------------------------------------

Uninstallable=yes
UninstallDisplayName=PoliCrypt
UninstallDisplayIcon={app}\PoliCrypt.ico


; ============================================================
; FILES
; ============================================================

[Files]

; PoliCrypt application
Source: "PoliCrypt.exe"; \
    DestDir: "{app}"; \
    Flags: ignoreversion

; PoliCrypt icon
Source: "PoliCrypt.ico"; \
    DestDir: "{app}"; \
    Flags: ignoreversion


; ============================================================
; SHORTCUTS
; ============================================================

[Icons]

; Desktop shortcut
Name: "{autodesktop}\PoliCrypt"; \
    Filename: "{app}\PoliCrypt.exe"; \
    WorkingDir: "{app}"; \
    IconFilename: "{app}\PoliCrypt.ico"

; Start Menu shortcut
Name: "{group}\PoliCrypt"; \
    Filename: "{app}\PoliCrypt.exe"; \
    WorkingDir: "{app}"; \
    IconFilename: "{app}\PoliCrypt.ico"

; Start Menu uninstall shortcut
Name: "{group}\Uninstall PoliCrypt"; \
    Filename: "{uninstallexe}"


; ============================================================
; RUN AFTER INSTALLATION
; ============================================================

[Run]

Filename: "{app}\PoliCrypt.exe"; \
    Description: "Pokreni PoliCrypt"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent