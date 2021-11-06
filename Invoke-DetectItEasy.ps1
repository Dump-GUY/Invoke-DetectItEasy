<#
.SYNOPSIS
Author: Dump-GUY (@vinopaljiri)
Credits: @horsicq - Author of Detect-It-Easy tool
Required Version of Detect-It-Easy >= 3.03
Invoke-DetectItEasy is a wrapper for excellent tool called Detect-It-Easy. This PS module is very useful for Threat Hunting and Forensics.
It could be also used to simply sort your malware repo.
Sometimes we just need to find anything suspicious so we must to detect it on system or sort files offline on mounted acquired image. 
This tool already served well in many forensic related cases/incidents.

.DESCRIPTION
Invoke-DetectItEasy enables you to process any output further and pipe it to other command.
It enables you to scan folder-recursive or file. With all output you can work as with objects.
It is as good as DIE so it enables you to process files with whole output or you can select only specified Packer you want to detect.
You can also detect only Packed files based on their entropy.
Big feature is added - Detection of PE32/PE64 without VALID Digital signatures where the output will contain also reason (example. "HashMismatch", NotSigned)
Another advantage of detection VALID Digital signatures is that powershell is able to read also Catalog files.
Example: When we detect files packed with Themida and with Digital Signature result as "HashMismatch" it should be our point of interest.

.PARAMETER PathToScan
Mandatory parameter.
Specifies the System Path to scan. It could be path to single File or Folder. Folder will be scanned recursively.

.PARAMETER PathToDiec
Optional parameter.
System Path to diec.exe tool - console version of Detect-It-Easy.
If powershell is running from the location of diec.exe - this parameter could be ignored otherwise specify this parameter.

.PARAMETER Detection
Optional parameter.
Specifies Packer or Protection etc.. We want to detect. All possible values are already set-predefined.
This parameter could be combined with others (example. with DetectNotValidSignature)

.PARAMETER DetectNotValidSignature
Optional parameter.
This parameter detects only PE32/PE64 without VALID Digital signatures where the output containing also reason (example. "HashMismatch", NotSigned) will be returned.
This parameter could be combined with others.

.PARAMETER DeepScan
This parameter enables to scan files with DeepScan feature of Detect-It-Easy.
This parameter could be combined with others.

.PARAMETER DetectPacked
Optional parameter.
This parameter specifies that only detected Packed files based on their entropy will be returned. 
This parameter can NOT be combined with others.
Returned objects contains filepath, status, entropy

.EXAMPLE
PS> Import-Module .\Invoke-DetectItEasy.ps1
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles' -Detection VMProtect -PathToDiec "C:\die_win64_portable\diec.exe" -DetectNotValidSignature -DeepScan
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles\malware.exe' -DetectNotValidSignature
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles' -PathToDiec "C:\die_win64_portable\diec.exe" -DetectPacked
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles' -PathToDiec "C:\die_win64_portable\diec.exe"
PS> Invoke-DetectItEasy -PathToScan 'C:\PEs ccc\' -PathToDiec "C:\die_win64_portable\diec.exe" -Detection VMProtect -DetectNotValidSignature | Select-Object -Property filepath, SignatureStatus
PS> Invoke-DetectItEasy -PathToScan 'C:\PEs ccc' -PathToDiec "C:\die_win64_portable\diec.exe" -DetectPacked | ?{$_.total -ge 7}
PS> (Invoke-DetectItEasy -PathToScan "C:\PEs ccc" -DetectNotValidSignature -PathToDiec "C:\die_win64_portable\diec.exe").filepath | %{Invoke-DetectItEasy -PathToScan $_ -PathToDiec "C:\die_win64_portable\diec.exe" -DetectPacked}

.LINK
https://github.com/Dump-GUY/Invoke-DetectItEasy
https://youtu.be/O8o0txFtrfQ
https://github.com/horsicq/Detect-It-Easy
#>
function Invoke-DetectItEasy
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PathToScan,

        [Parameter(Mandatory=$false)]
        [ValidateSet('12Ghosts Zip2', '32Lite', '7-Zip', '7-Zip', 'Aase Crypter', 'Abbyy Lingvo', 'ABC Cryptor', 'ACCAStore', 'AcidCrypt', 'ACProtect', 'Acronis installer', 'Active Delivery', 'ActiveMARK', 'Actual Installer', 'Adept Protector', 'Adobe Flash Player installer', 'Adobe FlashPlayer downloader', 'Adobe', 'ADS Self Extractor', 'Advanced BAT to EXE Converter', 'Advanced Installer', 'Adveractive', 'Aeco Systems installer', 'Agile .NET', 'AHpacker', 'AHTeam EP Protector', 'Alchemy Mindworks installer', 'Alex Protector', 'Alloy', 'ANDpakk', 'Anskya Binder', 'Anskya NTPacker Generator', 'Anslym Crypter', 'Anticrack Software Protector', 'AntiDote', 'AOLSetup', 'aPack', 'Apex-c', 'App Encryptor', 'AR Crypt Private', 'ARJSFX', 'ARM Protector', 'Armadillo', 'ARQ', 'ASDPack', 'ASPack', 'ASPR Stripper', 'ASProtect', 'ass-crypter', 'AssemblyInvoke', 'Astrum', 'AT4RE Protector', 'Autodesk Self-Extract', 'AutoIt', 'AutoPlay Media Studio', 'avast! Antivirus installer', 'AverCryptor', 'AZProtect', 'Babel .NET', 'bambam', 'Bat to Exe', 'beria', 'Berio', 'BeRo Tiny Pascal', 'BeRo', 'BitRock Installer', 'BitShape PE Crypt', 'Blade Joiner', 'BlindSpot', 'Blizzard PrePatch', 'BobPack', 'BopCrypt', 'Borland C++', 'Box Stub', 'Break Into Pattern', 'BulletProofSoft installer', 'Bytessence Install Maker', 'Microsoft Cabinet', 'Cameyo', 'CDS SS', 'Celesty File Binder', 'CExe', 'Chaos Software installer', 'Chilkat ZIP Self-Extractor', 'CICompress', 'CipherWall', 'ClickTeam', 'CliSecure', 'Code Virtualizer', 'Code-Lock', 'CodeCrypt', 'CodeCrypter', 'CodeFusion Wizard', 'Codegear Installer', 'CodeSafe', 'CodeVeil', 'CodeWall', 'CoffeeCup', 'Confuser', 'ConfuserEx', 'CopyMinder', 'CreateInstall', 'Crinkler', 'Crunch', 'CrypKey Installer', 'CrypKey', 'Cryptect', 'Crypter', 'Cryptic', 'Crypto Obfuscator For .Net', 'CrypToCrack Pe Protector', "CSDD's installer", 'Cygwin32', 'CZ installer', 'Daemon Protect', 'DalKrypt', 'DBPE', 'DCrypt Private', 'DeepSea', 'DEF', 'Borland Delphi', 'DelZip', 'Denuvo protector', 'dePack', 'DeployMaster', 'DesktopX Installer', 'Dimd', 'Ding Boys PE-lock Phantasm', 'DirTy CrYpt0r', 'distutils installer', 'DJoin', 'DNGuard', 'Dolphin Virtual Machine', 'DotFix NiceProtect', 'Dotfuscator', 'DragonArmor', 'Eutron SmartKey dongle reference', 'Hardlock dongle reference', 'HASP dongle reference', 'Key-Lok II dongle reference', 'MARX Crypto-Box dongle reference', 'Matrix Hardware Lock dongle reference', 'NetHASP dongle reference', 'Novex/Guardant dongle reference', 'Reprise License Manager (RLM)', 'Rockey4 dongle reference', 'SenseLock dongle reference', 'Rainbow Sentinel dongle reference', 'Sentinel SuperPro dongle reference', 'Sentinel SuperPro', 'SoftLok dongle reference', 'Unikey/Activator dongle reference', 'WIBU Key dongle reference', 'Wizzkey dongle reference', 'Duals eXe Encryptor', "dUP diablo2oo2's Universal Patcher", 'DxPack', 'DYAMAR', 'DZA Patcher', 'Eazfuscator', 'ElecKey', 'Embed PE', 'EncryptPE', 'Enigma Installer', 'Enigma Virtual Box', 'ENIGMA', 'Envoy Packager', 'EP', 'EP:MPRESS', 'EP:Microsoft C/C++', 'EP:Microsoft Visual C/C++', 'Escargot', 'Eschalon Installer', 'Excelsior Installer', 'Excelsior JET', 'Exe Guarder', 'Exe Locker', 'ExE Pack', 'EXE Password Protector', 'Exe Shield', 'Exe32Pack', 'EXECrypt', 'EXECryptor', 'EXEFog', 'ExeJoiner', 'EXERefactor', 'ExeSafeguard', 'ExeSmasher', 'ExeSplitter', 'ExeStealth', 'eXPressor', 'ezip', 'FakeNinja', 'FASM', 'FDM Installer', 'FileSplit Self-Merger', 'FISH .NET', 'Fish PE', 'FishPE Shield', 'FixupPak', 'FlashBack Protector', 'Flash Player', 'Fly-Crypter', 'Fox Pro', 'Free Basic', 'Free Pascal', 'FreeCryptor', 'FreeJoiner', 'FSG', 'Fuck n Joy', 'Fusion', 'G!X Protector', 'GameGuard', 'gcc', 'Gentee Installer', 'Ghost Installer', 'GkSetup SFX', 'Go', "Goat's PE Mutilator", 'Goliath', 'GPInstall', 'Gremlin Software Patcher/Updater', 'GSplit Self-Uniting', 'Guardant Stealth', 'GZip', 'HackShield', 'Hamrick Software - VueScan Installer', 'HASP HL/SRM Protection', 'HASP Protection', 'Hide&Protect', 'HidePE by BGCorp', 'hmimys PE-Pack', 'hmimys Protect', 'HTML executable', 'I-D Media installer', 'ICrypt', 'ID Application Protector(NoNamePacker)', 'Internet Download Manager Installer', 'ILUCRYPT', 'IMPostor Pack', 'INCrypter', 'INFTool', 'Inno Setup Module', 'inPEct', 'Inquartos Obfuscator', 'Instalit', 'Install Factory', 'Install4j Installer', 'InstallAnywhere', 'InstallShield', 'InstallUs', 'Intel C/C++ Compiler', 'IntelliProtector', 'INTENIUM install system', 'iPB Protect', 'IProtect', 'Jar2Exe', 'java', 'JDPack', 'KByS Packer', 'K!Cryptor', 'Keygen', 'KGCrypt', 'kkrunchy', 'k.kryptor', 'KoiVM', 'Konekt Protector', 'Krypton', 'Kryptonit', 'KRZIP', 'Lahey Fortran 90', 'LameCrypt', 'LARP', 'Laserlok', 'LCC-Win32', 'LCL', 'SafeNet Sentinel LDK', 'LucasArts Update Installer', 'Lyme SFX', 'MaskPE', 'MASM', 'Maxtocode', 'Metrowerks CodeWarrior', 'MEW', 'MFC', 'MicroJoiner', 'Microsoft Class Installer for Java', 'Microsoft Compound-based installer (MSI)', 'Microsoft dotNet installer', 'Microsoft Visual Basic', 'MiKTeX Installer', 'MinGW', 'Minke', 'Mioplanet installer', 'mkfPack', 'MoleBox', 'Morphine', 'Morphnah', 'Morton Software installer', 'MP-ZipTool SFX32', 'mPack', 'MPQ', 'MPRESS', 'MSLRH', 'muckis protector', 'Multimedia Fusion Installer', 'MZ-Crypt', 'MZ0oPE', 'N-Code', 'N-Joiner', 'N-Joy', 'NakedPacker', 'Native UD Packer', 'NeoLite', 'Ningishzida', 'NoobyProtect(Safengine)', 'NoodleCrypt', 'North Star PE Shrinker', 'NOS Installer', 'NOS Packer', 'nPack', 'NsPacK', 'NTkrnl Protector', 'NTPacker', 'NTSHELL', 'Nullsoft Scriptable Install System', "O'Setup95", 'Obfuscar', 'Obfuscator.NET 2009', 'Obsidium', 'Open Source Code Crypter', 'Oreans CodeVirtualizer', 'ORiEN', 'PACE', 'Pack Master', 'PackageForTheWeb', 'Packanoid', 'Packman', 'PACKWIN', 'Pantaray QSetup', 'Paquet Builder', 'Paquet archive', 'Patch', 'PC Guard', 'PCInstall', 'PCShrink', 'PE Diminisher', 'PE Encrypt', 'PE Intro', 'PELOCKnt', 'PE Ninja', 'PE Password', 'PE Protect', 'PE Quake', 'PE-Admin', 'PE-Armor', 'PE-SHiELD', 'Pe123', 'PEBundle', 'PECompact', 'PECRYPT32', 'Pelles C', 'PELock', 'PEncrypt', 'PEnguinCrypt', 'PENightMare', 'PE-PACK', 'PerlApp', 'PESpin', 'Petite', 'PeX', 'Phoenix', 'Photo Compiler', 'PIMP Installer', 'PKLITE32', 'PKSFX', 'PMAKER', 'PolyCrypt PE', 'PolyEnE', 'Power Screen Recorder', 'PowerBASIC', 'Private EXE Protector', 'Protection Plus', 'PUNiSHER', 'PureBasic', 'Python', 'QrYPt0r', 'QT installer', 'Qt', 'Quantum', 'QuickPack NT', 'Rar', 'RCryptor', 'RDG Tejon Crypter', 'ReactOS PE file', 'ReNET-pack', 'Resources', 'REVProt', 'RJoiner', 'RLP', 'RLPack', 'RNsetup', 'RosASM', 'R!SC Process Patcher', 'RTPatch', 'Safedisc', 'Safenet RMS (Sentinel)', 'Safengine Shielden', 'SC Obfuscator', 'Silver Creek Entertainment', 'SDProtector', 'SecuPack', 'Secure Shade', 'SecuROM', 'SerGreen Appacker', 'Setup Factory', 'Setup-Specialist', 'Sexe Crypter', 'Sfx Custom Action', 'SFXRun', 'Shrink Wrap', 'Shrinker', 'SimbiOZ', 'Simple Pack', 'Simple UPX Cryptor', 'simple patch', 'Sixxpack', 'Skater', 'SLVc0deProtector', 'Smart Assembly', 'Smart Install Maker', 'SmokesCrypt', 'Soft Defender', 'Softlocx', 'SoftProtect', 'SoftSentry', 'Software Compress', 'Sony Windows Installer', 'SpASM', 'Special EXE Password Protector', 'Spices.Net', 'Spoon Installer', 'Spoon Studio', 'Squeez SFX', 'StarForce', 'STATICSUP', 'Ste@lth PE', 'Steam stub', "Stone's PE Encryptor", 'ScanTime UnDetectable', 'SVK Protector', 'SwiftView Inc. installer', 'Synactis In-The-Box Installer', 'SZDD', 'Tages', 'Tarma Installer', 'tElock', 'temporary EXE SFX', 'The Best Cryptor by FsK', 'TheHypers protector', 'Themida/Winlicense', 'Thinstall(VMware ThinApp)', 'TPP Pack', 'TrueCrypt-VeraCrypt installer', 'UG2002 Cruncher', 'UltraPro', 'UnoPiX', 'UPolyX', 'UPX Inliner', 'UPX lock', 'UPX Modifier', 'UPX Protector', 'UPX scrambler', 'UPX shit', 'UPX', 'UPXcrypter', 'UPXFreak', 'VaySoft PDF to EXE Converter', 'VBox', 'Vbs To Exe', 'VCasm-Protector', 'Virtual Pascal', 'Vise', 'Visual Objects', 'Visual Prolog', 'VMProtect', 'VMWare', 'VPacker', 'Watcom', 'WinACE', 'Winamp Installer', 'Wind of Crypt', 'Windows Installer', 'Wine', 'WinImage', 'WinIMP', 'WinKript', 'WinPatch Apply Program by Artistry, Inc.', 'WinRAR Installer', 'WinRAR', '(Win)Upack', 'WinZip', 'Wise Installer', 'WiX Toolset installer', 'WWPACK', 'wxWidgets', 'XComp', 'XCR', 'Xenocode Postbuild', 'Xojo', 'Xoreax installer', 'XPACK', 'Xtreamlok (SoftWrap)', 'Xtreme-Protector', 'Yano', "Yoda's Crypter", "Yoda's Protector", 'Yummy Game SoftwareShield', 'yzPack', 'Zip SFX', 'ZipCentral SFX-32', 'Zprotect', '.BJFnt', 'Denuvo', '.NET Reactor', '.NET Spider', '.NET', '.netshrink', '.NETZ', 'CreateInstall data', '7-zip Installer data', 'ActiveMark protector data', 'Actual Installer data', 'Adveractive Installer data', 'Aeco Systems installer data', 'ARJSFX32 data', 'ARJ archive', 'ARQ archive', 'AutoPlay Media Studio installer data', 'ClickTeam installer data', 'CrypKey Installer archive', 'Dimd SFX data', 'distutils installer data', 'Envoy Packager data', 'Eschalon Installer archive', 'GPInstall data', 'GZip archive', 'Inno Setup Installer data', 'Inno Setup uninstall data', 'zlib archive', 'LucasArts Update Installer data', 'MP-ZipTool SFX32 data', 'MPQ archive', 'NOS Installer data', 'Pantaray QSetup data', 'Pantaray QSetup data', 'Paquet archive', 'Paquet Builder', 'QT installer data', 'RTPatch archive', 'Setup Factory installer data', 'Setup Factory installer data', 'STATICSUP installer data', 'Vise Installer data', 'WinImage SFX data', 'IMP archive', 'WinPatch Apply Program data', 'WinPatch Apply Program data', 'WinRAR Installer data', 'WinRAR Installer data', 'RAR archive', 'ZipCentral SFX-32 data', 'PCInstall data', 'InstallShield data', 'Adobe Flash', 'Smart Install Maker data', 'PackageForTheWeb data', 'Microsoft Compound', 'Autodesk Self-Extract data', 'Ghost Installer archive', 'CreateInstall data', 'VMWare Installation Launcher data', 'Codegear Installer data', 'Spoon Studio data', 'Advanced Installer data', 'Adobe SVG Installer', 'Chilkat ZIP Self-Extractor data', 'Dolphin Virtual Machine data', 'CodeFusion Wizard data', 'avast! Antivirus installer data', 'InstallAnywhere data', 'NSIS data', 'Internet Download Manager installer data', 'Install4j installer data', '7-zip Installer data', 'Sony Windows installer data', 'ADS Self Extractor data', 'ADS Self Extractor data', 'Chaos Software installer data', 'Gentee installer data', 'Squeez SFX data', 'Inno Setup data', 'CAB archive', 'InstallShield archive', 'Excelsior installer data', 'InstallShield data', 'Multimedia Fusion installer data', 'BZIP2', 'PIMP installer data', 'Tarma installer data', 'I-D Media installer data', 'SwiftView installer data', 'BulletProofSoft installer data', 'SecuROM data', 'CodeView 4.10 debug information', 'CodeView 5.0 debug information', 'PDB 2.0 file link', 'PDB 7.0 file link', 'Mioplanet installer executable+data', 'DelZip SFX data', 'CoffeeCup SFX data', 'KRZIP archive', 'Smart Install Maker data', 'AOLSetup data', 'Setup-Specialist archive', 'AutoIt v3 compiled script', 'CAB archive', 'ZIP archive', 'Bytessence Install Maker data', 'BitRock installer data', 'ThinApp data', 'Hamrick Software XOR-ed ZIP', 'EXE file', 'Box Stub installer data', 'Pantaray QSetup data', 'Pantaray QSetup data', 'Install Factory data')]
        [string]$Detection,

        [Parameter(Mandatory = $false)]
        [string]$PathToDiec = ".\diec.exe",

        [Parameter(Mandatory = $false)]
        [switch]$DetectNotValidSignature = $false,

        [Parameter(Mandatory = $false)]
        [switch]$DetectPacked = $false,

        [Parameter(Mandatory = $false)]
        [switch]$DeepScan
    )
    #convert json output to array of objects and add to each object property filepath (for folder path scanning)
    function CreateJsonObjects([System.Object]$DIECresult_x, [string]$PathToScan_x) {
        $json_objects = @()
        $json_string = ""
        foreach($line in $DIECresult_x){
            if( $line.StartsWith($PathToScan_x.Replace('\','/'))){
                $filepath = ($line.Replace('/','\\')).TrimEnd(':')
                $json_string = ""
            }
            elseif($line -ne "}"){
                $json_string += $line
            }
            else{
                $json_string += ",    `"filepath`": `"$filepath`"" + $line
                $json_objects += $json_string | ConvertFrom-Json
            }
        }
        return ($json_objects)    
    }
    #convert json output to object and add to object property filepath (for file path scanning)
    function CreateJsonObject_file([System.Object]$DIECresult_x, [string]$PathToScan_x) {
        $json_objects = @()
        $json_string = ""
        foreach($line in $DIECresult_x){
            if($line -ne "}"){
                $json_string += $line
            }
            else{
                $PathToScan_x = $PathToScan_x.Replace('\','\\')
                $json_string += ",    `"filepath`": `"$PathToScan_x`"" + $line
                $json_objects += $json_string | ConvertFrom-Json
            }
        }
        return ($json_objects)    
    }
    #returns files with detected protection
    function Detect([System.Object]$json_objects,[string]$detection){
        $detected_files = @()
        foreach($scanned_file in $json_objects){
            if( $detection -in $scanned_file.detects.Name){
                $detected_files += $scanned_file
            }
        }
        return ($detected_files)
    }
    #returns all PE32 or PE64 which dont have VALID AuthenticodeSignature (also without signature) -good to use with protection detection (using also catalog)
    function Is_AuthSignature_InValid([System.Object]$json_objects) {
        $detected_files = @()
        foreach($scanned_file in $json_objects){
            if($scanned_file.filetype -eq "PE32" -or $scanned_file.filetype -eq "PE64"){
                [string]$status = (Get-AuthenticodeSignature -LiteralPath $scanned_file.filepath).Status
                if($status -ne "Valid"){
                    $scanned_file | Add-Member -NotePropertyName SignatureStatus -NotePropertyValue $status
                    $detected_files += $scanned_file
                }            
            }
        }
        return ($detected_files)
    }
    #returns only packed files - High Entropy
    function Is_Packed([System.Object]$json_objects) {
        $detected_files = @()
        foreach($scanned_file in $json_objects){
            if($scanned_file.status -eq "packed"){
                $detected_files += $scanned_file | Select-Object -Property filepath,status,total                      
            }
        }
        return ($detected_files)
    }

################################################################################################ MAIN ################################################################################################
    #if diec path not specified test if in current dir
    if(!(Test-Path -LiteralPath $PathToDiec)){
        Write-Host "Detect-It-Easy `"diec.exe`" is not in current directory!" -ForegroundColor Red
        Write-Host "Run Powershell from `"diec.exe`" location or specify `$PathToDiec parameter!`n" -ForegroundColor Red
        Break
    }
    #if wrongly ending folder path
    if($PathToScan[-1] -eq "\"){
        $PathToScan = $PathToScan.TrimEnd("\")
    }

    $detected_files = @()
    #returns only packed samples with entropy and break
    if($DetectPacked){
        [string]$DetectPacked = '-e'
        [System.Object]$DIECresult = "&'$PathToDiec' $DetectPacked -j `"$PathToScan`"" | Invoke-Expression
        #PathToScan is path to file - process differently
        if(Test-Path -LiteralPath $PathToScan -PathType Leaf){
            [System.Object]$json_objects_results = CreateJsonObject_file -DIECresult_x $DIECresult -PathToScan_x $PathToScan
        }
        #PathToScan is path to folder - process differently
        else{
            [System.Object]$json_objects_results = CreateJsonObjects -DIECresult_x $DIECresult -PathToScan_x $PathToScan        
        }     
        $detected_files = Is_Packed -json_objects $json_objects_results   
    }

    #returns all objects or only with detected protection or without VALID AuthSignature or (Detected Protection + without VALID AuthSignature)
    else {
        #diec deepscan option
        if($DeepScan){
            [string]$DeepScan = '-d'
        }
        else {
            [string]$DeepScan = ''    
        }
        [System.Object]$DIECresult = "&'$PathToDiec' $DeepScan -j `"$PathToScan`"" | Invoke-Expression
        #PathToScan is path to file - process differently
        if(Test-Path -LiteralPath $PathToScan -PathType Leaf){
            [System.Object]$json_objects_results = CreateJsonObject_file -DIECresult_x $DIECresult -PathToScan_x $PathToScan
        }
        #PathToScan is path to folder - process differently
        else{
            [System.Object]$json_objects_results = CreateJsonObjects -DIECresult_x $DIECresult -PathToScan_x $PathToScan     
        }
        #returns objects only with detected protection or without VALID AuthSignature or (Detected Protection + without VALID AuthSignature)
        if($Detection -ne "" -or $DetectNotValidSignature){
            if($Detection -ne ""){
                $json_objects_results =  Detect -json_objects $json_objects_results -detection $Detection
            }
            if($DetectNotValidSignature){
                $json_objects_results = Is_AuthSignature_InValid -json_objects $json_objects_results
            }
            $detected_files = $json_objects_results
        }
        else{
            $detected_files = $json_objects_results
        }
    }
    $detected_files | Write-Output
}
