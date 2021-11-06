# Invoke-DetectItEasy
Invoke-DetectItEasy is a powershell module and wrapper for excellent tool called Detect-It-Easy. It is very useful for Threat Hunting and Forensics.<br/>

Guide: [[YouTube]](https://youtu.be/O8o0txFtrfQ)<br/>
Detect-It-Easy tool: https://github.com/horsicq/Detect-It-Easy<br/>
## ABOUT
Author: Dump-GUY (@vinopaljiri)<br/>
Credits: @horsicq - Author of Detect-It-Easy tool<br/>
Required Version of Detect-It-Easy >= 3.03<br/>
Invoke-DetectItEasy is a wrapper for excellent tool called Detect-It-Easy. This PS module is very useful for Threat Hunting and Forensics.<br/>
It could be also used to simply sort your malware repo.<br/>
Sometimes we just need to find anything suspicious so we must to detect it on system or sort files offline on mounted acquired image.<br/>
This tool already served well in many forensic related cases/incidents.<br/>

## DESCRIPTION
Invoke-DetectItEasy enables you to process any output further and pipe it to other command.<br/>
It enables you to scan folder-recursive or file. With all output you can work as with objects.<br/>
It is as good as DIE so it enables you to process files with whole output or you can select only specified Packer you want to detect.<br/>
You can also detect only Packed files based on their entropy.<br/>
Big feature is added - Detection of PE32/PE64 without VALID Digital signatures where the output will contain also reason (example. "HashMismatch", NotSigned)<br/>
Another advantage of detection VALID Digital signatures is that powershell is able to read also Catalog files.<br/>
Example: When we detect files packed with Themida and with Digital Signature result as "HashMismatch" it should be our point of interest.<br/>

## PARAMETER PathToScan
Mandatory parameter.<br/>
Specifies the System Path to scan. It could be path to single File or Folder. Folder will be scanned recursively.<br/>

## PARAMETER PathToDiec
Optional parameter.<br/>
System Path to diec.exe tool - console version of Detect-It-Easy.<br/>
If powershell is running from the location of diec.exe - this parameter could be ignored otherwise specify this parameter.<br/>

## PARAMETER Detection
Optional parameter.<br/>
Specifies Packer or Protection etc.. We want to detect. All possible values are already set-predefined.<br/>
This parameter could be combined with others (example. with DetectNotValidSignature)<br/>

## PARAMETER DetectNotValidSignature
Optional parameter.<br/>
This parameter detects only PE32/PE64 without VALID Digital signatures where the output containing also reason (example. "HashMismatch", NotSigned) will be returned.<br/>
This parameter could be combined with others.<br/>

## PARAMETER DeepScan
This parameter enables to scan files with DeepScan feature of Detect-It-Easy.<br/>
This parameter could be combined with others.<br/>

## PARAMETER DetectPacked
Optional parameter.<br/>
This parameter specifies that only detected Packed files based on their entropy will be returned.<br/>
This parameter can NOT be combined with others.<br/>
Returned objects contains filepath, status, entropy<br/>

## EXAMPLE
PS> Import-Module .\Invoke-DetectItEasy.ps1<br/>
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles' -Detection VMProtect -PathToDiec "C:\die_win64_portable\diec.exe" -DetectNotValidSignature -DeepScan<br/>
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles\malware.exe' -DetectNotValidSignature<br/>
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles' -PathToDiec "C:\die_win64_portable\diec.exe" -DetectPacked<br/>
PS> Invoke-DetectItEasy -PathToScan 'C:\testfiles' -PathToDiec "C:\die_win64_portable\diec.exe"<br/>
PS> Invoke-DetectItEasy -PathToScan 'C:\PEs ccc\' -PathToDiec "C:\die_win64_portable\diec.exe" -Detection VMProtect -DetectNotValidSignature | Select-Object -Property filepath, SignatureStatus<br/>
PS> Invoke-DetectItEasy -PathToScan 'C:\PEs ccc' -PathToDiec "C:\die_win64_portable\diec.exe" -DetectPacked | ?{$_.total -ge 7}<br/>
PS> (Invoke-DetectItEasy -PathToScan "C:\PEs ccc" -DetectNotValidSignature -PathToDiec "C:\die_win64_portable\diec.exe").filepath | %{Invoke-DetectItEasy -PathToScan $_ -PathToDiec "C:\die_win64_portable\diec.exe" -DetectPacked}<br/>

