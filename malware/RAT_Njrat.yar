/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Njrat: RAT
{
    meta:
        description = "Njrat"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(F)romBase64String/
        $string2 = /(B)ase64String/
        $string3 = /(C)onnected/ wide ascii
        $string4 = /(R)eceive/
        $string5 = /(S)end/ wide ascii
        $string6 = /(D)ownloadData/ wide ascii
        $string7 = /(D)eleteSubKey/ wide ascii
        $string8 = /(g)et_MachineName/
        $string9 = /(g)et_UserName/
        $string10 = /(g)et_LastWriteTime/
        $string11 = /(G)etVolumeInformation/
        $string12 = /(O)SFullName/ wide ascii
        $string13 = /(n)etsh firewall/ wide
        $string14 = /(c)md\.exe \/k ping 0 & del/ wide
        $string15 = /(c)md\.exe \/c ping 127\.0\.0\.1 & del/ wide
        $string16 = /(c)md\.exe \/c ping 0 -n 2 & del/ wide
        $string17 = {7C 00 27 00 7C 00 27 00 7C}

    condition:
        10 of them
}
rule njrat1: RAT
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-27"
        description = "Identify njRat"
    strings:
        $a1 = "netsh firewall add allowedprogram " wide
        $a2 = "SEE_MASK_NOZONECHECKS" wide

        $b1 = "[TAP]" wide
        $b2 = " & exit" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}
rule win_exe_njRAT 
{
meta:
author = "info@fidelissecurity.com"
descripion = "njRAT - Remote Access Trojan"
comment = "Variants have also been observed obfuscated with .NET Reactor"
filetype = "pe"
date = "2013-07-15"
version = "1.0"
hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
hash2 = "3576d40ce18bb0349f9dfa42b8911c3a"
hash3 = "24cc5b811a7f9591e7f2cb9a818be104"
hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
hash5 = "a98b4c99f64315aac9dd992593830f35"
hash6 ="5fcb5282da1a2a0f053051c8da1686ef"
hash7 = "a669c0da6309a930af16381b18ba2f9d"
hash8 = "79dce17498e1997264346b162b09bde8"
hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
ref1 = "http://bit.ly/19tlf4s"
ref2 = "http://www.fidelissecurity.com/threatadvisory"
ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njratuncovered.html"
ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

strings:
$magic = "MZ"
$string_setA_1 = "FromBase64String"
$string_setA_2 = "Base64String"
$string_setA_3 = "Connected" wide ascii
$string_setA_4 = "Receive"
$string_setA_5 = "DeleteSubKey" wide ascii
$string_setA_6 = "get_MachineName"
$string_setA_7 = "get_UserName"
$string_setA_8 = "get_LastWriteTime"
$string_setA_9 = "GetVolumeInformation"

$string_setB_1 = "OSFullName" wide ascii
$string_setB_2 = "Send" wide ascii
$string_setB_3 = "Connected" wide ascii
$string_setB_4 = "DownloadData" wide ascii
$string_setB_5 = "netsh firewall" wide
$string_setB_6 = "cmd.exe /k ping 0 & del" wide

condition:
($magic at 0) and ( all of ($string_setA*) or all of ($string_setB*) ) 
}

rule network_traffic_njRAT 
{
meta:
author = "info@fidelissecurity.com"
descripion = "njRAT - Remote Access Trojan"
comment = "Rule to alert on network traffic indicators"
filetype = "PCAP - Network Traffic"
date = "2013-07-15"
version = "1.0"
hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
hash2 ="3576d40ce18bb0349f9dfa42b8911c3a"
hash3 ="24cc5b811a7f9591e7f2cb9a818be104"
hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
hash5 = "a98b4c99f64315aac9dd992593830f35"
hash6 = "5fcb5282da1a2a0f053051c8da1686ef"
hash7 = "a669c0da6309a930af16381b18ba2f9d"
hash8 = "79dce17498e1997264346b162b09bde8"
hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
ref1 = "http://bit.ly/19tlf4s"
ref2 = "http://www.fidelissecurity.com/threatadvisory"
ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njrat-uncovered.html"
ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

strings:
$string1 = "FM|'|'|"     // File Manager
$string2 = "nd|'|'|"     // File Manager
$string3 = "rn|'|'|"      // Run File
$string4 = "sc~|'|'|"     // Remote Desktop
$string5 = "scPK|'|'|"     // Remote Desktop
$string6 = "CAM|'|'|"     // Remote Cam
$string7 = "USB Video Device[endof]" // Remote Cam
$string8 = "rs|'|'|"     // Reverse Shell
$string9 = "proc|'|'|"     // Process Manager
$string10 = "k|'|'|"     // Process Manager
$string11 = "RG|'|'|~|'|'|"    // Registry Manipulation
$string12 = "kl|'|'|"     // Keylogger file
$string13 = "ret|'|'|"     // Get Browser Passwords
$string14 = "pl|'|'|"     // Get Browser Passwords
$string15 = "lv|'|'|"     // General
$string16 = "prof|'|'|~|'|'|"   // Server rename
$string17 = "un|'|'|~[endof]"   // Uninstall
$idle_string = "P[endof]"    // Idle Connection

condition:
any of ($string*) or #idle_string > 4  

}
