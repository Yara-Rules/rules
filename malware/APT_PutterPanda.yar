/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule APT_Malware_PutterPanda_Rel 
{

    meta:
        description = "Detects an APT malware related to PutterPanda"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "5367e183df155e3133d916f7080ef973f7741d34"

    strings:
        $x0 = "app.stream-media.net" fullword ascii /* score: '12.03' */
        $x1 = "File %s does'nt exist or is forbidden to acess!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.035' */
        $s6 = "GetProcessAddresss of pHttpQueryInfoA Failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.02' */
        $s7 = "Connect %s error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.04' */
        $s9 = "Download file %s successfully!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.03' */
        $s10 = "index.tmp" fullword ascii /* score: '14.03' */
        $s11 = "Execute PE Successfully" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.03' */
        $s13 = "aa/22/success.xml" fullword ascii /* score: '12.005' */
        $s16 = "aa/22/index.asp" fullword ascii /* score: '11.02' */
        $s18 = "File %s a Non-Pe File" fullword ascii /* score: '8.04' */
        $s19 = "SendRequset error!" fullword ascii /* score: '8.04' */
        $s20 = "filelist[%d]=%s" fullword ascii /* score: '7.015' */

    condition:
        ( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( 4 of ($s*) )
}


rule APT_Malware_PutterPanda_Rel_2 
{

    meta:
        description = "APT Malware related to PutterPanda Group"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "f97e01ee04970d1fc4d988a9e9f0f223ef2a6381"

    strings:
        $s0 = "http://update.konamidata.com/test/zl/sophos/td/result/rz.dat?" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
        $s1 = "http://update.konamidata.com/test/zl/sophos/td/index.dat?" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
        $s2 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '20.03' */
        $s3 = "Internet connect error:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.035' */
        $s4 = "Proxy-Authorization:Basic" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.02' */
        $s5 = "HttpQueryInfo failed:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.015' */
        $s6 = "read file error:%d" fullword ascii /* score: '11.04' */
        $s7 = "downdll.dll" fullword ascii /* score: '11.025' */
        $s8 = "rz.dat" fullword ascii /* score: '10.005' */
        $s9 = "Invalid url" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.03' */
        $s10 = "Create file failed" fullword ascii /* score: '8.045' */
        $s11 = "myAgent" fullword ascii /* score: '8.025' */
        $s12 = "%s%s%d%d" fullword ascii /* score: '8.005' */
        $s13 = "down file success" fullword ascii /* score: '7.035' */
        $s15 = "error!" fullword ascii /* score: '6.04' */
        $s18 = "Avaliable data:%u bytes" fullword ascii /* score: '5.025' */
    
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule APT_Malware_PutterPanda_PSAPI 
{

    meta:
        description = "Detects a malware related to Putter Panda"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "f93a7945a33145bb6c106a51f08d8f44eab1cdf5"

    strings:
        $s0 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.03' */
        $s1 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.045' */
        $s2 = "psapi.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 54 times */
        $s3 = "urlmon.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 471 times */
        $s4 = "WinHttpGetProxyForUrl" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 179 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule APT_Malware_PutterPanda_WUAUCLT 
{

    meta:
        description = "Detects a malware related to Putter Panda"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "fd5ca5a2d444865fa8320337467313e4026b9f78"
    
    strings:
        $x0 = "WUAUCLT.EXE" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
        $x1 = "%s\\tmp%d.exe" fullword ascii /* score: '14.01' */   
        $x2 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */
        $s1 = "Microsoft Windows Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 4 times */
        $s2 = "InternetQueryOptionA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 166 times */
        $s3 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 336 times */
        $s4 = "WNetEnumResourceA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 29 times */
        $s5 = "HttpSendRequestExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 87 times */
        $s6 = "PSAPI.DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 420 times */
        $s7 = "Microsoft(R) Windows(R) Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 128 times */
        $s8 = "CreatePipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 222 times */
        $s9 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 410 times */

    condition:
        all of ($x*) or (1 of ($x*) and all of ($s*) )
}

rule APT_Malware_PutterPanda_Gen1 
{

    meta:
        description = "Detects a malware "
        author = "YarGen Rule Generator"
        reference = "not set"
        date = "2015-06-03"
        super_rule = 1
        hash0 = "bf1d385e637326a63c4d2f253dc211e6a5436b6a"
        hash1 = "76459bcbe072f9c29bb9703bc72c7cd46a692796"
        hash2 = "e105a7a3a011275002aec4b930c722e6a7ef52ad"

    strings:
        $s1 = "%s%duserid=%dthreadid=%dgroupid=%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.02' */
        $s2 = "ssdpsvc.dll" fullword ascii /* score: '11.00' */
        $s3 = "Fail %s " fullword ascii /* score: '10.04' */
        $s4 = "%s%dpara1=%dpara2=%dpara3=%d" fullword ascii /* score: '10.01' */
        $s5 = "LsaServiceInit" fullword ascii /* score: '7.03' */
        $s6 = "%-8d Fs %-12s Bs " fullword ascii /* score: '5.04' */
        $s7 = "Microsoft DH SChannel Cryptographic Provider" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5.00' */ /* Goodware String - occured 5 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule Malware_MsUpdater_String_in_EXE  
{

    meta:
        description = "MSUpdater String in Executable"
        author = "Florian Roth"
        score = 50
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "b1a2043b7658af4d4c9395fa77fde18ccaf549bb"

    strings:
        $x1 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
        // $x2 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */
        $x3 = "msupdater.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.02' */
        $x4 = "msupdater32.exe" fullword ascii
        $x5 = "msupdater32.exe" fullword wide
        $x6 = "msupdate.pif" fullword ascii
        $fp1 = "_msupdate_" wide /* False Positive */
        $fp2 = "_msupdate_" ascii /* False Positive */
        $fp3 = "/kies" wide

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and ( 1 of ($x*) ) and not ( 1 of ($fp*) ) 
}

rule APT_Malware_PutterPanda_MsUpdater_3 
{

    meta:
        description = "Detects Malware related to PutterPanda - MSUpdater"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "464149ff23f9c7f4ab2f5cadb76a4f41f969bed0"

    strings:
        $s0 = "msupdater.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.02' */
        $s1 = "Explorer.exe \"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.05' */
        $s2 = "FAVORITES.DAT" fullword ascii /* score: '11.02' */
        $s4 = "COMSPEC" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82' */ /* Goodware String - occured 178 times */
   
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule APT_Malware_PutterPanda_MsUpdater_1 
{

    meta:
        description = "Detects Malware related to PutterPanda - MSUpdater"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "b55072b67543f58c096571c841a560c53d72f01a"

    strings:
        $x0 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
        $x1 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */
        $s1 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */
        $s2 = "Automatic Updates" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
        $s3 = "VirtualProtectEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 68 times */
        $s4 = "Invalid parameter" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 69 times */
        $s5 = "VirtualAllocEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 95 times */
        $s6 = "WriteProcessMemory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.87' */ /* Goodware String - occured 131 times */
    condition:
        ( uint16(0) == 0x5a4d and 1 of ($x*) and 4 of ($s*) ) or ( 1 of ($x*) and all of ($s*) ) 
}

rule APT_Malware_PutterPanda_MsUpdater_2 
{

    meta:
        description = "Detects Malware related to PutterPanda - MSUpdater"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "365b5537e3495f8ecfabe2597399b1f1226879b1"
   
    strings:
        $s0 = "winsta0\\default" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99' */ /* Goodware String - occured 6 times */
        $s1 = "EXPLORER.EXE" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
        $s2 = "WNetEnumResourceA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97' */ /* Goodware String - occured 29 times */
        $s3 = "explorer.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97' */ /* Goodware String - occured 31 times */
        $s4 = "CreateProcessAsUserA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 86 times */
        $s5 = "HttpSendRequestExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 87 times */
        $s6 = "HttpEndRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 91 times */
        $s7 = "GetModuleBaseNameA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88' */ /* Goodware String - occured 121 times */
        $s8 = "GetModuleFileNameExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.86' */ /* Goodware String - occured 144 times */
        $s9 = "HttpSendRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85' */ /* Goodware String - occured 154 times */
        $s10 = "HttpOpenRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.84' */ /* Goodware String - occured 159 times */
        $s11 = "InternetConnectA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82' */ /* Goodware String - occured 183 times */
        $s12 = "Process32Next" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.80' */ /* Goodware String - occured 204 times */
        $s13 = "Process32First" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.79' */ /* Goodware String - occured 210 times */
        $s14 = "CreatePipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.78' */ /* Goodware String - occured 222 times */
        $s15 = "EnumProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.73' */ /* Goodware String - occured 273 times */
        $s16 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.66' */ /* Goodware String - occured 336 times */
        $s17 = "PeekNamedPipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.65' */ /* Goodware String - occured 347 times */
        $s18 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.59' */ /* Goodware String - occured 410 times */
        $s19 = "PSAPI.DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.58' */ /* Goodware String - occured 420 times */
        $s20 = "SPSSSQ" fullword ascii /* score: '4.51' */
   
    condition:
        uint16(0) == 0x5a4d and filesize < 220KB and all of them
}

rule APT_Malware_PutterPanda_Gen4 
{

    meta:
        description = "Detects Malware related to PutterPanda"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        super_rule = 1
        hash0 = "71a8378fa8e06bcf8ee9f019c807c6bfc58dca0c"
        hash1 = "8fdd6e5ed9d69d560b6fdd5910f80e0914893552"
        hash2 = "3c4a762175326b37035a9192a981f7f4cc2aa5f0"
        hash3 = "598430b3a9b5576f03cc4aed6dc2cd8a43324e1e"
        hash4 = "6522b81b38747f4aa09c98fdaedaed4b00b21689"

    strings:
        $x1 = "rz.dat" fullword ascii /* score: '10.00' */
        $s0 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '20.03' */
        $s1 = "Internet connect error:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.04' */
        $s2 = "Proxy-Authorization:Basic " fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.02' */
        $s5 = "Invalid url" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.03' */
        $s6 = "Create file failed" fullword ascii /* score: '8.04' */
        $s7 = "myAgent" fullword ascii /* score: '8.03' */
        $z1 = "%s%s%d%d" fullword ascii /* score: '8.00' */
        $z2 = "HttpQueryInfo failed:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.02' */
        $z3 = "read file error:%d" fullword ascii /* score: '11.04' */
        $z4 = "down file success" fullword ascii /* score: '7.04' */
        $z5 = "kPStoreCreateInstance" fullword ascii /* score: '5.03' */
        $z6 = "Avaliable data:%u bytes" fullword ascii /* score: '5.03' */
        $z7 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii /* PEStudio Blacklist: guid */ /* score: '5.00' */ /* Goodware String - occured 2 times */

    condition:
        filesize < 300KB and (( uint16(0) == 0x5a4d and $x1 and 3 of ($s*) ) or ( 3 of ($s*) and 4 of ($z*) ))
}
