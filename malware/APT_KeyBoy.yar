/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule KeyBoy_Dropper
{

    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:
        $1 = "I am Admin"
        $2 = "I am User"
        $3 = "Run install success!"
        $4 = "Service install success!"
        $5 = "Something Error!"
        $6 = "Not Configed, Exiting"

    condition:
        all of them
}

rule KeyBoy_Backdoor
{

    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:
        $1 = "$login$"
        $2 = "$sysinfo$"
        $3 = "$shell$"
        $4 = "$fileManager$"
        $5 = "$fileDownload$"
        $6 = "$fileUpload$"

    condition:
        all of them
}

/*
*
* This section of the rules are all specific to the new 2016
* KeyBoy sample targeting the Tibetan community. Other following
* sections capture file characteristics observed across multiple
* years of development.
*
*/

rule new_keyboy_export
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header //PE signature //The malware family seems to share many exports //but this is the new kid on the block.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and pe.exports("cfsUpdate")
}

rule new_keyboy_header_codes
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's header codes"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "*l*" wide fullword
        $s2 = "*a*" wide fullword
        $s3 = "*s*" wide fullword
        $s4 = "*d*" wide fullword
        $s5 = "*f*" wide fullword
        $s6 = "*g*" wide fullword
        $s7 = "*h*" wide fullword

    condition:
        //MZ header //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and all of them
}


/*
*
* This section of the rules are all broader and will hit on
* older KeyBoy samples and other samples possibly part of a
* a larger development effort.
*
*/

rule keyboy_commands
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's sent and received commands"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "Update" wide fullword
        $s2 = "UpdateAndRun" wide fullword
        $s3 = "Refresh" wide fullword
        $s4 = "OnLine" wide fullword
        $s5 = "Disconnect" wide fullword
        $s6 = "Pw_Error" wide fullword
        $s7 = "Pw_OK" wide fullword
        $s8 = "Sysinfo" wide fullword
        $s9 = "Download" wide fullword
        $s10 = "UploadFileOk" wide fullword
        $s11 = "RemoteRun" wide fullword
        $s12 = "FileManager" wide fullword

    condition:
        //MZ header //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and 6 of them
}

rule keyboy_errors
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the sample's shell error2 log statements"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are in ASCII pre-2015 and UNICODE in 2016
        $error = "Error2" ascii wide
        //2016 specific:
        $s1 = "Can't find [%s]!Check the file name and try again!" ascii wide
        $s2 = "Open [%s] error! %d" ascii wide
        $s3 = "The Size of [%s] is zero!" ascii wide
        $s4 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s5 = "UploadFile [%s] Error:Connect Server Failed!" ascii wide
        $s6 = "Receive [%s] Error(Recved[%d] != Send[%d])!" ascii wide
        $s7 = "Receive [%s] ok! Use %2.2f seconds, Average speed %2.2f k/s" ascii wide
        $s8 = "CreateThread UploadFile[%s] Error!" ascii wide
        //Pre-2016:
        $s9 = "Ready Download [%s] ok!" ascii wide
        $s10 = "Get ControlInfo from FileClient error!" ascii wide
        $s11 = "FileClient has a error!" ascii wide
        $s12 = "VirtualAlloc SendBuff Error(%d)" ascii wide
        $s13 = "ReadFile [%s] Error(%d)..." ascii wide
        $s14 = "ReadFile [%s] Data[Readed(%d) != FileSize(%d)] Error..." ascii wide
        $s15 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s16 = "RecvData MyRecv_Info Size Error!" ascii wide
        $s17 = "RecvData MyRecv_Info Tag Error!" ascii wide
        $s18 = "SendData szControlInfo_1 Error!" ascii wide
        $s19 = "SendData szControlInfo_3 Error!" ascii wide
        $s20 = "VirtualAlloc RecvBuff Error(%d)" ascii wide
        $s21 = "RecvData Error!" ascii wide
        $s22 = "WriteFile [%s} Error(%d)..." ascii wide

    condition:
        //MZ header  //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and $error and 3 of ($s*)
}


rule keyboy_systeminfo
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the system information format before sending to C2"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are ASCII pre-2015 and UNICODE in 2016
        $s1 = "SystemVersion:    %s" ascii wide
        $s2 = "Product  ID:      %s" ascii wide
        $s3 = "InstallPath:      %s" ascii wide
        $s4 = "InstallTime:      %d-%d-%d, %02d:%02d:%02d" ascii wide
        $s5 = "ResgisterGroup:   %s" ascii wide
        $s6 = "RegisterUser:     %s" ascii wide
        $s7 = "ComputerName:     %s" ascii wide
        $s8 = "WindowsDirectory: %s" ascii wide
        $s9 = "System Directory: %s" ascii wide
        $s10 = "Number of Processors:       %d" ascii wide
        $s11 = "CPU[%d]:  %s: %sMHz" ascii wide
        $s12 = "RAM:         %dMB Total, %dMB Free." ascii wide
        $s13 = "DisplayMode: %d x %d, %dHz, %dbit" ascii wide
        $s14 = "Uptime:      %d Days %02u:%02u:%02u" ascii wide

    condition:
        //MZ header //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and 7 of them
}


rule keyboy_related_exports
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header //PE signature //The malware family seems to share many exports //but this is the new kid on the block.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and pe.exports("Embedding") or pe.exports("SSSS") or pe.exports("GetUP")
}

// Note: The use of the .Init section has been observed in nearly
// all samples with the exception of the 2013 VN dropper from the
// Rapid7 blog. The config data was stored in that sample's .data
// section.

rule keyboy_init_config_section
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the Init section where the config is stored"
        date = "2016-08-28"

    condition:
        //MZ header //PE signature //Payloads are normally smaller but the new dropper we spotted //is a bit larger. //Observed virtual sizes of the .Init section vary but they've //always been 1024, 2048, or 4096 bytes.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 300KB and for any i in (0..pe.number_of_sections - 1): (pe.sections[i].name == ".Init" and pe.sections[i].virtual_size % 1024 == 0)
}
