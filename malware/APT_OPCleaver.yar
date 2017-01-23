/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule ZhoupinExploitCrew
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhoupin exploit crew" nocase
    $s2 = "zhopin exploit crew" nocase

  condition:
    1 of them
}

rule BackDoorLogger
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "BackDoorLogger"
    $s2 = "zhuAddress"

  condition:
    all of them
}

rule Jasus
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "pcap_dump_open"
    $s2 = "Resolving IPs to poison..."
    $s3 = "WARNNING: Gateway IP can not be found"

  condition:
    all of them
}

rule LoggerModule
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "%s-%02d%02d%02d%02d%02d.r"
    $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

  condition:
    all of them
}

rule NetC
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "NetC.exe" wide
    $s2 = "Net Service"

  condition:
    all of them
}

rule ShellCreator2
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "ShellCreator2.Properties"
    $s2 = "set_IV"

  condition:
    all of them
}

rule SmartCopy2
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "SmartCopy2.Properties"
    $s2 = "ZhuFrameWork"

  condition:
    all of them
}

rule SynFlooder
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    $s2 = "your target's IP is : %s"
    $s3 = "Raw TCP Socket Created successfully."

  condition:
    all of them
}

rule TinyZBot
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "NetScp" wide
    $s2 = "TinyZBot.Properties.Resources.resources"
    $s3 = "Aoao WaterMark"
    $s4 = "Run_a_exe"
    $s5 = "netscp.exe"
    $s6 = "get_MainModule_WebReference_DefaultWS"
    $s7 = "remove_CheckFileMD5Completed"
    $s8 = "http://tempuri.org/"
    $s9 = "Zhoupin_Cleaver"

  condition:
    ($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or ($s9)
}

rule antivirusdetector
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

    strings:
        $s1 = "getShadyProcess"
        $s2 = "getSystemAntiviruses"
        $s3 = "AntiVirusDetector"

    condition:
        all of them
}

rule csext
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "COM+ System Extentions"
    $s2 = "csext.exe"
    $s3 = "COM_Extentions_bin"

  condition:
    all of them
}

rule kagent
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "kill command is in last machine, going back"
    $s2 = "message data length in B64: %d Bytes"

  condition:
    all of them
}

rule mimikatzWrapper : Toolkit
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "mimikatzWrapper"
    $s2 = "get_mimikatz"

  condition:
    all of them
}

rule pvz_in
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "LAST_TIME=00/00/0000:00:00PM$"
    $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"

  condition:
    all of them
}

rule pvz_out
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "Network Connectivity Module" wide
    $s2 = "OSPPSVC" wide

  condition:
    all of them
}

rule wndTest
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "[Alt]" wide
    $s2 = "<< %s >>:" wide
    $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"

  condition:
    all of them
}

rule zhCat
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhCat -l -h -tp 1234"
    $s2 = "ABC ( A Big Company )" wide

  condition:
    all of them
}

rule zhLookUp
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhLookUp.Properties"

  condition:
    all of them
}

rule zhmimikatz
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "MimikatzRunner"
    $s2 = "zhmimikatz"

  condition:
    all of them
}

rule Zh0uSh311
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "Zh0uSh311"

  condition:
    all of them
}

rule OPCLEAVER_BackDoorLogger
{

    meta:
        description = "Keylogger used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "BackDoorLogger"
        $s2 = "zhuAddress"

    condition:
        all of them
}

rule OPCLEAVER_Jasus
{

    meta:
        description = "ARP cache poisoner used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "pcap_dump_open"
        $s2 = "Resolving IPs to poison..."
        $s3 = "WARNNING: Gateway IP can not be found"

    condition:
        all of them
}

rule OPCLEAVER_LoggerModule
{

    meta:
        description = "Keylogger used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "%s-%02d%02d%02d%02d%02d.r"
        $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

    condition:
        all of them
}

rule OPCLEAVER_NetC
{

    meta:
        description = "Net Crawler used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "NetC.exe" wide
        $s2 = "Net Service"

    condition:
        all of them
}

rule OPCLEAVER_ShellCreator2
{

    meta:
        description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "ShellCreator2.Properties"
        $s2 = "set_IV"

    condition:
        all of them
}

rule OPCLEAVER_SmartCopy2
{

    meta:
        description = "Malware or hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "SmartCopy2.Properties"
        $s2 = "ZhuFrameWork"

    condition:
        all of them
}

rule OPCLEAVER_SynFlooder
{

    meta:
        description = "Malware or hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
        $s2 = "your target’s IP is : %s"
        $s3 = "Raw TCP Socket Created successfully."

    condition:
        all of them
}

rule OPCLEAVER_TinyZBot
{

    meta:
        description = "Tiny Bot used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "NetScp" wide
        $s2 = "TinyZBot.Properties.Resources.resources"
        $s3 = "Aoao WaterMark"
        $s4 = "Run_a_exe"
        $s5 = "netscp.exe"
        $s6 = "get_MainModule_WebReference_DefaultWS"
        $s7 = "remove_CheckFileMD5Completed"
        $s8 = "http://tempuri.org/"
        $s9 = "Zhoupin_Cleaver"

    condition:
        (($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9)
}

rule OPCLEAVER_ZhoupinExploitCrew
{

    meta:
        description = "Keywords used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "zhoupin exploit crew" nocase
        $s2 = "zhopin exploit crew" nocase

    condition:
        1 of them
}

rule OPCLEAVER_antivirusdetector
{

    meta:
        description = "Hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "getShadyProcess"
        $s2 = "getSystemAntiviruses"
        $s3 = "AntiVirusDetector"

    condition:
        all of them
}

rule OPCLEAVER_csext
{

    meta:
        description = "Backdoor used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "COM+ System Extentions"
        $s2 = "csext.exe"
        $s3 = "COM_Extentions_bin"

    condition:
        all of them
}

rule OPCLEAVER_kagent
{

    meta:
        description = "Backdoor used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "kill command is in last machine, going back"
        $s2 = "message data length in B64: %d Bytes"

    condition:
        all of them
}

rule OPCLEAVER_mimikatzWrapper
{

    meta:
        description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "mimikatzWrapper"
        $s2 = "get_mimikatz"

    condition:
        all of them
}

rule OPCLEAVER_pvz_in
{

    meta:
        description = "Parviz tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "LAST_TIME=00/00/0000:00:00PM$"
        $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"

    condition:
        all of them
}

rule OPCLEAVER_pvz_out
{

    meta:
        description = "Parviz tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "Network Connectivity Module" wide
        $s2 = "OSPPSVC" wide

    condition:
        all of them
}

rule OPCLEAVER_wndTest
{

    meta:
        description = "Backdoor used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "[Alt]" wide
        $s2 = "<< %s >>:" wide
        $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"

    condition:
        all of them
}

rule OPCLEAVER_zhCat
{

    meta:
        description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
        $s2 = "ABC ( A Big Company )" wide fullword

    condition:
        all of them
}

rule OPCLEAVER_zhLookUp
{

    meta:
        description = "Hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "zhLookUp.Properties"

    condition:
        all of them
}

rule OPCLEAVER_zhmimikatz
{

    meta:
        description = "Mimikatz wrapper used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "MimikatzRunner"
        $s2 = "zhmimikatz"

    condition:
        all of them
}

rule OPCLEAVER_Parviz_Developer
{

    meta:
        description = "Parviz developer known from Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Florian Roth"
        score = "70"

    strings:
        $s1 = "Users\\parviz\\documents\\" nocase

    condition:
        $s1
}

rule OPCLEAVER_CCProxy_Config
{

    meta:
        description = "CCProxy config known from Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Florian Roth"
        score = "70"

    strings:
        $s1 = "UserName=User-001" fullword ascii
        $s2 = "Web=1" fullword ascii
        $s3 = "Mail=1" fullword ascii
        $s4 = "FTP=0" fullword ascii
        $x1 = "IPAddressLow=78.109.194.114" fullword ascii

    condition:
        all of ($s*) or $x1
}
