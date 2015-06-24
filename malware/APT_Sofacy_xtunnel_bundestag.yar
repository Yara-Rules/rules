/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule apt_sofacy_xtunnel {
    meta:
        author = "Claudio Guarnieri"
        description = "Sofacy Malware - German Bundestag"
        score = 75
    strings:
        $xaps = ":\\PROJECT\\XAPS_"
        $variant11 = "XAPS_OBJECTIVE.dll" $variant12 = "start"
        $variant21 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"
        $variant22 = "is you live?"
        $mix1 = "176.31.112.10"
        $mix2 = "error in select, errno %d" $mix3 = "no msg"
        $mix4 = "is you live?"
        $mix5 = "127.0.0.1"
        $mix6 = "err %d"
        $mix7 = "i`m wait"
        $mix8 = "hello"
        $mix9 = "OpenSSL 1.0.1e 11 Feb 2013" $mix10 = "Xtunnel.exe"
    condition:
        ((uint16(0) == 0x5A4D) or (uint16(0) == 0xCFD0)) and (($xaps) or (all of ($variant1*)) or (all of ($variant2*)) or (6 of ($mix*))) 
}

rule Sofacy_Bundestag_Winexe {
    meta:
        description = "Winexe tool used by Sofacy group in Bundestag APT"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
        score = 70
    strings:
        $s1 = "\\\\.\\pipe\\ahexec" fullword ascii 
        $s2 = "implevel" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule Sofacy_Bundestag_Mal2 {
    meta:
        description = "Sofacy Group Malware Sample 2"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"
        score = 70
    strings:
        $x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
        $x2 = "XAPS_OBJECTIVE.dll" fullword ascii

        $s1 = "i`m wait" fullword ascii 
    condition:
        uint16(0) == 0x5a4d and ( 1 of ($x*) ) and $s1
}

rule Sofacy_Bundestag_Mal3 {
    meta:
        description = "Sofacy Group Malware Sample 3"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "5f6b2a0d1d966fc4f1ed292b46240767f4acb06c13512b0061b434ae2a692fa1"
        score = 70
    strings:
        $s1 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" fullword ascii 
        $s2 = ".?AVAgentModuleRemoteKeyLogger@@" fullword ascii 
        $s3 = "<font size=4 color=red>process isn't exist</font>" fullword ascii 
        $s4 = "<font size=4 color=red>process is exist</font>" fullword ascii 
        $s5 = ".winnt.check-fix.com" fullword ascii 
        $s6 = ".update.adobeincorp.com" fullword ascii 
        $s7 = ".microsoft.checkwinframe.com" fullword ascii
        $s8 = "adobeincorp.com" fullword wide 
        $s9 = "# EXC: HttpSender - Cannot create Get Channel!" fullword ascii 

        $x1 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" wide 
        $x2 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" wide 
        $x3 = "C:\\Windows\\System32\\cmd.exe" fullword wide 
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (
            2 of ($s*) or 
            ( 1 of ($s*) and all of ($x*) )
        ) 
}

rule Sofacy_Bundestag_Batch {
    meta:
        description = "Sofacy Bundestags APT Batch Script"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        score = 70
    strings:
        $s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx) do (" ascii 
        $s2 = "cmd /c copy"
        $s3 = "forfiles"
    condition:
        filesize < 10KB and all of them
}

