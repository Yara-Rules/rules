/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Win32OPCHavex
{
    meta:
        Author      = "BAE Systems"
        Date        = "2014/06/23"
        Description = "Rule for identifying OPC version of HAVEX"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $mzhdr = "MZ"
        $dll = "7CFC52CD3F87.dll"
        $a1 = "Start finging of LAN hosts..." wide
        $a2 = "Finding was fault. Unexpective error" wide
        $a3 = "Was found %i hosts in LAN:" wide
        $a4 = "Hosts was't found." wide
        $a5 = "Start finging of OPC Servers..." wide
        $a6 = "Was found %i OPC Servers." wide
        $a7 = "OPC Servers not found. Programm finished" wide
        $a8 = "%s[%s]!!!EXEPTION %i!!!" wide
        $a9 = "Start finging of OPC Tags..." wide

    condition:
        $mzhdr at 0 and ($dll or (any of ($a*)))
}

rule Win32FertgerHavex
{
    meta:
        Author      = "BAE Systems"
        Date        = "2014/06/23"
        Description = "Rule for identifying Fertger version of HAVEX"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $mz = "MZ"
        $a1="\\\\.\\pipe\\mypipe-f" wide
        $a2="\\\\.\\pipe\\mypipe-h" wide
        $a3="\\qln.dbx" wide
        $a4="*.yls" wide
        $a5="\\*.xmd" wide
        $a6="fertger" wide
        $a7="havex"
    
    condition:
        $mz at 0 and 3 of ($a*) 
}

rule Havex_Trojan_PHP_Server
{
    meta:
        Author      = "Florian Roth"
        Date        = "2014/06/24"
        Description = "Detects the PHP server component of the Havex RAT"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"

    condition:
        all of them
} 
rule SANS_ICS_Cybersecurity_Challenge_400_Havex_Memdump : memory
	{
	meta:
		description = "Detects Havex Windows process executable from memory dump"
		date = "2015-12-2"
		author = "Chris Sistrunk"
		hash = "8065674de8d79d1c0e7b3baf81246e7d"
	strings:
		$magic = { 4d 5a }	
	
	        $s1 = "~tracedscn.yls" fullword wide
		$s2 = "[!]Start" fullword wide
		$s3 = "[+]Get WSADATA" fullword wide
		$s4 = "[-]Can not get local ip" fullword wide
		$s5 = "[+]Local:" fullword wide
		$s6 = "[-]Threads number > Hosts number" fullword wide
		$s7 = "[-]Connection error" fullword wide
		
		$x1 = "bddd4e2b84fa2ad61eb065e7797270ff.exe" fullword wide
	condition:
	    $magic at 0 and ( 3 of ($s*) or $x1 )
}
