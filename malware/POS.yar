/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
// Point of Sale (POS) Malware and Tools used during POS compromises

rule blackpos_v2
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	reference = "http://blog.nuix.com/2014/09/08/blackpos-v2-new-variant-or-different-family"
strings:
	$s1 = "Usage: -[start|stop|install|uninstall"
	$s2 = "\\SYSTEM32\\sc.exe config LanmanWorkstation"
	$s3 = "t.bat"
	$s4 = "mcfmisvc"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule dump_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Related to pwdump6 and fgdump tools"
strings:
	$s1 = "lsremora"
	$s2 = "servpw"
	$s3 = "failed: %d"
	$s4 = "fgdump"
	$s5 = "fgexec"
	$s6 = "fgexecpipe"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule osql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "O/I SQL - SQL query tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "osql\\src"
	$s2 = "OSQLUSER"
	$s3 = "OSQLPASSWORD"
	$s4 = "OSQLSERVER"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule misc_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS Malware"
strings:
	$s1 = "KAPTOXA"
	$s2 = "cmd /c net start %s"
	$s3 = "pid:"
	$s4 = "%ADD%"
	$s5 = "COMSPEC"
	$s6 = "KARTOXA"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule unknown
{
meta:
	author = "@patrickrolsen"
	reference = "Unknown POS"
strings:
	$s1 = "a.exe" wide
	$s2 = "Can anyone test" wide
	$s3 = "I m in computer class now" wide
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule regex_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Regex"
strings:
	$n1 = "REGEXEND" nocase
	$n2 = "RegExpr" nocase
	$n3 = "regex"
	$s4 = "[1-5][0-9]{14}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s5 = "[47][0-9]{13}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s6 = "(?:0[0-5]|[68][0-9])[0-9]{11}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s7 = "(?:011|5[0-9]{2})[0-9]{12}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s8 = "(?:2131|1800|35\\d{3})\\d{11}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s9 = "([0-9]{15,16}[D=](0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9]{8,30})"
	$s10 = "((b|B)[0-9]{13,19}\\^[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\^(0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9\\s]{3,50}[0-9]{1})"
	$s11 = "[0-9]*\\^[a-zA-Z]*/[a-zA-Z ]*\\^[0-9]*"
	$s12 = "\\d{15,19}=\\d{13,}"
	$s13 = "\\;?[3-9]{1}[0-9]{12,19}[D=\\u0061][0-9]{10,30}\\??"
	$s14 = "[0-9]{12}(?:[0-9]{3})?=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
condition:
	uint16(0) == 0x5A4D and 1 of ($n*) and 1 of ($s*)
}

rule regexpr_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "RegExpr" nocase
	$s2 = "Data.txt"
	$s3 = "Track1"
	$s4 = "Track2"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule reg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "T1_FOUND: %s"
	$s2 = "id=%s&log=%s"
	$s3 = "\\d{15,19}=\\d{13,}"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}

rule sets_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Sets"
strings:
	$s1 = "GET /sets.txt"
condition:
	uint16(0) == 0x5A4D and $s1
}

rule monitor_tool_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Monitoring Tool??"
strings:
	$s1 = "RCPT TO"
	$s2 = "MAIL FROM"
	$s3 = "AUTH LOGIN"
	$s4 = "Reply-To"
	$s5 = "X-Mailer"
	$s6 = "crypto"
	$s7 = "test335.txt" wide
	$s8 = "/c del"
condition:
	uint16(0) == 0x5A4D and 7 of ($s*)
}

rule pstgdump
{
meta:
	author = "@patrickrolsen"
	reference = "pstgdump"
strings:
	$s1 = "fgdump\\pstgdump"
	$s2 = "pstgdump"
	$s3 = "Outlook"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule keyfinder_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Magical Jelly Bean KeyFinder"
strings:
	$s1 = "chgxp.vbs"
	$s2 = "officekey.exe"
	$s3 = "findkey.exe"
	$s4 = "xpkey.exe"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}

rule memdump_diablo
{
meta:
	author = "@patrickrolsen"
	reference = "Process Memory Dumper - DiabloHorn"
strings:
	$s1 = "DiabloHorn"
	$s2 = "Process Memory Dumper"
	$s3 = "pid-%s.dmp"
	$s4 = "Pid %d in not acessible" // SIC
	$s5 = "memdump.exe"
	$s6 = "%s-%d.dmp"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule blazingtools
{
meta:
	author = "@patrickrolsen"
	reference = "Blazing Tools - http://www.blazingtools.com (Keyloggers)"
strings:
	$s1 = "blazingtools.com"
	$s2 = "Keystrokes" wide
	$s3 = "Screenshots" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule sysocmgr
{
meta:
	author = "@patrickrolsen"
	reference = "System stand-alone Optional Component Manager - http://support.microsoft.com/kb/222444"
strings:
	$s1 = "SYSOCMGR.EXE" wide
	$s2 = "System stand-alone Optional Component Manager" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule lacy_keylogger
{
meta:
	author = "@patrickrolsen"
	reference = "Appears to be a form of keylogger."
strings:
	$s1 = "Lacy.exe" wide
	$s2 = "Bldg Chive Duel Rip Query" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule searchinject
{
meta:
	author = "@patrickrolsen"
	reference = "Usage: SearchInject <PID1>[PID2][PID3] - It loads Searcher.dll (appears to be hard coded)"
strings:
	$s1 = "SearchInject"
	$s2 = "inject base:"
	$s3 = "Searcher.dll" nocase
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule heistenberg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS Malware"
strings:
	$s1 = "KARTOXA"
	$s2 = "dmpz.log"
	$s3 = "/api/process.php?xy="
	$s4 = "User-Agent: PCICompliant" // PCICompliant/3.33
	$s6 = "%s:*:Enabled:%s"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule pos_jack
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
	version = "0.1"
	reference = "http://blog.spiderlabs.com/2014/02/jackpos-the-house-always-wins.html"
	date = "2/22/2014"
strings:
	$pdb1 = "\\ziedpirate.ziedpirate-PC\\"
	$pdb2 = "\\sop\\sop\\"
condition:
	uint16(0) == 0x5A4D and 1 of ($pdb*)
}

rule pos_memory_scrapper_
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware Memory Scraper"
	version = "0.3"
	description = "POS Memory Scraper"
	date = "01/30/2014"
strings:
	$s1 = "kartoxa" nocase
	$s2 = "CC2 region:"
	$s3 = "CC memregion:"
	$s4 = "target pid:"
	$s5 = "scan all processes:"
	$s6 = "<pid> <PATTERN>"
	$s7 = "KAPTOXA"
	$s8 = "ATTERN"
	$s9 = "\\svhst%p"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule pos_malwre_dexter_stardust
{
meta:
	author = "@patrickrolsen"
	maltype = "Dexter Malware - StarDust Variant"
	version = "0.1"
	description = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
	reference = "16b596de4c0e4d2acdfdd6632c80c070, 2afaa709ef5260184cbda8b521b076e1, and e3dd1dc82ddcfaf410372ae7e6b2f658"
	date = "12/30/2013"
strings:
	$s1 = "ceh_3\\.\\ceh_4\\..\\ceh_6"
	$s2 = "Yatoed3fe3rex23030am39497403"
	$s3 = "Poo7lo276670173quai16568unto1828Oleo9eds96006nosysump7hove19"
	$s4 = "CommonFile.exe"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}
    
rule pos_malware_project_hook
{
meta:
	author = "@patrickrolsen"
	maltype = "Project Hook"
	version = "0.1"
	description = "Table 1 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
	reference = "759154d20849a25315c4970fe37eac59"
	date = "12/30/2013"
strings:
	$s1 = "CallImage.exe"
	$s2 = "BurpSwim"
	$s3 = "Work\\Project\\Load"
	$s4 = "WortHisnal"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule pdb_strings_Rescator
{
meta:
	author = "@patrickrolsen"
	maltype = "Target Attack"
	version = "0.3"
	description = "Rescator PDB strings within binaries"
	date = "01/30/2014"
strings:
	$pdb1 = "\\Projects\\Rescator" nocase
condition:
	uint16(0) == 0x5A4D and $pdb1
}

rule pos_uploader
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "http://blogs.mcafee.com/mcafee-labs/analyzing-the-target-point-of-sale-malware"
	version = "0.1"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "cmd /c net start %s"
	$s2 = "ftp -s:%s"
	$s3 = "data_%d_%d_%d_%d_%d.txt"
	$s4 = "\\uploader\\"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule winxml_dll
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "ce0296e2d77ec3bb112e270fc260f274"
	version = "0.1"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "\\system32\\winxml.dll"
	//$s2 = "cmd /c net start %s"
	//$s3 = "=== pid:"
	//$s4 = "GOTIT"
	//$s5 = ".memdump"
	//$s6 = "POSWDS"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule pos_chewbacca
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "https://www.securelist.com/en/blog/208214185/ChewBacca_a_new_episode_of_Tor_based_Malware"
    hashes = "21f8b9d9a6fa3a0cd3a3f0644636bf09, 28bc48ac4a92bde15945afc0cee0bd54"
	version = "0.2"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "tor -f <torrc>"
	$s2 = "tor_"
	$s3 = "umemscan"
	$s4 = "CHEWBAC"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
