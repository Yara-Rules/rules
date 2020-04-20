/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Dridex_Trojan_XML : maldoc {
	meta:
		description = "Dridex Malware in XML Document"
		author = "Florian Roth @4nc4p"
		reference = "https://threatpost.com/dridex-banking-trojan-spreading-via-macros-in-xml-files/111503"
		date = "2015/03/08"
		hash1 = "88d98e18ed996986d26ce4149ae9b2faee0bc082"
		hash2 = "3b2d59adadf5ff10829bb5c27961b22611676395"
		hash3 = "e528671b1b32b3fa2134a088bfab1ba46b468514"
		hash4 = "981369cd53c022b434ee6d380aa9884459b63350"
		hash5 = "96e1e7383457293a9b8f2c75270b58da0e630bea"
	strings:
		// can be ascii or wide formatted - therefore no restriction
		$c_xml      = "<?xml version="
		$c_word     = "<?mso-application progid=\"Word.Document\"?>"
		$c_macro    = "w:macrosPresent=\"yes\""
		$c_binary   = "<w:binData w:name="
		$c_0_chars  = "<o:Characters>0</o:Characters>"
		$c_1_line   = "<o:Lines>1</o:Lines>"
	condition:
		all of ($c*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-02
	Identifier: Phishing Gina Harrowell Dez 2015
*/

rule PHISH_02Dez2015_dropped_p0o6543f {
	meta:
		description = "Phishing Wave - file p0o6543f.exe"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210"
	strings:
		$s1 = "netsh.exe" fullword wide
		$s2 = "routemon.exe" fullword wide
		$s3 = "script=" fullword wide /* Goodware String - occured 4 times */
		$s4 = "disconnect" fullword wide /* Goodware String - occured 14 times */
		$s5 = "GetClusterResourceTypeKey" fullword ascii /* Goodware String - occured 17 times */
		$s6 = "QueryInformationJobObject" fullword ascii /* Goodware String - occured 34 times */
		$s7 = "interface" fullword wide /* Goodware String - occured 52 times */
		$s8 = "connect" fullword wide /* Goodware String - occured 61 times */
		$s9 = "FreeConsole" fullword ascii /* Goodware String - occured 91 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658 {
	meta:
		description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
	strings:
		$s1 = "Execute" ascii
		$s2 = "Process WriteParameterFiles" fullword ascii
		$s3 = "WScript.Shell" fullword ascii
		$s4 = "STOCKMASTER" fullword ascii
		$s5 = "InsertEmailFax" ascii
	condition:
		uint16(0) == 0xcfd0 and filesize < 200KB and all of them
}

