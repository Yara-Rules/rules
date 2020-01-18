rule crime_ole_loadswf_cve_2018_4878
{
meta:
description = "Detects CVE-2018-4878"
vuln_type = "Remote Code Execution"
vuln_impact = "Use-after-free"
affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
mitigation0 = "Implement Protected View for Office documents"
mitigation1 = "Disable Adobe Flash"
weaponization = "Embedded in Microsoft Office first payloads"
actor = "Purported North Korean actors"
reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
report = "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/"
author = "Vitali Kremez, Flashpoint"
version = "1.1"

strings:
// EMBEDDED FLASH OBJECT BIN HEADER
$header = "rdf:RDF" wide ascii

// OBJECT APPLICATION TYPE TITLE
$title = "Adobe Flex" wide ascii

// PDB PATH 
$pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii

// LOADER STRINGS
$s0 = "URLRequest" wide ascii
$s1 = "URLLoader" wide ascii
$s2 = "loadswf" wide ascii
$s3 = "myUrlReqest" wide ascii

condition:
all of ($header*) and all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)
}
