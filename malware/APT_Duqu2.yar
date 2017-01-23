/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule apt_duqu2_loaders 
{ 

    meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 samples"
		last_modified = "2015-06-09"
		version = "1.0"

    strings:
		$a1 = "{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide 
		$a2 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a4 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
		$a5 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
		$a8 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" wide
		$a9 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" wide
		$a7 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" wide
		$b1 = "MSI.dll"
		$b2 = "msi.dll"
		$b3 = "StartAction"
		$c1 = "msisvc_32@" wide
		$c2 = "PROP=" wide
		$c3 = "-Embedding" wide
		$c4 = "S:(ML;;NW;;;LW)" wide
		$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
		$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}
	
    condition:
		( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 ) or ( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}

rule apt_duqu2_drivers 
{ 

    meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 drivers"
		last_modified = "2015-06-09"
		version = "1.0"
	
    strings:
		$a1 = "\\DosDevices\\port_optimizer" wide nocase 
		$a2 = "romanian.antihacker" 
		$a3 = "PortOptimizerTermSrv" wide 
		$a4 = "ugly.gorilla1"
		$b1 = "NdisIMCopySendCompletePerPacketInfo" 
		$b2 = "NdisReEnumerateProtocolBindings"
		$b3 = "NdisOpenProtocolConfiguration"
	condition:
		uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000
}

/* Action Loader Samples --------------------------------------------------- */

rule Duqu2_Generic1 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Generic Rule"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		super_rule = 1
		hash0 = "3f9168facb13429105a749d35569d1e91465d313"
		hash1 = "0a574234615fb2382d85cd6d1a250d6c437afecc"
		hash2 = "38447ed1d5e3454fe17699f86c0039f30cc64cde"
		hash3 = "5282d073ee1b3f6ce32222ccc2f6066e2ca9c172"
		hash4 = "edfca3f0196788f7fde22bd92a8817a957c10c52"
		hash5 = "6a4ffa6ca4d6fde8a30b6c8739785f4bd2b5c415"
		hash6 = "00170bf9983e70e8dd4f7afe3a92ce1d12664467"
		hash7 = "32f8689fd18c723339414618817edec6239b18f3"
		hash8 = "f860acec9920bc009a1ad5991f3d5871c2613672"
		hash9 = "413ba509e41c526373f991d1244bc7c7637d3e13"
		hash10 = "29cd99a9b6d11a09615b3f9ef63f1f3cffe7ead8"
		hash11 = "dfe1cb775719b529138e054e7246717304db00b1"
	
    strings:
		$s0 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" fullword wide
		$s1 = "SetSecurityDescriptorSacl" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 189 times */
		$s2 = "msisvc_32@" fullword wide
		$s3 = "CompareStringA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1392 times */
		$s4 = "GetCommandLineW" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1680 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule APT_Kaspersky_Duqu2_procexp 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
		hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
		hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"
	
    strings:
		$x1 = "svcmsi_32.dll" fullword wide
		$x2 = "msi3_32.dll" fullword wide
		$x3 = "msi4_32.dll" fullword wide
		$x4 = "MSI.dll" fullword ascii
		$s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "Sysinternals installer" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "Process Explorer" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 5 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) ) and ( all of ($s*) )
}

rule APT_Kaspersky_Duqu2_SamsungPrint 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - file 2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "ce39f41eb4506805efca7993d3b0b506ab6776ca"
	
    strings:
		$s0 = "Installer for printer drivers and applications" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "msi4_32.dll" fullword wide
		$s2 = "HASHVAL" fullword wide
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword wide
	
    condition:
		uint16(0) == 0x5a4d and filesize < 82KB and all of them
}

rule APT_Kaspersky_Duqu2_msi3_32 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - file d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
	
    strings:
		$s0 = "ProcessUserAccounts" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s4 = "msi3_32.dll" fullword wide
		$s5 = "RunDLL" fullword ascii
		$s6 = "MSI Custom Action v3" fullword wide
		$s7 = "msi3_32" fullword wide
		$s8 = "Operating System" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 9203 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 72KB and all of them
}
