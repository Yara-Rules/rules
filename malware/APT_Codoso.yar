/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-30
	Identifier: Codoso
	Comment: Reduced signature set for LOKI integration
*/

/* Rule Set ----------------------------------------------------------------- */

rule Codoso_PlugX_3
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "74e1e83ac69e45a3bee78ac2fac00f9e897f281ea75ed179737e9b6fe39971e3"

    strings:
        $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
        $s2 = "mcs.exe" fullword ascii
        $s3 = "McAltLib.dll" fullword ascii
        $s4 = "WinRAR self-extracting archive" fullword wide

    condition:
        uint16(0) == 0x5a4d and filesize < 1200KB and all of them
}

rule Codoso_PlugX_2
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "b9510e4484fa7e3034228337768176fce822162ad819539c6ca3631deac043eb"

    strings:
        $s1 = "%TEMP%\\HID" fullword wide
        $s2 = "%s\\hid.dll" fullword wide
        $s3 = "%s\\SOUNDMAN.exe" fullword wide
        $s4 = "\"%s\\SOUNDMAN.exe\" %d %d" fullword wide
        $s5 = "%s\\HID.dllx" fullword wide

    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them ) or all of them
}

rule Codoso_CustomTCP_4
{

    meta:
        description = "Detects Codoso APT CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash1 = "ea67d76e9d2e9ce3a8e5f80ff9be8f17b2cd5b1212153fdf36833497d9c060c0"
        hash2 = "130abb54112dd47284fdb169ff276f61f2b69d80ac0a9eac52200506f147b5f8"
        hash3 = "3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa"
        hash4 = "02cf5c244aebaca6195f45029c1e37b22495609be7bdfcfcd79b0c91eac44a13"

    strings:
        $x1 = "varus_service_x86.dll" fullword ascii
        $s1 = "/s %s /p %d /st %d /rt %d" fullword ascii
        $s2 = "net start %%1" fullword ascii
        $s3 = "ping 127.1 > nul" fullword ascii
        $s4 = "McInitMISPAlertEx" fullword ascii
        $s5 = "sc start %%1" fullword ascii
        $s6 = "net stop %%1" fullword ascii
        $s7 = "WorkerRun" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and 5 of them ) or ( $x1 and 2 of ($s*) )
}

rule Codoso_CustomTCP_3
{

    meta:
        description = "Detects Codoso APT CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"

    strings:
        $s1 = "DnsApi.dll" fullword ascii
        $s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
        $s3 = "CONNECT %s:%d hTTP/1.1" ascii
        $s4 = "CONNECT %s:%d HTTp/1.1" ascii
        $s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
        $s6 = "iphlpapi.dll" ascii
        $s7 = "%systemroot%\\Web\\" ascii
        $s8 = "Proxy-Authorization: Negotiate %s" ascii
        $s9 = "CLSID\\{%s}\\InprocServer32" ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 500KB and 5 of them ) or 7 of them
}

rule Codoso_CustomTCP_2
{

    meta:
        description = "Detects Codoso APT CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"

    strings:
        $s1 = "varus_service_x86.dll" fullword ascii
        $s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
        $s3 = "net start %%1" fullword ascii
        $s4 = "ping 127.1 > nul" fullword ascii
        $s5 = "McInitMISPAlertEx" fullword ascii
        $s6 = "sc start %%1" fullword ascii
        $s7 = "B_WKNDNSK^" fullword ascii
        $s8 = "net stop %%1" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 406KB and all of them
}

rule Codoso_PGV_PVID_6
{

    meta:
        description = "Detects Codoso APT PGV_PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"

    strings:
        $s0 = "rundll32 \"%s\",%s" fullword ascii
        $s1 = "/c ping 127.%d & del \"%s\"" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}

rule Codoso_Gh0st_3
{

    meta:
        description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"

    strings:
        $x1 = "RunMeByDLL32" fullword ascii
        $s1 = "svchost.dll" fullword wide
        $s2 = "server.dll" fullword ascii
        $s3 = "Copyright ? 2008" fullword wide
        $s4 = "testsupdate33" fullword ascii
        $s5 = "Device Protect Application" fullword wide
        $s6 = "MSVCP60.DLL" fullword ascii /* Goodware String - occured 1 times */
        $s7 = "mail-news.eicp.net" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 195KB and $x1 or 4 of them
}

rule Codoso_Gh0st_2
{

    meta:
        description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"

    strings:
        $s0 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
        $s1 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
        $s13 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
        $s14 = "%s -r debug 1" fullword ascii
        $s15 = "\\\\.\\keymmdrv1" fullword ascii
        $s17 = "RunMeByDLL32" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}

rule Codoso_CustomTCP
{

    meta:
        description = "Codoso CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"

    strings:
        $s4 = "wnyglw" fullword ascii
        $s5 = "WorkerRun" fullword ascii
        $s7 = "boazdcd" fullword ascii
        $s8 = "wayflw" fullword ascii
        $s9 = "CODETABL" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 405KB and all of them
}

/* Super Rules ------------------------------------------------------------- */

rule Codoso_PGV_PVID_5
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $s1 = "/c del %s >> NUL" fullword ascii
        $s2 = "%s%s.manifest" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Codoso_Gh0st_1
{

    meta:
        description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
        hash2 = "7dc7cec2c3f7e56499175691f64060ebd955813002d4db780e68a8f6e7d0a8f8"
        hash3 = "d7004910a87c90ade7e5ff6169f2b866ece667d2feebed6f0ec856fb838d2297"

    strings:
        $x1 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
        $x2 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
        $x3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
        $x4 = "\\\\.\\keymmdrv1" fullword ascii
        $s1 = "spideragent.exe" fullword ascii
        $s2 = "AVGIDSAgent.exe" fullword ascii
        $s3 = "kavsvc.exe" fullword ascii
        $s4 = "mspaint.exe" fullword ascii
        $s5 = "kav.exe" fullword ascii
        $s6 = "avp.exe" fullword ascii
        $s7 = "NAV.exe" fullword ascii
        $c1 = "Elevation:Administrator!new:" wide
        $c2 = "Global\\RUNDLL32EXITEVENT_NAME{12845-8654-543}" fullword ascii
        $c3 = "\\sysprep\\sysprep.exe" fullword wide
        $c4 = "\\sysprep\\CRYPTBASE.dll" fullword wide
        $c5 = "Global\\TERMINATEEVENT_NAME{12845-8654-542}" fullword ascii
        $c6 = "ConsentPromptBehaviorAdmin" fullword ascii
        $c7 = "\\sysprep" fullword wide
        $c8 = "Global\\UN{5FFC0C8B-8BE5-49d5-B9F2-BCDC8976EE10}" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and ( 4 of ($s*) or 4 of ($c*) ) or 1 of ($x*) or 6 of ($c*)
}

rule Codoso_PGV_PVID_4
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash2 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
        hash3 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
        hash4 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
        hash5 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $x1 = "dropper, Version 1.0" fullword wide
        $x2 = "dropper" fullword wide
        $x3 = "DROPPER" fullword wide
        $x4 = "About dropper" fullword wide
        $s1 = "Microsoft Windows Manager Utility" fullword wide
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\" fullword ascii /* Goodware String - occured 9 times */
        $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" fullword ascii /* Goodware String - occured 10 times */
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* Goodware String - occured 46 times */
        $s5 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></supportedOS>" fullword ascii /* Goodware String - occured 65 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 900KB and 1 of ($x*) and 2 of ($s*)
}

rule Codoso_PlugX_1
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "0b8cbc9b4761ab35acce2aa12ba2c0a283afd596b565705514fd802c8b1e144b"
        hash2 = "448711bd3f689ceebb736d25253233ac244d48cb766834b8f974c2e9d4b462e8"
        hash3 = "fd22547497ce52049083092429eeff0599d0b11fe61186e91c91e1f76b518fe2"

    strings:
        $s1 = "GETPASSWORD1" fullword ascii
        $s2 = "NvSmartMax.dll" fullword ascii
        $s3 = "LICENSEDLG" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule Codoso_PGV_PVID_3
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "126fbdcfed1dfb31865d4b18db2fb963f49df838bf66922fea0c37e06666aee1"
        hash2 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash3 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
        hash4 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
        hash5 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
        hash6 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $x1 = "Copyright (C) Microsoft Corporation.  All rights reserved.(C) 2012" fullword wide

    condition:
        $x1
}

rule Codoso_PGV_PVID_2
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash2 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
        hash3 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
        $s1 = "regsvr32.exe /s \"%s\"" fullword ascii
        $s2 = "Help and Support" fullword ascii
        $s3 = "netsvcs" fullword ascii
        $s9 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" fullword ascii /* Goodware String - occured 4 times */
        $s10 = "winlogon" fullword ascii /* Goodware String - occured 4 times */
        $s11 = "System\\CurrentControlSet\\Services" fullword ascii /* Goodware String - occured 11 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Codoso_PGV_PVID_1
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
        hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
        hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
        hash4 = "ce91ea20aa2e6af79508dd0a40ab0981f463b4d2714de55e66d228c579578266"
        hash5 = "e770a298ae819bba1c70d0c9a2e02e4680d3cdba22d558d21caaa74e3970adf1"

    strings:
        $x1 = "Cookie: pgv_pvid=" ascii
        $x2 = "DRIVERS\\ipinip.sys" fullword wide
        $s1 = "TsWorkSpaces.dll" fullword ascii
        $s2 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
        $s3 = "/selfservice/microsites/search.php?%016I64d" fullword ascii
        $s4 = "/solutions/company-size/smb/index.htm?%016I64d" fullword ascii
        $s5 = "Microsoft Chart ActiveX Control" fullword wide
        $s6 = "MSChartCtrl.ocx" fullword wide
        $s7 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
        $s8 = "WUServiceMain" fullword ascii /* Goodware String - occured 2 times */
    condition:
        ( uint16(0) == 0x5a4d and ( 1 of ($x*) or 3 of them ) ) or 5 of them
}
