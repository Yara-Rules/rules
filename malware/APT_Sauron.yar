/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
    Warning: Don't use this rule set without excluding the false positive hashes listed in the file falsepositive-hashes.txt from https://github.com/Neo23x0/Loki/blob/master/signatures/falsepositive-hashes.txt

*/

import "pe"
import "math"

rule apt_ProjectSauron_pipe_backdoor  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron pipe backdoors"
        version = "1.0"    
        reference = "https://securelist.com/blog/"
   
    strings:
        $a1 = "CreateNamedPipeW" fullword ascii
        $a2 = "SetSecurityDescriptorDacl" fullword ascii
        $a3 = "GetOverlappedResult" fullword ascii
        $a4 = "TerminateThread" fullword ascii
        $a5 = "%s%s%X" fullword wide  

    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 100000
}

rule apt_ProjectSauron_encrypted_LSA  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron encrypted LSA samples"
        version = "1.0"    
        reference = "https://securelist.com/blog/"

    strings:
        $a1 = "EFEB0A9C6ABA4CF5958F41DB6A31929776C643DEDC65CC9B67AB8B0066FF2492" fullword ascii
        $a2 = "\\Device\\NdisRaw_" fullword ascii
        $a3 = "\\\\.\\GLOBALROOT\\Device\\{8EDB44DC-86F0-4E0E-8068-BD2CABA4057A}" fullword wide
        $a4 = "Global\\{a07f6ba7-8383-4104-a154-e582e85a32eb}" fullword wide
        $a5 = "Missing function %S::#%d" fullword wide
        $a6 = {8945D08D8598FEFFFF2BD08945D88D45BC83C20450C745C0030000008975C48955DCFF55FC8BF88D8F0000003A83F90977305333DB53FF15}
        $a7 = {488D4C24304889442450488D452044886424304889442460488D4520C7442434030000002BD848897C243844896C244083C308895C246841FFD68D880000003A8BD883F909772DFF}

    condition:
        uint16(0) == 0x5A4D and (any of ($a*) or ( pe.exports("InitializeChangeNotify") and pe.exports("PasswordChangeNotify") and math.entropy(0x400, filesize) >= 7.5 )) and filesize < 1000000
}

rule apt_ProjectSauron_encrypted_SSPI  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect encrypted ProjectSauron SSPI samples"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    condition:
        uint16(0) == 0x5A4D and filesize < 1000000 and pe.exports("InitSecurityInterfaceA") and pe.characteristics & pe.DLL and (pe.machine == pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_IA64) and math.entropy(0x400, filesize) >= 7.5 }

rule apt_ProjectSauron_MyTrampoline  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron MyTrampoline module"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $a1 = ":\\System Volume Information\\{" wide
        $a2 = "\\\\.\\PhysicalDrive%d" wide
        $a3 = "DMWndClassX%d"
        $b1 = "{774476DF-C00F-4e3a-BF4A-6D8618CFA532}" ascii wide
        $b2 = "{820C02A4-578A-4750-A409-62C98F5E9237}" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 5000000 and (all of ($a*) or any of ($b*)) }

rule apt_ProjectSauron_encrypted_container  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron samples encrypted container"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $vfs_header = {02 AA 02 C1 02 0?}
        $salt = {91 0A E0 CC 0D FE CE 36 78 48 9B 9C 97 F7 F5 55}

    condition:
        uint16(0) == 0x5A4D and ((@vfs_header < 0x4000) or $salt) and math.entropy(0x400, filesize) >= 6.5 and (filesize > 0x400) and filesize < 10000000 }

rule apt_ProjectSauron_encryption  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron string encryption"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $a1 = {81??02AA02C175??8B??0685}
        $a2 = {918D9A94CDCC939A93939BD18B9AB8DE9C908DAF8D9B9BBE8C8C9AFF}
        $a3 = {803E225775??807E019F75??807E02BE75??807E0309}

    condition:
        filesize < 5000000 and any of ($a*)
}

rule apt_ProjectSauron_generic_pipe_backdoor 
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron generic pipe backdoors"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $a = { C7 [2-3] 32 32 32 32 E8 }
        $b = { 42 12 67 6B }
        $c = { 25 31 5F 73 }
        $d = "rand"
        $e = "WS2_32"

condition:
    uint16(0) == 0x5A4D and (all of them) and filesize < 400000

}

