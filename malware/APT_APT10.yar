rule Dropper_DeploysMalwareViaSideLoading {
meta:
description = "Detect a dropper used to deploy an implant via side loading. This dropper has specifically been observed deploying REDLEAVES & PlugX"
author = "USG"
true_positive = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481: drops REDLEAVES. 6392e0701a77ea25354b1f40f5b867a35c0142abde785a66b83c9c8d2c14c0c3: drops plugx. "
reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
$UniqueString = {2e 6c 6e 6b [0-14] 61 76 70 75 69 2e 65 78 65} // ".lnk" near "avpui.exe"
$PsuedoRandomStringGenerator = {b9 1a [0-6] f7 f9 46 80 c2 41 88 54 35 8b 83 fe 64} // Unique function that generates a 100 character pseudo random string.

condition:
any of them
}

rule REDLEAVES_DroppedFile_ImplantLoader_Starburn {
meta:
description = "Detect the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
author = "USG"
true_positive = "7f8a867a8302fe58039a6db254d335ae" // StarBurn.dll
reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
strings:
        $XOR_Loop = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10} // Deobfuscation loop
condition:
        any of them
}

rule REDLEAVES_DroppedFile_ObfuscatedShellcodeAndRAT_handkerchief {
meta:
description = "Detect obfuscated .dat file containing shellcode and core REDLEAVES RAT"
author = "USG"
true_positive = "fb0c714cd2ebdcc6f33817abe7813c36" // handkerchief.dat
reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
    $RedleavesStringObfu = {73 64 65 5e 60 74 75 74 6c 6f 60 6d 5e 6d 64 60 77 64 72 5e 65 6d 6d 6c 60 68 6f 2f 65 6d 6d} // This is 'red_autumnal_leaves_dllmain.dll' XOR'd with 0x01
condition:
    any of them
}

rule REDLEAVES_CoreImplant_UniqueStrings {
meta:
description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
author = "USG"
reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
    $unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
    $unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
    $unique7 = "\\NamePipe_MoreWindows" wide ascii
condition:
  any of them
}

rule PLUGX_RedLeaves
{
meta:
author = "US-CERT Code Analysis Team"
date = "03042017"
incident = "10118538"
date = "2017/04/03"
MD5_1 = "598FF82EA4FB52717ACAFB227C83D474"
MD5_2 = "7D10708A518B26CC8C3CBFBAA224E032"
MD5_3 = "AF406D35C77B1E0DF17F839E36BCE630"
MD5_4 = "6EB9E889B091A5647F6095DCD4DE7C83"
MD5_5 = "566291B277534B63EAFC938CDAAB8A399E41AF7D"
info = "Detects specific RedLeaves and PlugX binaries"
reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
$s0 = { 80343057403D2FD0010072F433C08BFF80343024403D2FD0010072F4 }
$s1 = "C:/Users/user/Desktop/my_OK_2014/bit9/runsna/Release/runsna.pdb" fullword ascii
$s2 = "d:/work/plug4.0(shellcode)" fullword ascii
$s3 = "/shellcode/shellcode/XSetting.h" fullword ascii
$s4 = { 42AFF4276A45AA58474D4C4BE03D5B395566BEBCBDEDE9972872C5C4C5498228 }
$s5 = { 8AD32AD002D180C23830140E413BCB7CEF6A006A006A00566A006A00 }
$s6 = { EB055F8BC7EB05E8F6FFFFFF558BEC81ECC8040000535657 }
$s7 = { 8A043233C932043983C10288043283F90A7CF242890D18AA00103BD37CE2891514AA00106A006A006A0056 }
$s8 = { 293537675A402A333557B05E04D09CB05EB3ADA4A4A40ED0B7DAB7935F5B5B08 }
$s9 = "RedLeavesCMDSimulatorMutex"
condition:
$s0 or $s1 or $s2 and $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9
}
