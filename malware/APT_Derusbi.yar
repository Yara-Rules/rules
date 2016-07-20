/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule apt_nix_elf_derusbi : APT Derusbi ELF
{
        meta:
        Author = "@seifreed"
	strings:
		$ = "LxMain"
		$ = "execve"
		$ = "kill"
		$ = "cp -a %s %s"
		$ = "%s &"
		$ = "dbus-daemon"
		$ = "--noprofile"
		$ = "--norc"
		$ = "TERM=vt100"
		$ = "/proc/%u/cmdline"
		$ = "loadso"
		$ = "/proc/self/exe"
		$ = "Proxy-Connection: Keep-Alive"
		$ = "Connection: Keep-Alive"
		$ = "CONNECT %s"
		$ = "HOST: %s:%d"
		$ = "User-Agent: Mozilla/4.0"
		$ = "Proxy-Authorization: Basic %s"
		$ = "Server: Apache"
		$ = "Proxy-Authenticate"
		$ = "gettimeofday"
		$ = "pthread_create"
		$ = "pthread_join"
		$ = "pthread_mutex_init"
		$ = "pthread_mutex_destroy"
		$ = "pthread_mutex_lock"
		$ = "getsockopt"
		$ = "socket"
		$ = "setsockopt"
		$ = "select"
		$ = "bind"
		$ = "shutdown"
		$ = "listen"
		$ = "opendir"
		$ = "readdir"
		$ = "closedir"
		$ = "rename"

	condition:
		(uint32(0) == 0x4464c457f) and (all of them)
}
rule apt_nix_elf_derusbi_kernelModule : APT Derusbi ELF
{
	meta:
        Author = "@seifreed"
	strings:
		$ = "__this_module"   
		$ = "init_module"      
		$ = "unhide_pid"       
		$ = "is_hidden_pid"    
		$ = "clear_hidden_pid" 
		$ = "hide_pid"
		$ = "license"
		$ = "description"
		$ = "srcversion="
		$ = "depends="
		$ = "vermagic="
		$ = "current_task"
		$ = "sock_release"
		$ = "module_layout"
		$ = "init_uts_ns"
		$ = "init_net"
		$ = "init_task"
		$ = "filp_open"
		$ = "__netlink_kernel_create"
		$ = "kfree_skb"

	condition:
		(uint32(0) == 0x4464c457f) and (all of them)
}
rule apt_nix_elf_Derusbi_Linux_SharedMemCreation : APT Derusbi ELF
{
	meta:
        Author = "@seifreed"
	strings:
		$byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }
	condition:
		(uint32(0) == 0x464C457F) and (any of them)
}

rule apt_nix_elf_Derusbi_Linux_Strings : APT Derusbi ELF
{
	meta:
        Author = "@seifreed"
        strings:
    	$a1 = "loadso" wide ascii fullword
        	$a2 = "\nuname -a\n\n" wide ascii
        	$a3 = "/dev/shm/.x11.id" wide ascii
        	$a4 = "LxMain64" wide ascii nocase
        	$a5 = "# \\u@\\h:\\w \\$ " wide ascii
        	$b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
        	$b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
			$b3 = "ret %d" wide fullword
        	$b4 = "uname -a\n\n" wide ascii
        	$b5 = "/proc/%u/cmdline" wide ascii
			$b6 = "/proc/self/exe" wide ascii
			$b7 = "cp -a %s %s" wide ascii
			$c1 = "/dev/pts/4" wide ascii fullword
        	$c2 = "/tmp/1408.log" wide ascii fullword
	condition:
		uint32(0) == 0x464C457F and
		((1 of ($a*) and 4 of ($b*)) or
		(1 of ($a*) and 1 of ($c*)) or
		2 of ($a*) or
		all of ($b*))
}

rule apt_win_exe_trojan_derusbi : APT Derusbi 
{
   meta:
          Author = "@seifreed"
   strings:
	  $sa_1 = "USB" wide ascii
	  $sa_2 = "RAM" wide ascii
	  $sa_3 = "SHARE" wide ascii
	  $sa_4 = "HOST: %s:%d"
	  $sa_5 = "POST"
	  $sa_6 = "User-Agent: Mozilla"
	  $sa_7 = "Proxy-Connection: Keep-Alive"
	  $sa_8 = "Connection: Keep-Alive"
	  $sa_9 = "Server: Apache"
	  $sa_10 = "HTTP/1.1"
	  $sa_11 = "ImagePath"
	  $sa_12 = "ZwUnloadDriver"
	  $sa_13 = "ZwLoadDriver"
	  $sa_14 = "ServiceMain"
	  $sa_15 = "regsvr32.exe"
	  $sa_16 = "/s /u" wide ascii
	  $sa_17 = "rand"
	  $sa_18 = "_time64"
	  $sa_19 = "DllRegisterServer"
	  $sa_20 = "DllUnregisterServer"
	  $sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 } // Decode Driver

	  $sb_1 = "PCC_CMD_PACKET"
	  $sb_2 = "PCC_CMD"
	  $sb_3 = "PCC_BASEMOD"
	  $sb_4 = "PCC_PROXY"
	  $sb_5 = "PCC_SYS"
	  $sb_6 = "PCC_PROCESS"
	  $sb_7 = "PCC_FILE"
	  $sb_8 = "PCC_SOCK"
	 
	  $sc_1 = "bcdedit -set testsigning" wide ascii
	  $sc_2 = "update.microsoft.com" wide ascii
	  $sc_3 = "_crt_debugger_hook" wide ascii
	  $sc_4 = "ue8G5" wide ascii
	 
	  $sd_1 = "NET" wide ascii
	  $sd_2 = "\\\\.\\pipe\\%s" wide ascii
	  $sd_3 = ".dat" wide ascii
	  $sd_4 = "CONNECT %s:%d" wide ascii
	  $sd_5 = "\\Device\\" wide ascii
	 
	  $se_1 = "-%s-%04d" wide ascii
	  $se_2 = "-%04d" wide ascii
	  $se_3 = "FAL" wide ascii
	  $se_4 = "OK" wide ascii
	  $se_5 = "2.03" wide ascii
	  $se_6 = "XXXXXXXXXXXXXXX" wide ascii

   condition:
	  (uint16(0) == 0x5A4D) and ( (all of ($sa_*)) or (
		 (13 of ($sa_*)) and
			( (5 of ($sb_*)) or (3 of ($sc_*)) or (all of ($sd_*)) or
			   ( (1 of ($sc_*)) and (all of ($se_*)) ) ) ) )
}


rule Trojan_Derusbi : APT Derusbi  {
    meta:
        Author = "RSA_IR"
        Date     = "4Sept13"
        File     = "derusbi_variants v 1.3"
        MD5      = " c0d4c5b669cc5b51862db37e972d31ec "

    strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ?? 40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4 A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}

    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8)
}

rule APT_Derusbi_DeepPanda : APT Derusbi ELF DeepPanda
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"
strings:
	$D = "Dom4!nUserP4ss" wide ascii
condition:
	$D
}


rule APT_Derusbi_Gen : APT Derusbi 
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$2 = "273ce6-b29f-90d618c0" wide ascii
	$A = "Ace123dx" fullword wide ascii
	$A1 = "Ace123dxl!" fullword wide ascii
	$A2 = "Ace123dx!@#x" fullword wide ascii
	$C = "/Catelog/login1.asp" wide ascii
	$DF = "~DFTMP$$$$$.1" wide ascii
	$G = "GET /Query.asp?loginid=" wide ascii
	$L = "LoadConfigFromReg failded" wide ascii
	$L1 = "LoadConfigFromBuildin success" wide ascii
	$ph = "/photoe/photo.asp HTTP" wide ascii
	$PO = "POST /photos/photo.asp" wide ascii
	$PC = "PCC_IDENT" wide ascii
condition:
	any of them
}
/*
	Yara Rule Set
	Author: Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud
	Date: 2015-12-09
   Reference = http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family
	Identifier: Derusbi Dez 2015
*/

rule derusbi_kernel : APT Derusbi 
{
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
    strings:
        $token1 = "$$$--Hello"
        $token2 = "Wrod--$$$"
        $cfg = "XXXXXXXXXXXXXXX"
        $class = ".?AVPCC_BASEMOD@@"
        $MZ = "MZ"
    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}

rule derusbi_linux  : APT Derusbi ELF
{
    meta:
        description = "Derusbi Server Linux version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"
    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-15
	Identifier: Derusbi Dez 2015
*/

rule Derusbi_Kernel_Driver_WD_UDFS : APT Derusbi  {
	meta:
		description = "Detects Derusbi Kernel Driver"
		author = "Florian Roth"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 80
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "e27fb16dce7fff714f4b05f2cef53e1919a34d7ec0e595f2eaa155861a213e59"
	strings:
      $x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
      $x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
      $x3 = "\\??\\pipe\\usbpcex%d" fullword wide
		$x4 = "\\??\\pipe\\usbpcg%d" fullword wide
      $x5 = "$$$--Hello" fullword ascii
      $x6 = "Wrod--$$$" fullword ascii

		$s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
		$s2 = "Update.dll" fullword ascii
		$s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
		$s4 = "\\Driver\\nsiproxy" fullword wide
		$s5 = "HOST: %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and
      (
         2 of ($x*) or all of ($s*)
      )
}

rule Derusbi_Code_Signing_Cert : APT Derusbi  {
	meta:
		description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
		author = "Florian Roth"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 40
   strings:
      $s1 = "Fuqing Dawu Technology Co.,Ltd.0" fullword ascii
      $s2 = "XL Games Co.,Ltd.0" fullword ascii
      $s3 = "Wemade Entertainment co.,Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule XOR_4byte_Key : APT Derusbi  {
	meta:
		description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
		author = "Florian Roth"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
   strings:
      /* Op Code */
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }
      /*
      test    ecx, ecx
      jz      short loc_590170
      xor     [esi], eax
      add     [esi], ebx
      add     esi, 4
      dec     ecx
      jmp     short loc_590162
      */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and all of them
}

rule apt_win32_dll_bergard_pgv_pvid_variant : Win32 Derusbi
{

    meta:
        copyright = "Fidelis Cybersecurity"
        reference = "http://www.threatgeek.com/2016/05/turbo-twist-two-64-bit-derusbi-strains-converge.html"
    strings:
        $ = "Accept:"
        $ = "User-Agent: %s"
        $ = "Host: %s:%d"
        $ = "Cache-Control: no-cache"
        $ = "Connection: Keep-Alive"
        $ = "Cookie: pgv_pvid="
        $ = "Content-Type: application/x-octet-stream"
        $ = "User-Agent: %s"
        $ = "Host: %s:%d"
        $ = "Pragma: no-cache"
        $ = "Connection: Keep-Alive"
        $ = "HTTP/1.0"

    condition:

        (uint16(0) == 0x5A4D) and (all of them)
}
