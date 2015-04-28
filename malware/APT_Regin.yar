/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule Regin_APT_KernelDriver_Generic_A {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "187044596bc1328efa0ed636d8aa4a5c"
		hash2 = "06665b96e293b23acc80451abb413e50"
		hash3 = "d240f06e98c8d3e647cbf4d442d79475"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		
		$s0 = "atapi.sys" fullword wide
		$s1 = "disk.sys" fullword wide
		$s3 = "h.data" fullword ascii
		$s4 = "\\system32" fullword ascii
		$s5 = "\\SystemRoot" fullword ascii
		$s6 = "system" fullword ascii
		$s7 = "temp" fullword ascii
		$s8 = "windows" fullword ascii

		$x1 = "LRich6" fullword ascii
		$x2 = "KeServiceDescriptorTable" fullword ascii		
	condition:
		$m0 at 0 and $m1 and  	
		all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "ffb0b9b5b610191051a7bdf0806e1e47"
		hash2 = "bfbe8c3ee78750c3a520480700e440f8"
		hash3 = "b29ca4f22ae7b7b25f79c1d4a421139d"
		hash4 = "06665b96e293b23acc80451abb413e50"
		hash5 = "2c8b9d2885543d7ade3cae98225e263b"
		hash6 = "4b6b86c7fec1c574706cecedf44abded"
		hash7 = "187044596bc1328efa0ed636d8aa4a5c"
		hash8 = "d240f06e98c8d3e647cbf4d442d79475"
		hash9 = "6662c390b2bbbd291ec7987388fc75d7"
		hash10 = "1c024e599ac055312a4ab75b3950040a"
		hash11 = "ba7bb65634ce1e30c1e5415be3d1db1d"
		hash12 = "b505d65721bb2453d5039a389113b566"
		hash13 = "b269894f434657db2b15949641a67532"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s2 = "H.data" fullword ascii nocase
		$s3 = "INIT" fullword ascii
		$s4 = "ntoskrnl.exe" fullword ascii
		
		$v1 = "\\system32" fullword ascii
		$v2 = "\\SystemRoot" fullword ascii
		$v3 = "KeServiceDescriptorTable" fullword ascii	
		
		$w1 = "\\system32" fullword ascii
		$w2 = "\\SystemRoot" fullword ascii		
		$w3 = "LRich6" fullword ascii
		
		$x1 = "_snprintf" fullword ascii
		$x2 = "_except_handler3" fullword ascii
		
		$y1 = "mbstowcs" fullword ascii
		$y2 = "wcstombs" fullword ascii
		$y3 = "KeGetCurrentIrql" fullword ascii
		
		$z1 = "wcscpy" fullword ascii
		$z2 = "ZwCreateFile" fullword ascii
		$z3 = "ZwQueryInformationFile" fullword ascii
		$z4 = "wcslen" fullword ascii
		$z5 = "atoi" fullword ascii
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) ) 
		and filesize < 20KB
}

rule Regin_APT_KernelDriver_Generic_C {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "e0895336617e0b45b312383814ec6783556d7635"
		hash2 = "732298fa025ed48179a3a2555b45be96f7079712"		
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
	
		$s0 = "KeGetCurrentIrql" fullword ascii
		$s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		$s2 = "usbclass" fullword wide
		
		$x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
		$x2 = "Universal Serial Bus Class Driver" fullword wide
		$x3 = "5.2.3790.0" fullword wide
		
		$y1 = "LSA Shell" fullword wide
		$y2 = "0Richw" fullword ascii		
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($x*) or all of ($y*) ) 
		and filesize < 20KB
}

/* Update 27.11.14 */

rule Regin_sig_svcsstat {
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"
	strings:
		$s0 = "Service Control Manager" fullword ascii
		$s1 = "_vsnwprintf" fullword ascii
		$s2 = "Root Agency" fullword ascii
		$s3 = "Root Agency0" fullword ascii
		$s4 = "StartServiceCtrlDispatcherA" fullword ascii
		$s5 = "\\\\?\\UNC" fullword wide
		$s6 = "%ls%ls" fullword wide
	condition:
		all of them and filesize < 15KB and filesize > 10KB 
}

rule Regin_Sample_1 {
	meta:
		description = "Auto-generated rule - file-3665415_sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"
	strings:
		$s0 = "Getting PortName/Identifier failed - %x" fullword ascii
		$s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
		$s2 = "External Naming Failed - Status %x" fullword ascii
		$s3 = "------- Same multiport - different interrupts" fullword ascii
		$s4 = "%x occurred prior to the wait - starting the" fullword ascii
		$s5 = "'user registry info - userPortIndex: %d" fullword ascii
		$s6 = "Could not report legacy device - %x" fullword ascii
		$s7 = "entering SerialGetPortInfo" fullword ascii
		$s8 = "'user registry info - userPort: %x" fullword ascii
		$s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
		$s10 = "Kernel debugger is using port at address %X" fullword ascii
		$s12 = "Release - freeing multi context" fullword ascii
		$s13 = "Serial driver will not load port" fullword ascii
		$s14 = "'user registry info - userAddressSpace: %d" fullword ascii
		$s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
		$s20 = "'user registry info - userIndexed: %d" fullword ascii
	condition:
		all of them and filesize < 110KB and filesize > 80KB
}

rule Regin_Sample_2 {
	meta:
		description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"
	strings:
		$s0 = "\\SYSTEMROOT\\system32\\lsass.exe" fullword wide
		$s1 = "atapi.sys" fullword wide
		$s2 = "disk.sys" fullword wide
		$s3 = "IoGetRelatedDeviceObject" fullword ascii
		$s4 = "HAL.dll" fullword ascii
		$s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" fullword ascii
		$s6 = "PsGetCurrentProcessId" fullword ascii
		$s7 = "KeGetCurrentIrql" fullword ascii
		$s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s9 = "KeSetImportanceDpc" fullword ascii
		$s10 = "KeQueryPerformanceCounter" fullword ascii
		$s14 = "KeInitializeEvent" fullword ascii
		$s15 = "KeDelayExecutionThread" fullword ascii
		$s16 = "KeInitializeTimerEx" fullword ascii
		$s18 = "PsLookupProcessByProcessId" fullword ascii
		$s19 = "ExReleaseFastMutexUnsafe" fullword ascii
		$s20 = "ExAcquireFastMutexUnsafe" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_3 {
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		date = "27.11.14"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"		
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "Service Pack x" fullword wide
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide
		$s3 = "mntoskrnl.exe" fullword wide
		$s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" fullword wide
		$s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
		$s6 = "Service Pack" fullword wide
		$s7 = ".sys" fullword wide
		$s8 = ".dll" fullword wide		
		
		$s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" fullword wide
		$s11 = "IoGetRelatedDeviceObject" fullword ascii
		$s12 = "VMEM.sys" fullword ascii
		$s13 = "RtlGetVersion" fullword wide
		$s14 = "ntkrnlpa.exe" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize > 160KB and filesize < 200KB
}

rule Regin_Sample_Set_1 {
	meta:
		description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash1 = "8487a961c8244004c9276979bb4b0c14392fc3b8"
		hash2 = "bcf3461d67b39a427c83f9e39b9833cfec977c61"		
	strings:
		$s0 = "HAL.dll" fullword ascii
		$s1 = "IoGetDeviceObjectPointer" fullword ascii
		$s2 = "MaximumPortsServiced" fullword wide
		$s3 = "KeGetCurrentIrql" fullword ascii
		$s4 = "ntkrnlpa.exe" fullword ascii
		$s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s6 = "ConnectMultiplePorts" fullword wide
		$s7 = "\\SYSTEMROOT" fullword wide
		$s8 = "IoWriteErrorLogEntry" fullword ascii
		$s9 = "KeQueryPerformanceCounter" fullword ascii
		$s10 = "KeServiceDescriptorTable" fullword ascii
		$s11 = "KeRemoveEntryDeviceQueue" fullword ascii
		$s12 = "SeSinglePrivilegeCheck" fullword ascii
		$s13 = "KeInitializeEvent" fullword ascii
		$s14 = "IoBuildDeviceIoControlRequest" fullword ascii
		$s15 = "KeRemoveDeviceQueue" fullword ascii
		$s16 = "IofCompleteRequest" fullword ascii
		$s17 = "KeInitializeSpinLock" fullword ascii
		$s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
		$s19 = "IoCreateDevice" fullword ascii
		$s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_Set_2 {
	meta:
		description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
		author = "@MalwrSignatures"
		date = "27.11.14"
		hash1 = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash2 = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "d%ls%ls" fullword wide
		$s1 = "\\\\?\\UNC" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
		$s3 = "\\\\?\\UNC\\" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
		$s6 = "\\\\.\\Global\\%s" fullword wide
		$s7 = "temp" fullword wide
		$s8 = "\\\\.\\%s" fullword wide
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide		
		
		$s10 = "sscanf" fullword ascii
		$s11 = "disp.dll" fullword ascii
		$s12 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
		$s13 = "%d.%d.%d.%d%c" fullword ascii
		$s14 = "imagehlp.dll" fullword ascii
		$s15 = "%hd %d" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize < 450KB and filesize > 360KB
}

rule apt_regin_legspin {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Legspin module"
	    version = "1.0"
	    last_modified = "2015-01-22"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "29105f46e4d33f66fee346cfd099d1cc"
	strings:
	    $mz="MZ"
	    $a1="sharepw"
	    $a2="reglist"
	    $a3="logdump"
	    $a4="Name:" wide
	    $a5="Phys Avail:"
	    $a6="cmd.exe" wide
	    $a7="ping.exe" wide
	    $a8="millisecs"
	condition:
	    ($mz at 0) and all of ($a*)
}

rule apt_regin_hopscotch {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Hopscotch module"
	    version = "1.0"
	    last_modified = "2015-01-22"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "6c34031d7a5fc2b091b623981a8ae61c"
	strings:

	    $mz="MZ"

	    $a1="AuthenticateNetUseIpc"
	    $a2="Failed to authenticate to"
	    $a3="Failed to disconnect from"
	    $a4="%S\\ipc$" wide
	    $a5="Not deleting..."
	    $a6="CopyServiceToRemoteMachine"
	    $a7="DH Exchange failed"
	    $a8="ConnectToNamedPipes"
	condition:
	    ($mz at 0) and all of ($a*)
}


rule apt_regin_2011_32bit_stage1 {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin 32 bit stage 1 loaders"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$key1={331015EA261D38A7}
$key2={9145A98BA37617DE}
$key3={EF745F23AA67243D}
$mz="MZ"
condition:
($mz at 0) and any of ($key*) and filesize < 300000
}
rule apt_regin_rc5key {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin RC5 decryption keys"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$key1={73 23 1F 43 93 E1 9F 2F 99 0C 17 81 5C FF B4 01}
$key2={10 19 53 2A 11 ED A3 74 3F C3 72 3F 9D 94 3D 78}
condition:
any of ($key*)
}

rule apt_regin_vfs {
meta:
	copyright = "Kaspersky Lab"
	author = "Kaspersky Lab"
	description = "Rule to detect Regin VFSes"
	version = "1.0"
	last_modified = "2014-11-18"
strings:
	$a1={00 02 00 08 00 08 03 F6 D7 F3 52}
	$a2={00 10 F0 FF F0 FF 11 C7 7F E8 52}
	$a3={00 04 00 10 00 10 03 C2 D3 1C 93}
	$a4={00 04 00 10 C8 00 04 C8 93 06 D8}
condition:
	($a1 at 0) or ($a2 at 0) or ($a3 at 0) or ($a4 at 0)
}

rule apt_regin_dispatcher_disp_dll {

meta:
	copyright = "Kaspersky Lab"
	author = "Kaspersky Lab"
	description = "Rule to detect Regin disp.dll dispatcher"
	version = "1.0"
	last_modified = "2014-11-18"

strings:
	$mz="MZ"
	$string1="shit"
	$string2="disp.dll"
	$string3="255.255.255.255"
	$string4="StackWalk64"
	$string5="imagehlp.dll"
condition:
	($mz at 0) and (all of ($string*))
}

rule apt_regin_2013_64bit_stage1 {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin 64 bit stage 1 loaders"
 version = "1.0"
 last_modified = "2014-11-18"
 filename="wshnetc.dll"
 md5="bddf5afbea2d0eed77f2ad4e9a4f044d"
 filename="wsharp.dll"
 md5="c053a0a3f1edcbbfc9b51bc640e808ce"
strings:
$mz="MZ"
$a1="PRIVHEAD"
$a2="\\\\.\\PhysicalDrive%d"
$a3="ZwDeviceIoControlFile"
condition:
($mz at 0) and (all of ($a*)) and filesize < 100000
}

