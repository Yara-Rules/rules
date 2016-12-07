/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule CrowdStrike_Shamoon_DroppedFile { 
	meta:
		description = "Rule to detect Shamoon malware http://goo.gl/QTxohN"
		reference = "http://www.rsaconference.com/writable/presentations/file_upload/exp-w01-hacking-exposed-day-of-destruction.pdf"
	strings:
		$testn123 = "test123" wide
		$testn456 = "test456" wide
		$testn789 = "test789" wide
		$testdomain = "testdomain.com" wide $pingcmd = "ping -n 30 127.0.0.1 >nul" wide
	condition:
		(any of ($testn*) or $pingcmd) and $testdomain
}
rule Shamoon2_Wiper {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}

rule Shamoon2_ComComp {
   meta:
      description = "Detects Shamoon 2.0 Communication Components"
      author = "Florian Roth (with Binar.ly)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"
   strings:
      $s1 = "mkdir %s%s > nul 2>&1" fullword ascii
      $s2 = "p[%s%s%d.%s" fullword ascii

      $op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 }
      $op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d }
      $op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c }
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and ( all of ($s*) or all of ($op*) )
}

rule EldoS_RawDisk {
   meta:
      description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
      author = "Florian Roth (with Binar.ly)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 50
      hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
      hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
   strings:
      $s1 = "g\\system32\\" fullword wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $s4 = "FEJIKC" fullword ascii
      $s5 = "INZQND" fullword ascii
      $s6 = "IUTLOM" fullword wide
      $s7 = "DKFKCK" fullword ascii

      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 4 of them )
}

rule Shamoon_Disttrack_Dropper {
   meta:
      description = "Detects Shamoon 2.0 Disttrack Dropper"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6"
      hash2 = "5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a"
   strings:
      $a1 = "\\#{9A6DB7D2-FECF-41ff-9A92-6EDA696613DF}#" wide
      $a2 = "\\#{8A6DB7D2-FECF-41ff-9A92-6EDA696613DE}#" wide

      $s1 = "\\amd64\\elrawdsk.pdb" fullword ascii
      $s2 = "RawDiskSample.exe" fullword wide
      $s3 = "RawDisk Driver. Allows write access to files and raw disk sectors for user mode applications in Windows 2000 and later." fullword wide
      $s4 = "elrawdsk.sys" fullword wide
      $s5 = "\\DosDevices\\ElRawDisk" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of ($a*) and 1 of ($s*) )
}
