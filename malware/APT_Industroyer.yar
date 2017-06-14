/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-13
   Identifier: Industroyer
   Reference: https://goo.gl/x81cSy
*/

/* Rule Set ----------------------------------------------------------------- */

rule Industroyer_Malware_1 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "ad23c7930dae02de1ea3c6836091b5fb3c62a89bf2bcfb83b4b39ede15904910"
      hash2 = "018eb62e174efdcdb3af011d34b0bf2284ed1a803718fba6edffe5bc0b446b81"
   strings:
      $s1 = "haslo.exe" fullword ascii
      $s2 = "SYSTEM\\CurrentControlSet\\Services\\%ls" fullword wide
      $s3 = "SYS_BASCON.COM" fullword wide
      $s4 = "*.pcmt" fullword wide
      $s5 = "*.pcmi" fullword wide

      $x1 = { 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73
         00 5C 00 25 00 6C 00 73 00 00 00 49 00 6D 00 61
         00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 43
         00 3A 00 5C 00 00 00 44 00 3A 00 5C 00 00 00 45
         00 3A 00 5C 00 00 00 }
      $x2 = "haslo.dat\x00Crash"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) or 2 of them )
}

rule Industroyer_Malware_2 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "3e3ab9674142dec46ce389e9e759b6484e847f5c1e1fc682fc638fc837c13571"
      hash2 = "37d54e3d5e8b838f366b9c202f75fa264611a12444e62ae759c31a0d041aa6e4"
      hash3 = "ecaf150e087ddff0ec6463c92f7f6cca23cc4fd30fe34c10b3cb7c2a6d135c77"
      hash1 = "6d707e647427f1ff4a7a9420188a8831f433ad8c5325dc8b8cc6fc5e7f1f6f47"
   strings:
      $x1 = "sc create %ls type= own start= auto error= ignore binpath= \"%ls\" displayname= \"%ls\"" fullword wide
      $x2 = "10.15.1.69:3128" fullword wide

      $s1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" fullword wide
      $s2 = "/c sc stop %s" fullword wide
      $s3 = "sc start %ls" fullword wide
      $s4 = "93.115.27.57" fullword wide
      $s5 = "5.39.218.152" fullword wide
      $s6 = "tierexe" fullword wide
      $s7 = "comsys" fullword wide
      $s8 = "195.16.88.6" fullword wide
      $s9 = "TieringService" fullword wide

      $a1 = "TEMP\x00\x00DEF" fullword wide
      $a2 = "TEMP\x00\x00DEF-C" fullword wide
      $a3 = "TEMP\x00\x00DEF-WS" fullword wide
      $a4 = "TEMP\x00\x00DEF-EP" fullword wide
      $a5 = "TEMP\x00\x00DC-2-TEMP" fullword wide
      $a6 = "TEMP\x00\x00DC-2" fullword wide
      $a7 = "TEMP\x00\x00CES-McA-TEMP" fullword wide
      $a8 = "TEMP\x00\x00SRV_WSUS" fullword wide
      $a9 = "TEMP\x00\x00SRV_DC-2" fullword wide
      $a10 = "TEMP\x00\x00SCE-WSUS01" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) or 3 of them or 1 of ($a*) ) or ( 5 of them )
}

rule Industroyer_Portscan_3 {
   meta:
      description = "Detects Industroyer related custom port scaner"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "893e4cca7fe58191d2f6722b383b5e8009d3885b5913dcd2e3577e5a763cdb3f"
   strings:
      $s1 = "!ZBfamily" fullword ascii
      $s2 = ":g/outddomo;" fullword ascii
      $s3 = "GHIJKLMNOTST" fullword ascii
      /* Decompressed File */
      $d1 = "Error params Arguments!!!" fullword wide
      $d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
      $d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
      $d4 = "Error IP Range %ls - %ls" fullword wide
      $d5 = "Can't closesocket." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) or 2 of ($d*) )
}

rule Industroyer_Portscan_3_Output {
   meta:
      description = "Detects Industroyer related custom port scaner output file"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
   strings:
      $s1 = "WSA library load complite." fullword ascii
      $s2 = "Connection refused" fullword ascii
   condition:
      all of them
}

rule Industroyer_Malware_4 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "21c1fdd6cfd8ec3ffe3e922f944424b543643dbdab99fa731556f8805b0d5561"
   strings:
      $s1 = "haslo.dat" fullword wide
      $s2 = "defragsvc" fullword ascii

      /* .dat\x00\x00Crash */
      $a1 = { 00 2E 00 64 00 61 00 74 00 00 00 43 72 61 73 68 00 00 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or $a1 )
}

rule Industroyer_Malware_5 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad"
   strings:
      $x1 = "D2MultiCommService.exe" fullword ascii
      $x2 = "Crash104.dll" fullword ascii
      $x3 = "iec104.log" fullword ascii
      $x4 = "IEC-104 client: ip=%s; port=%s; ASDU=%u " fullword ascii

      $s1 = "Error while getaddrinfo executing: %d" fullword ascii
      $s2 = "return info-Remote command" fullword ascii
      $s3 = "Error killing process ..." fullword ascii
      $s4 = "stop_comm_service_name" fullword ascii
      $s5 = "*1* Data exchange: Send: %d (%s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or 4 of them ) ) or ( all of them )
}
