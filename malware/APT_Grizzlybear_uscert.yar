/*
   Yara Rule Set
   Author: US CERT
   Date: 2017-02-10
   Identifier: US CERT Report on Grizzly Steppe - APT28/APT29
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule IMPLANT_1_v1 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {6A ?? E8 ?? ?? FF FF 59 85 C0 74 0B 8B C8 E8 ?? ?? FF FF 8B F0
         EB 02 33 F6 8B CE E8 ?? ?? FF FF 85 F6 74 0E 8B CE E8 ?? ?? FF FF 56
         E8 ?? ?? FF FF 59}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_1_v2 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {83 3E 00 53 74 4F 8B 46 04 85 C0 74 48 83 C0 02 50 E8 ?? ?? 00
         00 8B D8 59 85 DB 74 38 8B 4E 04 83 F9 FF 7E 21 57 }
      $STR2 = {55 8B EC 8B 45 08 3B 41 08 72 04 32 C0 EB 1B 8B 49 04 8B 04 81
         80 78 19 01 75 0D FF 70 10 FF [5] 85 C0 74 E3 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_1_v3 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $rol7encode = { 0F B7 C9 C1 C0 07 83 C2 02 33 C1 0F B7 0A 47 66 85 C9 75 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_1_v4 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XOR_LOOP = { 8B 45 FC 8D 0C 06 33 D2 6A 0B 8B C6 5B F7 F3 8A 82 ?? ??
         ?? ?? 32 04 0F 46 88 01 3B 75 0C 7C E0 }
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_1_v5 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $drivername = { 6A 30 ?? 6A 33 [5] 6A 37 [5] 6A 32 [5] 6A 31 [5] 6A 77
         [5] 6A 69 [5] 6A 6E [5] 6A 2E [5] 6A 73 [5-9] 6A 79 [5] 6A 73 }
      $mutexname = { C7 45 ?? 2F 2F 64 66 C7 45 ?? 63 30 31 65 C7 45 ?? 6C 6C
         36 7A C7 45 ?? 73 71 33 2D C7 45 ?? 75 66 68 68 66 C7 45 ?? 66 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_1_v6 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XORopcodes_eax = { 35 (22 07 15 0e|56 d7 a7 0a) }
      $XORopcodes_others = { 81 (F1|F2|F3|F4|F5|F6|F7) (22 07 15 0E|56 D7 A7 0A) }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025) and any of them
}

*/

rule IMPLANT_1_v7 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v1 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8d ?? fa [2] e8 [2] FF FF C7 [2-5] 00 00 00 00 8D [2-5] 5? 6a 00 6a 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v2 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8]
         48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v3 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {C1 EB 07 8D ?? 01 32 1C ?? 33 D2 }
      $STR2 = {2B ?? 83 ?? 06 0F 83 ?? 00 00 00 EB 02 33 }
      $STR3 = {89 ?? ?? 89 ?? ?? 89 55 ?? 89 45 ?? 3B ?? 0F 83 ?? 00 00 00 8D
         ?? ?? 8D ?? ?? FE }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v4 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53
         56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68
         [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v5 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00 33
         C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15 ?? 00
         00 00 48 8B CC E8}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v6 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { e8 [2] ff ff 8b [0-6] 00 04 00 00 7F ?? [1-2] 00 02 00 00 7F
         ?? [1-2] 00 01 00 00 7F ?? [1-2] 80 00 00 00 7F ?? 83 ?? 40 7F}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v7 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $s1 = {10 A0 FA FD 83 3D 28 D4 1F FF 77 5? ?8 B4 50 CC 1E B0 78 D7 90 13
         21 C0 23 3D 28 BC 78 95 DE 4B B0 60 00 00 0F 7F 38 B4 50 C8 D5 9F E0
         25 DF F3 21 C0 28 BC 13 3D 2B 90 60 00 00 0F 7F 18 B4 50 C8 BC F2 21
         C0 28 B4 5E 48 B5 5E 00 8D 41 FE 83 F8 06 8B 45 ?? 72 ?? 8B 4D ?? 8B }
      $s2 = {28 D9 B0 00 00 00 00 FB 65 C0 AF E8 D3 40 28 B4 5? ?0 3C 20 FA FD
         88 D7 A0 18 D4 2F F3 3D 2F 77 5? ?C 1E B0 78 BC 73 21 C0 A3 3D 2B 90
         60 00 00 0F 7F 18 A4 D? ?8 B4 50 C8 0E 90 20 24 D? ?3 20 C0 28 B4 5?
         ?3 3D 2F 77 5? ?8 B4 50 C2 20 C0 28 BD 70 2D 93 01 E8 B4 D0 C8 D4 2F
         E3 B4 5E 88 B4 5? ?8 95 5? ?7 2A 05 F5 E5 B8 BE 55 DC 20 80 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v8 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {8B ?? 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA C1 EE 02 89
         74 24 58 44 8B ?? 41 F7 ?? 8B CA BA 03 00 00 00 C1 E9 02 89 0C 24 8D
         04 49 03 C0 44 2B ?? 44 89 ?? 24 04 3B F1 0F 83 ?? 01 00 00 8D 1C 76
         4C 89 6C 24 }
      $STR2 = {C5 41 F7 E0 ?? ?? ?? ?? ?? ?? 8D 0C 52 03 C9 2B C1 8B C8 ?? 8D
         04 ?? 46 0F B6 0C ?? 40 02 C7 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7
         E1 C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA 46 22 0C ?? 41 8D 48
         FE F7 E1 C1 EA 02 8D 04 52 03 C0 2B C8 8B C1 }
      $STR3 = {41 F7 E0 C1 EA 02 41 8B C0 8D 0C 52 03 C9 2B C1 8B C8 42 8D 04
         1B 46 0F B6 0C ?? 40 02 C6 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7 E1
         C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA }
      $STR4 = {46 22 0C ?? 41 8D 48 FE F7 E1 C1 EA 02 8D 04 52 8B 54 24 58 03
         C0 2B C8 8B C1 0F B6 4F FF 42 0F B6 04 ?? 41 0F AF CB C1 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v9 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8A C3 02 C0 02 D8 8B 45 F8 02 DB 83 C1 02 03 45 08 88 5D 0F 89
         45 E8 8B FF 0F B6 5C 0E FE 8B 45 F8 03 C1 0F AF D8 8D 51 01 89 55 F4
         33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B 45 F4 C1 EB 07 32 1C 32 33 D2
         F7 F7 8A C1 02 45 0F 2C 02 32 04 32 33 D2 88 45 FF 8B C1 8B F7 F7 F6
         8A 45 FF 8B 75 14 22 04 32 02 D8 8B 45 E8 30 1C 08 8B 4D F4 8D 51 FE
         3B D7 72 A4 8B 45 E4 8B 7D E0 8B 5D F0 83 45 F8 06 43 89 5D F0 3B D8
         0F 82 ?? ?? ?? ?? 3B DF 75 13 8D 04 7F 8B 7D 10 03 C0 2B F8 EB 09 33
         C9 E9 5B FF FF FF 33 FF 3B 7D EC 0F 83 ?? ?? ?? ?? 8B 55 08 8A CB 02
         C9 8D 04 19 02 C0 88 45 13 8D 04 5B 03 C0 8D 54 10 FE 89 45 E0 8D 4F
         02 89 55 E4 EB 09 8D 9B 00 00 00 00 8B 45 E0 0F B6 5C 31 FE 8D 44 01
         FE 0F AF D8 8D 51 01 89 55 0C 33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B
         45 0C C1 EB 07 32 1C 32 33 D2 F7 F7 8A C1 02 45 13 2C 02 32 04 32 33
         D2 88 45 0B 8B C1 8B F7 F7 F6 8A 45 0B 8B 75 14 22 04 32 02 D8 8B 45
         E4 30 1C 01 8B 4D 0C }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v10 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8]
         48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v11 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53
         56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68
         [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v12 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00
         33 C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15
         ?? 00 00 00 48 8B CC E8}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v13 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF
         [6-8] 48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v14 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {8B ?? 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA C1 EE 02 89
         74 24 58 44 8B ?? 41 F7 ?? 8B CA BA 03 00 00 00 C1 E9 02 89 0C 24 8D
         04 49 03 C0 44 2B ?? 44 89 ?? 24 04 3B F1 0F 83 ?? 01 00 00 8D 1C 76
         4C 89 6C 24  }
      $STR2 = {C5 41 F7 E0 ?? ?? ?? ?? ?? ?? 8D 0C 52 03 C9 2B C1 8B C8 ?? 8D
         04 ?? 46 0F B6 0C ?? 40 02 C7 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7
         E1 C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA 46 22 0C ?? 41 8D 48
         FE F7 E1 C1 EA 02 8D 04 52 03 C0 2B C8 8B C1 }
      $STR3 = {41 F7 E0 C1 EA 02 41 8B C0 8D 0C 52 03 C9 2B C1 8B C8 42 8D 04
         1B 46 0F B6 0C ?? 40 02 C6 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7 E1
         C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA }
      $STR4 = {46 22 0C ?? 41 8D 48 FE F7 E1 C1 EA 02 8D 04 52 8B 54 24 58 03
         C0 2B C8 8B C1 0F B6 4F FF 42 0F B6 04 ?? 41 0F AF CB C1 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v15 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XOR_LOOP1 = { 32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 }
      $XOR_LOOP2 = { 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 }
      $XOR_LOOP3 = { 02 C3 30 06 8B 5D F0 8D 41 FE 83 F8 06 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v16 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $OBF_FUNCT = { 0F B6 1C 0B 8D 34 08 8D 04 0A 0F AF D8 33 D2 8D 41 FF F7
         75 F8 8B 45 0C C1 EB 07 8D 79 01 32 1C 02 33 D2 8B C7 89 5D E4 BB 06
         00 00 00 F7 F3 8B 45 0C 8D 59 FE 02 5D FF 32 1C 02 8B C1 33 D2 B9 06
         00 00 00 F7 F1 8B 45 0C 8B CF 22 1C 02 8B 45 E4 8B 55 E0 02 C3 30 06
         8B 5D F0 8D 41 FE 83 F8 06 8B 45 DC 72 9A }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $OBF_FUNCT
}

rule IMPLANT_2_v17  {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 24108b44241c894424148b4424246836 }
      $STR2 = { 518d4ddc516a018bd08b4de4e8360400 }
      $STR3 = { e48178061591df75740433f6eb1a8b48 }
      $STR4 = { 33d2f775f88b45d402d903c641321c3a }
      $STR5 = { 006a0056ffd083f8ff74646a008d45f8 }
   condition:
      (uint16(0) == 0x5A4D) and 2 of them
}

rule IMPLANT_2_v18 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8A C1 02 C0 8D 1C 08 8B 45 F8 02 DB 8D 4A 02 8B 55 0C 88 5D FF
         8B 5D EC 83 C2 FE 03 D8 89 55 E0 89 5D DC 8D 49 00 03 C1 8D 34 0B 0F
         B6 1C 0A 0F AF D8 33 D2 8D 41 FF F7 75 F4 8B 45 0C C1 EB 07 8D 79 01
         32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 8B 45 0C 8D 59 FE
         02 5D FF 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B 45 0C 8B CF 22
         1C 02 8B 45 E4 8B 55 E0 02 C3 30 06 8B 5D DC 8D 41 FE 83 F8 06 8B 45
         F8 72 9B 8B 4D F0 8B 5D D8 8B 7D 08 8B F0 41 83 C6 06 89 4D F0 89 75
         F8 3B 4D D4 0F 82 ?? ?? ?? ?? 8B 55 E8 3B CB 75 09 8D 04 5B 03 C0 2B
         F8 EB 02 33 FF 3B FA 0F 83 ?? ?? ?? ?? 8B 5D EC 8A C1 02 C0 83 C3 FE
         8D 14 08 8D 04 49 02 D2 03 C0 88 55 0B 8D 48 FE 8D 57 02 03 C3 89 4D
         D4 8B 4D 0C 89 55 F8 89 45 D8 EB 06 8D 9B 00 00 00 00 0F B6 5C 0A FE
         8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42 FF 33 D2 F7 75 F4 C1
         EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1 8A 4D F8 8B 45 0C 80
         E9 02 02 4D 0B 32 0C 02 8B 45 F8 33 D2 F7 75 F4 8B 45 0C 22 0C 02 8B
         D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v19 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $obfuscated_RSA1 = { 7C 41 B4 DB ED B0 B8 47 F1 9C A1 49 B6 57 A6 CC D6
         74 B5 52 12 4D FC B1 B6 3B 85 73 DF AB 74 C9 25 D8 3C EA AE 8F 5E D2
         E3 7B 1E B8 09 3C AF 76 A1 38 56 76 BB A0 63 B6 9E 5D 86 E4 EC B0 DC
         89 1E FA 4A E5 79 81 3F DB 56 63 1B 08 0C BF DC FC 75 19 3E 1F B3 EE
         9D 4C 17 8B 16 9D 99 C3 0C 89 06 BB F1 72 46 7E F4 0B F6 CB B9 C2 11
         BE 5E 27 94 5D 6D C0 9A 28 F2 2F FB EE 8D 82 C7 0F 58 51 03 BF 6A 8D
         CD 99 F8 04 D6 F7 F7 88 0E 51 88 B4 E1 A9 A4 3B }
      $cleartext_RSA1 = { 06 02 00 00 00 A4 00 00 52 53 41 31 00 04 00 00 01
         00 01 00 AF BD 26 C9 04 65 45 9F 0E 3F C4 A8 9A 18 C8 92 00 B2 CC 6E
         0F 2F B2 71 90 FC 70 2E 0A F0 CA AA 5D F4 CA 7A 75 8D 5F 9C 4B 67 32
         45 CE 6E 2F 16 3C F1 8C 42 35 9C 53 64 A7 4A BD FA 32 99 90 E6 AC EC
         C7 30 B2 9E 0B 90 F8 B2 94 90 1D 52 B5 2F F9 8B E2 E6 C5 9A 0A 1B 05
         42 68 6A 3E 88 7F 38 97 49 5F F6 EB ED 9D EF 63 FA 56 56 0C 7E ED 14
         81 3A 1D B9 A8 02 BD 3A E6 E0 FA 4D A9 07 5B E6 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_2_v20 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $func = { 0F B6 5C 0A FE 8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42
         FF 33 D2 F7 75 F4 C1 EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1
         8A 4D F8 8B 45 0C 80 E9 02 02 4D 0B 32 0C 02 8B 45 F8 33 D2 F7 75 F4
         8B 45 0C 22 0C 02 8B D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 8B 45
         D8 89 55 F8 72 A0 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_3_v1 {
   meta:
      description = "X-Agent/CHOPSTICK Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = ">process isn't exist<" ascii wide
      $STR2 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" ascii wide
      $STR3 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0" ascii wide
      $STR4 = "webhp?rel=psy&hl=7&ai=" ascii wide
      $STR5 = {0f b6 14 31 88 55 ?? 33 d2 8b c1 f7 75 ?? 8b 45 ?? 41 0f b6 14
         02 8a 45 ?? 03 fa}
   condition:
      any of them
}

rule IMPLANT_3_v2 {
   meta:
      description = "X-Agent/CHOPSTICK Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $base_key_moved = {C7 45 ?? 3B C6 73 0F C7 45 ?? 8B 07 85 C0 C7 45 ?? 74
         02 FF D0 C7 45 ?? 83 C7 04 3B C7 45 ?? FE 72 F1 5F C7 45 ?? 5E C3 8B
         FF C7 45 ?? 56 B8 D8 78 C7 45 ?? 75 07 50 E8 C7 45 ?? B1 D1 FF FF C7
         45 ?? 59 5D C3 8B C7 45 ?? FF 55 8B EC C7 45 ?? 83 EC 10 A1 66 C7 45
         ?? 33 35}
      $base_key_b_array = {3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE
         72 F1 5F 5E C3 8B FF 56 B8 D8 78 75 07 50 E8 B1 D1 FF FF 59 5D C3 8B
         FF 55 8B EC 83 EC 10 A1 33 35 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_3_v3 {
   meta:
      description = "X-Agent/CHOPSTICK Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = ".?AVAgentKernel@@"
      $STR2 = ".?AVIAgentModule@@"
      $STR3 = "AgentKernel"
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_4_v1 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {55 8B EC 81 EC 54 01 00 00 83 65 D4 00 C6 45 D8 61 C6 45 D9 64
         C6 45 DA 76 C6 45 DB 61 C6 45 DC 70 C6 45 DD 69 C6 45 DE 33 C6 45 DF
         32 C6 45 E0 2EE9 ?? ?? ?? ??} $STR2 = {C7 45 EC 5A 00 00 00 C7 45 E0
            46 00 00 00 C7 45 E8 5A 00 00 00 C7 45 E4 46 00 00 00}
   condition:
      (uint16(0)== 0x5A4D or uint16(0) == 0xCFD0 or uint16(0)== 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 1 of them
}

rule IMPLANT_4_v2 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $BUILD_USER32 = {75 73 65 72 ?? ?? ?? 33 32 2E 64}
      $BUILD_ADVAPI32 = {61 64 76 61 ?? ?? ?? 70 69 33 32}
      $CONSTANT = {26 80 AC C8}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

/* Some false positives - replaced with alternative rule (see below)

rule IMPLANT_4_v3 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $a1 = "Adobe Flash Player Installer" wide nocase
      $a3 = "regedt32.exe" wide nocase
      $a4 = "WindowsSysUtility" wide nocase
      $a6 = "USB MDM Driver" wide nocase
      $b1 = {00 05 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 3F 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 5C 04 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 1C 02 00 00 01 00 30 00 30
         00 31 00 35 00 30 00 34 00 62 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 46
         00 0F 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 55 00 53 00 42 00 20
         00 4D 00 44 00 4D 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00
         00 00 3C 00 0E 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
         00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00
         30 00 30 00 2E 00 35 00 35 00 31 00 32 00 00 00 4A 00 13 00 01 00 4C
         00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00
         68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
         00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 33 00 00 00 00 00
         3E 00 0B 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46
         00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 75 00 73 00 62 00
         6D 00 64 00 6D 00 2E 00 73 00 79 00 73 00 00 00 00 00 66 00 23 00 01
         00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00
         00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20
         00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4F 00 70 00 65 00
         72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65
         00 6D 00 00 00 00 00 40 00 0E 00 01 00 50 00 72 00 6F 00 64 00 75 00
         63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 2E
         00 31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00
         00 00 1C 02 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 62 00 30
         00 00 00 4C 00 16 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00
         4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73
         00 6F 00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F 00 72 00 61 00
         74 00 69 00 6F 00 6E 00 00 00 46 00 0F 00 01 00 46 00 69 00 6C 00 65
         00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00
         00 00 00 00 55 00 53 00 42 00 20 00 4D 00 44 00 4D 00 20 00 44 00 72
         00 69 00 76 00 65 00 72 00 00 00 00 00 3C 00 0E 00 01 00 46 00 69 00
         6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35
         00 2E 00 31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00
         32 00 00 00 4A 00 13 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F
         00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43 00 6F 00 70 00
         79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32
         00 30 00 31 00 33 00 00 00 00 00 3E 00 0B 00 01 00 4F 00 72 00 69 00
         67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D
         00 65 00 00 00 75 00 73 00 62 00 6D 00 64 00 6D 00 2E 00 73 00 79 00
         73 00 00 00 00 00 66 00 23 00 01 00 50 00 72 00 6F 00 64 00 75 00 63
         00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00
         6F 00 73 00 6F 00 66 00 74 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77
         00 73 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00
         20 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 40 00 0E 00 01
         00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00
         69 00 6F 00 6E 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00 30 00 30
         00 2E 00 35 00 35 00 31 00 32 00 00 00 48 00 00 00 01 00 56 00 61 00
         72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 28
         00 08 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00
         6F 00 6E 00 00 00 00 00 15 00 B0 04 09 04 B0 04}
      $b2 = {34 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 03 00 03 00 04 00 02 00 03 00 03 00 04 00 02 00 3F 00 00 00
         00 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 94 02 00 00 00 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 70 02 00 00 00 00 30 00 34
         00 30 00 39 00 30 00 34 00 65 00 34 00 00 00 4A 00 15 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 53 00 6F 00 6C 00 69 00 64 00 20 00 53 00 74 00 61 00 74 00 65 00
         20 00 4E 00 65 00 74 00 77 00 6F 00 72 00 6B 00 73 00 00 00 00 00 62
         00 1D 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 41 00 64 00 6F 00 62
         00 65 00 20 00 46 00 6C 00 61 00 73 00 68 00 20 00 50 00 6C 00 61 00
         79 00 65 00 72 00 20 00 49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 65
         00 72 00 00 00 00 00 30 00 08 00 01 00 46 00 69 00 6C 00 65 00 56 00
         65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 33 00 2E 00 33 00 2E
         00 32 00 2E 00 34 00 00 00 32 00 09 00 01 00 49 00 6E 00 74 00 65 00
         72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 68 00 6F 00 73
         00 74 00 2E 00 65 00 78 00 65 00 00 00 00 00 76 00 29 00 01 00 4C 00
         65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68
         00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00
         20 00 28 00 43 00 29 00 20 00 41 00 64 00 6F 00 62 00 65 00 20 00 53
         00 79 00 73 00 74 00 65 00 6D 00 73 00 20 00 49 00 6E 00 63 00 6F 00
         72 00 70 00 6F 00 72 00 61 00 74 00 65 00 64 00 00 00 00 00 3A 00 09
         00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00
         6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 6F 00 73 00 74 00 2E
         00 65 00 78 00 65 00 00 00 00 00 5A 00 1D 00 01 00 50 00 72 00 6F 00
         64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 41 00 64
         00 6F 00 62 00 65 00 20 00 46 00 6C 00 61 00 73 00 68 00 20 00 50 00
         6C 00 61 00 79 00 65 00 72 00 20 00 49 00 6E 00 73 00 74 00 61 00 6C
         00 6C 00 65 00 72 00 00 00 00 00 34 00 08 00 01 00 50 00 72 00 6F 00
         64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00
         00 33 00 2E 00 33 00 2E 00 32 00 2E 00 34 00 00 00 44 00 00 00 00 00
         56 00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00
         00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00
         74 00 69 00 6F 00 6E 00 00 00 00 00 09 04 E4 04 46 45 32 58}
      $b3 = {C8 02 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 17 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 28 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 04 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 65 00 34 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 48
         00 10 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 49 00 44 00 45 00 20
         00 50 00 6F 00 72 00 74 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00
         00 00 62 00 21 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
         00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00
         30 00 30 00 2E 00 35 00 35 00 31 00 32 00 20 00 28 00 78 00 70 00 73
         00 70 00 2E 00 30 00 38 00 30 00 34 00 31 00 33 00 2D 00 30 00 38 00
         35 00 32 00 29 00 00 00 00 00 4A 00 13 00 01 00 4C 00 65 00 67 00 61
         00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00
         43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43
         00 29 00 20 00 32 00 30 00 30 00 39 00 00 00 00 00 66 00 23 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00
         00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00
         57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4F 00 70 00 65 00 72
         00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00
         6D 00 00 00 00 00 40 00 0E 00 01 00 50 00 72 00 6F 00 64 00 75 00 63
         00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 2E 00
         31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00 00
         00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00
         6E 00 66 00 6F 00 00 00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E
         00 73 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 00 00 00 00 09 04 E4 04 }
      $b4 = {9C 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 06 00 01 40 B0 1D 01 00 06 00 01 40 B0 1D 3F 00 00 00
         00 00 00 00 04 00 04 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 FA 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 D6 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 58
         00 18 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 52 00 65 00 67 00 69
         00 73 00 74 00 72 00 79 00 20 00 45 00 64 00 69 00 74 00 6F 00 72 00
         20 00 55 00 74 00 69 00 6C 00 69 00 74 00 79 00 00 00 6C 00 26 00 01
         00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00
         00 00 00 00 36 00 2E 00 31 00 2E 00 37 00 36 00 30 00 30 00 2E 00 31
         00 36 00 33 00 38 00 35 00 20 00 28 00 77 00 69 00 6E 00 37 00 5F 00
         72 00 74 00 6D 00 2E 00 30 00 39 00 30 00 37 00 31 00 33 00 2D 00 31
         00 32 00 35 00 35 00 29 00 00 00 3A 00 0D 00 01 00 49 00 6E 00 74 00
         65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 72 00 65
         00 67 00 65 00 64 00 74 00 33 00 32 00 2E 00 65 00 78 00 65 00 00 00
         00 00 80 00 2E 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
         00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9 00 20 00 4D 00 69 00
         63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00 6F 00 72 00 70
         00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20 00 41 00 6C 00
         6C 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73
         00 65 00 72 00 76 00 65 00 64 00 2E 00 00 00 42 00 0D 00 01 00 4F 00
         72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E
         00 61 00 6D 00 65 00 00 00 72 00 65 00 67 00 65 00 64 00 74 00 33 00
         32 00 2E 00 65 00 78 00 65 00 00 00 00 00 6A 00 25 00 01 00 50 00 72
         00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00
         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57
         00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00
         72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65
         00 6D 00 00 00 00 00 42 00 0F 00 01 00 50 00 72 00 6F 00 64 00 75 00
         63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 36 00 2E
         00 31 00 2E 00 37 00 36 00 30 00 30 00 2E 00 31 00 36 00 33 00 38 00
         35 00 00 00 00 00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6C
         00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 24 00 04 00 00 00 54 00
         72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 00 00 00
         00 09 04 B0 04}
      $b5 = {78 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 00 00 05 00 6A 44 B1 1D 00 00 05 00 6A 44 B1 1D 3F 00 00 00
         00 00 00 00 04 00 04 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 D6 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 B2 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 4E
         00 13 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 57 00 69 00 6E 00 64
         00 6F 00 77 00 73 00 AE 00 53 00 79 00 73 00 55 00 74 00 69 00 6C 00
         69 00 74 00 79 00 00 00 00 00 72 00 29 00 01 00 46 00 69 00 6C 00 65
         00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00
         30 00 2E 00 37 00 36 00 30 00 31 00 2E 00 31 00 37 00 35 00 31 00 34
         00 20 00 28 00 77 00 69 00 6E 00 37 00 73 00 70 00 31 00 5F 00 72 00
         74 00 6D 00 2E 00 31 00 30 00 31 00 31 00 31 00 39 00 2D 00 31 00 38
         00 35 00 30 00 29 00 00 00 00 00 30 00 08 00 01 00 49 00 6E 00 74 00
         65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 6D 00 73
         00 69 00 65 00 78 00 65 00 63 00 00 00 80 00 2E 00 01 00 4C 00 65 00
         67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
         00 00 00 A9 00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00
         74 00 20 00 43 00 6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F
         00 6E 00 2E 00 20 00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68 00
         74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2E
         00 00 00 40 00 0C 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00
         6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 73
         00 69 00 65 00 78 00 65 00 63 00 2E 00 65 00 78 00 65 00 00 00 58 00
         1C 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D
         00 65 00 00 00 00 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 53 00
         79 00 73 00 55 00 74 00 69 00 6C 00 69 00 74 00 79 00 20 00 2D 00 20
         00 55 00 6E 00 69 00 63 00 6F 00 64 00 65 00 00 00 42 00 0F 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69
         00 6F 00 6E 00 00 00 35 00 2E 00 30 00 2E 00 37 00 36 00 30 00 31 00
         2E 00 31 00 37 00 35 00 31 00 34 00 00 00 00 00 44 00 00 00 01 00 56
         00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00
         00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74
         00 69 00 6F 00 6E 00 00 00 00 00 09 04 B0 04}
      $b6 = {D4 02 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 17 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 34 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         00 65 00 49 00 6E 00 66 00 6F 00 00 00 10 02 00 00 01 00 30 00 34 00
         30 00 39 00 30 00 34 00 65 00 34 00 00 00 4C 00 16 00 01 00 43 00 6F
         00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 00
         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00 6F
         00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 4E 00
         13 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69
         00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 53 00 65 00 72 00 69 00
         61 00 6C 00 20 00 50 00 6F 00 72 00 74 00 20 00 44 00 72 00 69 00 76
         00 65 00 72 00 00 00 00 00 62 00 21 00 01 00 46 00 69 00 6C 00 65 00
         56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31
         00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00 20 00
         28 00 78 00 70 00 73 00 70 00 2E 00 30 00 38 00 30 00 34 00 31 00 33
         00 2D 00 30 00 38 00 35 00 32 00 29 00 00 00 00 00 4A 00 13 00 01 00
         4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67
         00 68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00
         74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 30 00 34 00 00 00 00
         00 6A 00 25 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00
         61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
         00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00
         AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20
         00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 40 00 0E 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69
         00 6F 00 6E 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00 30 00 30 00
         2E 00 35 00 35 00 31 00 32 00 00 00 44 00 00 00 01 00 56 00 61 00 72
         00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 24 00
         04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F
         00 6E 00 00 00 00 00 09 04 E4 04}
   condition:
      (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
      (((any of ($a*)) and (uint32(uint32(0x3C)+8) == 0x00000000)) or
      (for any of ($b*): ($ in (uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+20))..(uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+20))+uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+16)))))))
}

*/

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-12
   Identifier: Grizzly Steppe Alternatives
*/

/* Alternative Rule Set ---------------------------------------------------- */

rule IMPLANT_4_v3_AlternativeRule {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      comment = "Alternative rule - not based on the original samples but samples on which the original rule matched"
      author = "Florian Roth"
      reference = "US CERT Grizzly Steppe Report"
      date = "2017-02-12"
      hash1 = "2244fe9c5d038edcb5406b45361613cf3909c491e47debef35329060b00c985a"
   strings:
      $op1 = { 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 53 1e 01 00 } /* Opcode */
      $op2 = { 21 da 40 00 00 a0 40 00 08 a0 40 00 b0 70 40 00 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and all of them )
}

/* Alternative Rule Set ---------------------------------------------------- */

rule IMPLANT_4_v4 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DK_format1 = "/c format %c: /Y /Q" ascii
      $DK_format2 = "/c format %c: /Y /X /FS:NTFS" ascii
      $DK_physicaldrive = "PhysicalDrive%d" wide
      $DK_shutdown = "shutdown /r /t %d"
   condition:
      uint16(0) == 0x5A4D and all of ($DK*)
}

rule IMPLANT_4_v5 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $GEN_HASH = {0F BE C9 C1 C0 07 33 C1}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or
      uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or
      uint32(1) == 0x6674725C) and all of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_4_v6 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "DispatchCommand" wide ascii
      $STR2 = "DispatchEvent" wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

*/

rule IMPLANT_4_v7 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $sb1 = {C7 [1-5] 33 32 2E 64 C7 [1-5] 77 73 32 5F 66 C7 [1-5] 6C 6C}
      $sb2 = {C7 [1-5] 75 73 65 72 C7 [1-5] 33 32 2E 64 66 C7 [1-5] 6C 6C}
      $sb3 = {C7 [1-5] 61 64 76 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb4 = {C7 [1-5] 77 69 6E 69 C7 [1-5] 6E 65 74 2E C7 [1-5] 64 6C 6C}
      $sb5 = {C7 [1-5] 73 68 65 6C C7 [1-5] 6C 33 32 2E C7 [1-5] 64 6C 6C}
      $sb6 = {C7 [1-5] 70 73 61 70 C7 [1-5] 69 2E 64 6C 66 C7 [1-5] 6C}
      $sb7 = {C7 [1-5] 6E 65 74 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb8 = {C7 [1-5] 76 65 72 73 C7 [1-5] 69 6F 6E 2E C7 [1-5] 64 6C 6C}
      $sb9 = {C7 [1-5] 6F 6C 65 61 C7 [1-5] 75 74 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb10 = {C7 [1-5] 69 6D 61 67 C7 [1-5] 65 68 6C 70 C7 [1-5] 2E 64 6C 6C}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 3 of them
}

rule IMPLANT_4_v8 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $f1 = {5E 81 EC 04 01 00 00 8B D4 68 04 01 00 00 52 6A 00 FF 57 1C 8B D4
         33 C9 03 D0 4A 41 3B C8 74 05 80 3A 5C 75 F5 42 81 EC 04 01 00 00 8B
         DC 52 51 53 68 04 01 00 00 FF 57 20 59 5A 66 C7 04 03 5C 20 56 57 8D
         3C 03 8B F2 F3 A4 C6 07 00 5F 5E 33 C0 50 68 80 00 00 00 6A 02 50 50
         68 00 00 00 40 53 FF 57 14 53 8B 4F 4C 8B D6 33 DB 30 1A 42 43 3B D9
         7C F8 5B 83 EC 04 8B D4 50 6A 00 52 FF 77 4C 8B D6 52 50 FF 57 24 FF
         57 18}
      $f2 = {5E 83 EC 1C 8B 45 08 8B 4D 08 03 48 3C 89 4D E4 89 75 EC 8B 45 08
         2B 45 10 89 45 E8 33 C0 89 45 F4 8B 55 0C 3B 55 F4 0F 86 98 00 00 00
         8B 45 EC 8B 4D F4 03 48 04 89 4D F4 8B 55 EC 8B 42 04 83 E8 08 D1 E8
         89 45 F8 8B 4D EC 83 C1 08 89 4D FC}
      $f3 = {5F 8B DF 83 C3 60 2B 5F 54 89 5C 24 20 8B 44 24 24 25 00 00 FF FF
         66 8B 18 66 81 FB 4D 5A 74 07 2D 00 00 01 00 EB EF 8B 48 3C 03 C8 66
         8B 19 66 81 FB 50 45 75 E0 8B E8 8B F7 83 EC 60 8B FC B9 60 00 00 00
         F3 A4 83 EF 60 6A 0D 59 E8 88 00 00 00 E2 F9 68 6C 33 32 00 68 73 68
         65 6C 54 FF 57}
      $a1 = {83 EC 04 60 E9 1E 01 00 00}
   condition:
      $a1 at pe.entry_point or any of ($f*)
}

rule IMPLANT_4_v9 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $a = "wevtutil clear-log" ascii wide nocase
      $b = "vssadmin delete shadows" ascii wide nocase
      $c = "AGlobal\\23d1a259-88fa-41df-935f-cae523bab8e6" ascii wide nocase
      $d = "Global\\07fd3ab3-0724-4cfd-8cc2-60c0e450bb9a" ascii wide nocase //$e = {57 55 33 c9 51 8b c3 99 57 52 50}
      $openPhysicalDiskOverwriteWithZeros = { 57 55 33 C9 51 8B C3 99 57 52
         50 E8 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 83 C4 10 84 C0 75 21 33 C0 89
         44 24 10 89 44 24 14 6A 01 8B C7 99 8D 4C 24 14 51 52 50 56 FF 15 ??
         ?? ?? ?? 85 C0 74 0B 83 C3 01 81 FB 00 01 00 00 7C B6 }
      $f = {83 c4 0c 53 53 6a 03 53 6a 03 68 00 00 00 c0}
   condition:
      ($a and $b) or $c or $d or ($openPhysicalDiskOverwriteWithZeros and $f)
}

rule IMPLANT_4_v10 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $ ={A1B05C72}
      $ ={EB3D0384}
      $ ={6F45594E}
      $ ={71815A4E}
      $ ={D5B03E72}
      $ ={6B43594E}
      $ ={F572993D}
      $ ={665D9DC0}
      $ ={0BE7A75A}
      $ ={F37443C5}
      $ ={A2A474BB}
      $ ={97DEEC67}
      $ ={7E0CB078}
      $ ={9C9678BF}
      $ ={4A37A149}
      $ ={8667416B}
      $ ={0A375BA4}
      $ ={DC505A8D}
      $ ={02F1F808}
      $ ={2C819712}
   condition:
      uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 and 15 of them
}

rule IMPLANT_4_v11 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $ = "/c format %c: /Y /X /FS:NTFS"
      $ = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" wide
      $ = ".dll.exe.xml.ttf.nfo.fon.ini.cfg.boot.jar" wide
      $= ".crt.bin.exe.db.dbf.pdf.djvu.doc.docx.xls.xlsx.jar.ppt.pptx.tib.vhd.iso.lib.mdb.accdb.sql.mdf.xml.rtf.ini.cf g.boot.txt.rar.msi.zip.jpg.bmp.jpeg.tiff" wide
      $tempfilename = "%ls_%ls_%ls_%d.~tmp" ascii wide
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 2 of them
}

/* Deactivated - Slowing down scanning

rule IMPLANT_4_v12 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $CMP1 = {81 ?? 4D 5A 00 00 }
      $SUB1 = {81 ?? 00 10 00 00}
      $CMP2 = {66 81 38 4D 5A}
      $SUB2 = {2D 00 10 00 00}
      $HAL = "HAL.dll"
      $OUT = {E6 64 E9 ?? ?? FF FF}
   condition:
   (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
   uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and ($CMP1 or $CMP2)
   and ($SUB1 or $SUB2) and $OUT and $HAL
}
*/

rule IMPLANT_4_v13 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XMLDOM1 = {81 BF 33 29 36 7B D2 11 B2 0E 00 C0 4F 98 3E 60}
      $XMLDOM2 = {90 BF 33 29 36 7B D2 11 B2 0E 00 C0 4F 98 3E 60}
      $XMLPARSE = {8B 06 [0-2] 8D 55 ?C 52 FF 75 08 [0-2] 50 FF 91 04 01 00 00
         66 83 7D ?C FF 75 3? 8B 06 [0-2] 8D 55 F? 52 50 [0-2] FF 51 30 85 C0
         78 2?}
      $EXP1 = "DispatchCommand"
      $EXP2 = "DispatchEvent"
      $BDATA = {85 C0 74 1? 0F B7 4? 06 83 C? 28 [0-6] 72 ?? 33 C0 5F 5E 5B 5D
         C2 08 00 8B 4? 0? 8B 4? 0? 89 01 8B 4? 0C 03 [0-2] EB E?}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_5_v1 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $hexstr = {2D 00 53 00 69 00 00 00 2D 00 53 00 70 00 00 00 2D 00 55 00
         70 00 00 00 2D 00 50 00 69 00 00 00 2D 00 50 00 70 00 00 00}
      $UDPMSG1 = "error 2005 recv from server UDP - %d\x0a"
      $TPSMSG1 = "error 2004 send to TPS - %d\x0a"
      $TPSMSG2 = "error 2003 recv from TPS - %d\x0a"
      $UDPMSG2 = "error 2002 send to server UDP - %d\x0a"
   condition:
      any of them
}

rule IMPLANT_5_v2 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $key0 = { 987AB999FE0924A2DF0A412B14E26093746FCDF9BA31DC05536892C33B116AD3 }
      $key1 = { 8B236C892D902B0C9A6D37AE4F9842C3070FBDC14099C6930158563C6AC00FF5 }
      $key2 = { E47B7F110CAA1DA617545567EC972AF3A6E7B4E6807B7981D3CFBD3D8FCC3373 }
      $key3 = { 48B284545CA1FA74F64FDBE2E605D68CED8A726D05EBEFD9BAAC164A7949BDC1 }
      $key4 = { FB421558E30FCCD95FA7BC45AC92D2991C44072230F6FBEAA211341B5BF2DC56 }
      $key5 = { 34F1AE17017AF16021ADA5CE3F77675BBC6E7DEC6478D6078A0B22E5FDFF3B31 }
      $key6 = { F0EA48F164395186E6F754256EBB812A2AFE168E77ED9501F8B8E6F5B72126A7 }
      $key7 = { 0B6E9970A8EAF68EE14AB45005357A2F3391BEAA7E53AB760B916BC2B3916ABE }
      $key8 = { FF032EA7ED2436CF6EEA1F741F99A3522A61FDA8B5A81EC03A8983ED1AEDAB1A }
      $key9 = { F0DAC1DDFEF7AC6DE1CBE1006584538FE650389BF8565B32E0DE1FFACBCB14BB }
      $key10 = { A5D699A3CD4510AF11F1AF767602055C523DF74B94527D74319D6EFC6883B80D }
      $key11 = { 5951B02696C1D5A7B2851D28872384DA607B25F4CEA268FF3FD7FBA75AB3B4B3 }
      $key12 = { 0465D99B26AF42D8346001BB838595E301BAD8CF5D40CE9C17C944717DF82481 }
      $key13 = { 5DFE1C83AD5F5CE1BF5D9C42E23225E3ECFDB2493E80E6554A2AC7C722EB4880 }
      $key14 = { E9650396C45F7783BC14C59F46EA8232E8357C26B5627BFF8C42C6AE2E0F2E17 }
      $key15 = { 7432AE389125BB4E3980ED7F6A6FB252A42E785A90F4591C3620CA642FF97CA3 }
      $key16 = { 2B2ADBBC4F960A8916F7088067BAD30BE84B65783FBF9476DF5FDA0E5856B183 }
      $key17 = { 808C3FD0224A59384161B8A81C8BB404D7197D16D8118CB77067C5C8BD764B3E }
      $key18 = { 028B0E24D5675C16C815BFE4A073E9778C668E65771A1CE881E2B03F58FC7D5B }
      $key19 = { 878B7F5CF2DC72BAF1319F91A4880931EE979665B1B24D3394FE72EDFAEF4881 }
      $key20 = { 7AC7DD6CA34F269481C526254D2F563BC6ECA1779FEEAA33EC1C20E60B686785 }
      $key21 = { 3044F1D394186815DD8E3A2BBD9166837D07FA1CF6A550E2C170C9CDD9305209 }
      $key22 = { 7544DC095C441E39D258648FE9CB1267D20D83C8B2D3AB734474401DA4932619 }
      $key23 = { D702223347406C1999D1A9829CBBE96EC86D377A40E2EE84562EA1FAC1C71498 }
      $key24 = { CA36CB1177382A1009D392A58F7C1357E94AD2292CC0AE82EE4F7DB0179148E1 }
      $key25 = { C714F23E4C1C4E55F0E1FA7F5D0DD64658A86F84681D07576D840784154F65DC }
      $key26 = { 63571BAF736904634AFEE2A70CB9ED64615DE8CA7AEF21E773286B8877D065DB }
      $key27 = { 27808A9BE98FFE348DE1DB999AC9FDFB26E6C5A0D5E688490EF3D186C43661EB }
      $key28 = { B6EB86A07A85D40866AFA100789FFB9E85C13F5AA7C7A3B6BA753C7EAB9D6A62 }
      $key29 = { 88F0020375D60BDB85ACDBFE4BD79CD098DB2B3FA2CEF55D4331DBEFCE455157 }
      $key30 = { 36535AAB296587AE1162AC5D39492DD1245811C72706246A38FF590645AA5D7B }
      $key31 = { FDB726261CADD52E10818B49CAB81BEF112CB63832DAA26AD9FC711EA6CE99A4 }
      $key32 = { 86C0CAA26D9FD07D215BC7EB14E2DA250E905D406AFFAB44FB1C62A2EAFC4670 }
      $key33 = { BC101329B0E3A7D13F6EBC535097785E27D59E92D449D6D06538725034B8C0F0 }
      $key34 = { C8D31A78B7C149F62F06497F9DC1DDC4967B566AC52C3A2A65AC7A99643B8A2D }
      $key35 = { 0EA4A5C565EFBB94F5041392C5F0565B6BADC630D9005B3EADD5D81110623E1F }
      $key36 = { 06E4E46BD3A0FFC8A4125A6A02B0C56D5D8B9E378CF97539CE4D4ADFAF89FEB5 }
      $key37 = { 6DE22040821F0827316291331256A170E23FA76E381CA7066AF1E5197AE3CFE7 }
      $key38 = { C6EF27480F2F6F40910074A45715143954BBA78CD74E92413F785BBA5B2AA121 }
      $key39 = { 19C96A28F8D9698ADADD2E31F2426A46FD11D2D45F64169EDC7158389BFA59B4 }
      $key40 = { C3C3DDBB9D4645772373A815B5125BB2232D8782919D206E0E79A6A973FF5D36 }
      $key41 = { C33AF1608037D7A3AA7FB860911312B4409936D236564044CFE6ED42E54B78A8 }
      $key42 = { 856A0806A1DFA94B5E62ABEF75BEA3B657D9888E30C8D2FFAEC042930BBA3C90 }
      $key43 = { 244496C524401182A2BC72177A15CDD2EF55601F1D321ECBF2605FFD1B9B8E3F }
      $key44 = { DF24050364168606D2F81E4D0DEB1FFC417F1B5EB13A2AA49A89A1B5242FF503 }
      $key45 = { 54FA07B8108DBFE285DD2F92C84E8F09CDAA687FE492237F1BC4343FF4294248 }
      $key46 = { 23490033D6BF165B9C45EE65947D6E6127D6E00C68038B83C8BFC2BCE905040C }
      $key47 = { 4E044025C45680609B6EC52FEB3491130A711F7375AAF63D69B9F952BEFD5F0C }
      $key48 = { 019F31C5F5B2269020EBC00C1F511F2AC23E9D37E89374514C6DA40A6A03176C }
      $key49 = { A2483197FA57271B43E7276238468CFB8429326CBDA7BD091461147F642BEB06 }
      $key50 = { 731C9D6E74C589B7ACB019E5F6A6E07ACF12E68CB9A396CE05AA4D69D5387048 }
      $key51 = { 540DB6C8D23F7F7FEF9964E53F445F0E56459B10E931DEEEDB2B57B063C7F8B7 }
      $key52 = { D5AF80A7EEFF26DE988AC3D7CE23E62568813551B2133F8D3E973DA15E355833 }
      $key53 = { E4D8DBD3D801B1708C74485A972E7F00AFB45161C791EE05282BA68660FFBA45 }
      $key54 = { D79518AF96C920223D687DD596FCD545B126A678B7947EDFBF24661F232064FB }
      $key55 = { B57CAA4B45CA6E8332EB58C8E72D0D9853B3110B478FEA06B35026D7708AD225 }
      $key56 = { 077C714C47DFCF79CA2742B1544F4AA8035BB34AEA9D519DEE77745E01468408 }
      $key57 = { C3F5550AD424839E4CC54FA015994818F4FB62DE99B37C872AF0E52C376934FA }
      $key58 = { 5E890432AE87D0FA4D209A62B9E37AAEDEDC8C779008FEBAF9E4E6304D1B2AAC }
      $key59 = { A42EDE52B5AF4C02CFE76488CADE36A8BBC3204BCB1E05C402ECF450071EFCAB }
      $key60 = { 4CDAFE02894A04583169E1FB4717A402DAC44DA6E2536AE53F5F35467D31F1CA }
      $key61 = { 0BEFCC953AD0ED6B39CE6781E60B83C0CFD166B124D1966330CBA9ADFC9A7708 }
      $key62 = { 8A439DC4148A2F4D5996CE3FA152FF702366224737B8AA6784531480ED8C8877 }
      $key63 = { CF253BE3B06B310901FF48A351471374AD35BBE4EE654B72B860F2A6EC7B1DBB }
      $key64 = { A0599F50C4D059C5CFA16821E97C9596B1517B9FB6C6116F260415127F32CE1F }
      $key65 = { 8B6D704F3DC9150C6B7D2D54F9C3EAAB14654ACA2C5C3952604E65DF8133FE0C }
      $key66 = { A06E5CDD3871E9A3EE17F7E8DAE193EE47DDB87339F2C599402A78C15D77CEFD }
      $key67 = { E52ADA1D9BC4C089DBB771B59904A3E0E25B531B4D18B58E432D4FA0A41D9E8A }
      $key68 = { 4778A7E23C686C171FDDCCB8E26F98C4CBEBDF180494A647C2F6E7661385F05B }
      $key69 = { FE983D3A00A9521F871ED8698E702D595C0C7160A118A7630E8EC92114BA7C12 }
      $key70 = { 52BA4C52639E71EABD49534BBA80A4168D15762E2D1D913BAB5A5DBF14D9D166 }
      $key71 = { 931EB8F7BC2AE1797335C42DB56843427EB970ABD601E7825C4441701D13D7B1 }
      $key72 = { 318FA8EDB989672DBE2B5A74949EB6125727BD2E28A4B084E8F1F50604CCB735 }
      $key73 = { 5B5F2315E88A42A7B59C1B493AD15B92F819C021BD70A5A6619AAC6666639BC2 }
      $key74 = { C2BED7AA481951FEB56C47F03EA38236BC425779B2FD1F1397CB79FE2E15C0F0 }
      $key75 = { D3979B1CB0EC1A655961559704D7CDC019253ACB2259DFB92558B7536D774441 }
      $key76 = { 0EDF5DBECB772424D879BBDD51899D6AAED736D0311589566D41A9DBB8ED1CC7 }
      $key77 = { CC798598F0A9BCC82378A5740143DEAF1A147F4B2908A197494B7202388EC905 }
      $key78 = { 074E9DF7F859BF1BD1658FD2A86D81C282000EAB09AF4252FAB45433421D3849 }
      $key79 = { 6CD540642E007F00650ED20D7B54CFFD54DDA95D8DEBB087A004BAE222F22C8E }
      $key80 = { C76CF2F66C71F6D17FC8DEFA1CAEF8718BA1CE188C7EA02C835A0FA54D3B3314 }
      $key81 = { A7250A149600E515C9C40FE5720756FDA8251635A3B661261070CB5DABFE7253 }
      $key82 = { 237C67B97D4CCE4610DE2B82E582808EA796C34A4C24715C953CBA403B2C935E }
      $key83 = { A8FA182547E66B57C497DAAA195A38C0F0FB0A3C1F7B98B4B852F5F37E885127 }
      $key84 = { 83694CCA50B821144FFBBE6855F62845F1328111AE1AC5666CBA59EB43AA12C6 }
      $key85 = { 145E906416B17865AD37CD022DF5481F28C930D6E3F53C50B0953BF33F4DB953 }
      $key86 = { AB49B7C2FA3027A767F5AA94EAF2B312BBE3E89FD924EF89B92A7CF977354C22 }
      $key87 = { 7E04E478340C209B01CA2FEBBCE3FE77C6E6169F0B0528C42FA4BDA6D90AC957 }
      $key88 = { 0EADD042B9F0DDBABA0CA676EFA4EDB68A045595097E5A392217DFFC21A8532F }
      $key89 = { 5623710F134ECACD5B70434A1431009E3556343ED48E77F6A557F2C7FF46F655 }
      $key90 = { 6968657DB62F4A119F8E5CB3BF5C51F4B285328613AA7DB9016F8000B576561F }
      $key91 = { DEBB9C95EAE6A68974023C335F8D2711135A98260415DF05845F053AD65B59B4 }
      $key92 = { 16F54900DBF08950F2C5835153AB636605FB8C09106C0E94CB13CEA16F275685 }
      $key93 = { 1C9F86F88F0F4882D5CBD32876368E7B311A84418692D652A6A4F315CC499AE8 }
      $key94 = { E920E0783028FA05F4CE2D6A04BBE636D56A775CFD4DAEA3F2A1B8BEEB52A6D4 }
      $key95 = { 73874CA3AF47A8A315D50E1990F44F655EC7C15B146FFE0611B6C4FC096BD07C }
      $key96 = { F21C1FA163C745789C53922C47E191A5A85301BDC2FFC3D3B688CFBFF39F3BE5 }
      $key97 = { BC5A861F21CB98BD1E2AE9650B7A0BB4CD0C71900B3463C1BC3380AFD2BB948E }
      $key98 = { 151BAE36E646F30570DC6A7B57752F2481A0B48DD5184E914BCF411D8AD5ACA0 }
      $key99 = { F05AD6D7A0CADC10A6468BFDBCBB223D5BD6CA30EE19C239E8035772D80312C9 }
      $key100 = { 5DE9A0FDB37C0D59C298577E5379BCAF4F86DF3E9FA17787A4CEFA7DD10C462E }
      $key101 = { F5E62BA862380224D159A324D25FD321E5B35F8554D70CF9A506767713BCA508 }
      $key102 = { A2D1B10409B328DA0CCBFFDE2AD2FF10855F95DA36A1D3DBA84952BB05F8C3A7 }
      $key103 = { C974ABD227D3AD339FAC11C97E11D904706EDEA610B181B8FAD473FFCC36A695 }
      $key104 = { AB5167D2241406C3C0178D3F28664398D5213EE5D2C09DCC9410CB604671F5F1 }
      $key105 = { C25CC4E671CAAA31E137700A9DB3A272D4E157A6A1F47235043D954BAE8A3C70 }
      $key106 = { E6005757CA0189AC38F9B6D5AD584881399F28DA949A0F98D8A4E3862E20F715 }
      $key107 = { 204E6CEB4FF59787EF4D5C9CA5A41DDF4445B9D8E0C970B86D543E9C7435B194 }
      $key108 = { 831D7FD21316590263B69E095ABBE89E01A176E16AE799D83BD774AF0D254390 }
      $key109 = { 42C36355D9BC573D72F546CDB12E6BB2CFE2933AC92C12040386B310ABF6A1ED }
      $key110 = { B9044393C09AD03390160041446BF3134D864D16B25F1AB5E5CDC690C4677E7D }
      $key111 = { 6BC1102B5BE05EEBF65E2C3ACA1F4E17A59B2E57FB480DE016D371DA3AEF57A5 }
      $key112 = { B068D00B482FF73F8D23795743C76FE8639D405EE54D3EFB20AFD55A9E2DFF4E }
      $key113 = { 95CF5ADDFE511C8C7496E3B75D52A0C0EFE01ED52D5DD04D0CA6A7ABD3A6F968 }
      $key114 = { 75534574A4620019F8E3D055367016255034FA7D91CBCA9E717149441742AC8D }
      $key115 = { 96F1013A5301534BE424A11A94B740E5EB3A627D052D1B769E64BAB6A666433C }
      $key116 = { 584477AB45CAF729EE9844834F84683ABECAB7C4F7D23A9636F54CDD5B8F19B3 }
      $key117 = { D3905F185B564149EE85CC3D093477C8FF2F8CF601C68C38BBD81517672ECA3A }
      $key118 = { BF29521A7F94636D1930AA236422EB6351775A523DE68AF9BF9F1026CEDA618D }
      $key119 = { 04B3A783470AF1613A9B849FBD6F020EE65C612343EB1C028B2C28590789E60B }
      $key120 = { 3D8D8E84977FE5D21B6971D8D873E7BED048E21333FE15BE2B3D1732C7FD3D04 }
      $key121 = { 8ACB88224B6EF466D7653EB0D8256EA86D50BBA14FD05F7A0E77ACD574E9D9FF }
      $key122 = { B46121FFCF1565A77AA45752C9C5FB3716B6D8658737DF95AE8B6A2374432228 }
      $key123 = { A4432874588D1BD2317224FB371F324DD60AB25D4191F2F01C5C13909F35B943 }
      $key124 = { 78E1B7D06ED2A2A044C69B7CE6CDC9BCD77C19180D0B082A671BBA06507349C8 }
      $key125 = { 540198C3D33A631801FE94E7CB5DA3A2D9BCBAE7C7C3112EDECB342F3F7DF793 }
      $key126 = { 7E905652CAB96ACBB7FEB2825B55243511DF1CD8A22D0680F83AAF37B8A7CB36 }
      $key127 = { 37218801DBF2CD92F07F154CD53981E6189DBFBACAC53BC200EAFAB891C5EEC8 }
   condition:
      any of them
}

rule IMPLANT_5_v3 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $BYTES1 = { 0F AF C0 6? C0 07 00 00 00 2D 01 00 00 00 0F AF ?? 39 ?8 }
      $BYTES2 = { 0F AF C0 6? C0 07 48 0F AF ?? 39 ?8 }
   condition:
      any of them
}

rule IMPLANT_5_v4 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $FBKEY1 = { 987AB999FE0924A2DF0A412B14E26093746FCDF9BA31DC05536892C33B116AD3 }
      $FBKEY2 = { 8B236C892D902B0C9A6D37AE4F9842C3070FBDC14099C6930158563C6AC00FF5 }
      $FBKEY3 = { E47B7F110CAA1DA617545567EC972AF3A6E7B4E6807B7981D3CFBD3D8FCC3373 }
      $FBKEY4 = { 48B284545CA1FA74F64FDBE2E605D68CED8A726D05EBEFD9BAAC164A7949BDC1 }
      $FBKEY5 = { FB421558E30FCCD95FA7BC45AC92D2991C44072230F6FBEAA211341B5BF2DC56 }
   condition:
      all of them
}

rule IMPLANT_6_v1
{
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "dll.dll" wide ascii
      $STR2 = "Init1" wide ascii
      $STR3 = "netui.dll" wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v2 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $obf_func = { 8B 45 F8 6A 07 03 C7 33 D2 89 45 E8 8D 47 01 5B 02 4D 0F F7 F3 6A 07 8A 04 32 33 D2 F6 E9 8A C8 8B C7 F7 F3 8A 44 3E FE 02 45 FC 02 0C 32 B2 03 F6 EA 8A D8 8D 47 FF 33 D2 5F F7 F7 02 5D 14 8B 45 E8 8B 7D F4 C0 E3 06 02 1C 32 32 CB 30 08 8B 4D 14 41 47 83 FF 09 89 4D 14 89 7D F4 72 A1 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v3 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $deob_func = { 8D 46 01 02 D1 83 E0 07 8A 04 38 F6 EA 8B D6 83 E2 07 0A
         04 3A 33 D2 8A 54 37 FE 03 D3 03 D1 D3 EA 32 C2 8D 56 FF 83 E2 07 8A
         1C 3A 8A 14 2E 32 C3 32 D0 41 88 14 2E 46 83 FE 0A 7C ?? }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v4 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $ASM = {53 5? 5? [6-15] ff d? 8b ?? b? a0 86 01 00 [7-13] ff d? ?b
         [6-10] c0 [0-1] c3}
   condition:
   (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
   uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v5 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 EC 18 8B 4C 24 24 B8 AB AA AA AA F7 E1 8B 44 24 20 53 55 8B
         EA 8D 14 08 B8 AB AA AA AA 89 54 24 1C F7 E2 56 8B F2 C1 ED 02 8B DD
         57 8B 7C 24 38 89 6C 24 1C C1 EE 02 3B DE 89 5C 24 18 89 74 24 20 0F
         83 CF 00 00 00 8D 14 5B 8D 44 12 FE 89 44 24 10 3B DD 0F 85 CF 00 00
         00 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B CA 83 F9 06 89 4C 24 38 0F 83
         86 00 00 00 8A C3 B2 06 F6 EA 8B 54 24 10 88 44 24 30 8B 44 24 2C 8D
         71 02 03 D0 89 54 24 14 8B 54 24 10 33 C0 8A 44 37 FE 03 D6 8B D8 8D
         46 FF 0F AF DA 33 D2 BD 06 00 00 00 F7 F5 C1 EB 07 8A 04 3A 33 D2 32
         D8 8D 46 01 F7 F5 8A 44 24 30 02 C1 8A 0C 3A 33 D2 32 C8 8B C6 F7 F5
         8A 04 3A 22 C8 8B 44 24 14 02 D9 8A 0C 30 32 CB 88 0C 30 8B 4C 24 38
         41 46 83 FE 08 89 4C 24 38 72 A1 8B 5C 24 18 8B 6C 24 1C 8B 74 24 20
         8B 4C 24 10 43 83 C1 06 3B DE 89 4C 24 10 8B 4C 24 34 89 5C 24 18 0F
         82 3C FF FF FF 3B DD 75 1A 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B CA EB
         0D 33 C9 89 4C 24 38 E9 40 FF FF FF 33 C9 8B 44 24 24 33 D2 BE 06 00
         00 00 89 4C 24 38 F7 F6 3B CA 89 54 24 24 0F 83 95 00 00 00 8A C3 B2
         06 F6 EA 8D 1C 5B 88 44 24 30 8B 44 24 2C 8D 71 02 D1 E3 89 5C 24 34
         8D 54 03 FE 89 54 24 14 EB 04 8B 5C 24 34 33 C0 BD 06 00 00 00 8A 44
         3E FE 8B D0 8D 44 1E FE 0F AF D0 C1 EA 07 89 54 24 2C 8D 46 FF 33 D2
         BB 06 00 00 00 F7 F3 8B 5C 24 2C 8A 04 3A 33 D2 32 D8 8D 46 01 F7 F5
         8A 44 24 30 02 C1 8A 0C 3A 33 D2 32 C8 8B C6 F7 F5 8A 04 3A 22 C8 8B
         44 24 14 02 D9 8A 0C 06 32 CB 88 0C 06 8B 4C 24 38 8B 44 24 24 41 46
         3B C8 89 4C 24 38 72 8F 5F 5E 5D 5B 83 C4 18 C2 10 00 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v6 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $Init1_fun = {68 10 27 00 00 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 6A FF 50
         FF 15 ?? ?? ?? ?? 33 C0 C3}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_6_v7 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "Init1"
      $OPT1 = "ServiceMain"
      $OPT2 = "netids" nocase wide ascii
      $OPT3 = "netui" nocase wide ascii
      $OPT4 = "svchost.exe" wide ascii
      $OPT5 = "network" nocase wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $STR1 and 2 of ($OPT*)
}

*/

rule IMPLANT_7_v1 {
   meta:
      description = "Implant 7 by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8A 44 0A 03 32 C3 0F B6 C0 66 89 04 4E 41 3B CF 72 EE }
      $STR2 = { F3 0F 6F 04 08 66 0F EF C1 F3 0F 7F 04 11 83 C1 10 3B CF 72 EB }
   condition:
      (uint16(0) == 0x5A4D) and ($STR1 or $STR2)
}

rule IMPLANT_8_v1
{
   meta:
      description = "HAMMERTOSS / HammerDuke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DOTNET = "mscorlib" ascii
      $REF_URL = "https://www.google.com/url?sa=" wide
      $REF_var_1 = "&rct=" wide
      $REF_var_2 = "&q=&esrc=" wide
      $REF_var_3 = "&source=" wide
      $REF_var_4 = "&cd=" wide
      $REF_var_5 = "&ved=" wide
      $REF_var_6 = "&url=" wide
      $REF_var_7 = "&ei=" wide
      $REF_var_8 = "&usg=" wide
      $REF_var_9 = "&bvm=" wide
      $REF_value_1 = "QFj" wide
      $REF_value_2 = "bv.81" wide
   condition:
      (uint16(0) == 0x5A4D) and ($DOTNET) and ($REF_URL) and
      (3 of ($REF_var*)) and (1 of ($REF_value*))
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_8_v2 {
   meta:
      description = "HAMMERTOSS / HammerDuke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DOTNET= "mscorlib" ascii
      $XOR = {61 20 AA 00 00 00 61}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

*/

rule IMPLANT_9_v1 {
   meta:
      description = "Onion Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8B 03 8A 54 01 03 32 55 FF 41 88 54 39 FF 3B CE 72 EE }
      $STR2 = { 8B C8 83 E1 03 8A 54 19 08 8B 4D 08 32 54 01 04 40 88 54 38 FF
         3B C6 72 E7 }
      $STR3 = { 8B 55 F8 8B C8 83 E1 03 8A 4C 11 08 8B 55 FC 32 0C 10 8B 17 88
         4C 02 04 40 3B 06 72 E3 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0)) and all of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_10_v1 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {33 ?? 83 F2 ?? 81 E2 FF 00 00 00}
      $STR2 = {0F BE 14 01 33 D0 ?? F2 [1-4] 81 E2 FF 00 00 00 66 89 [6] 40 83
         F8 ?? 72}
   condition:
      uint16(0) == 0x5A4D and ($STR1 or $STR2)
}

*/

rule IMPLANT_10_v2 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $xor = { 34 ?? 66 33 C1 48 FF C1 }
      $nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00}
   condition:
      uint16(0) == 0x5A4D and $xor and $nop
}

/* Deactivated - Slowing down scanning

rule IMPLANT_11_v12 {
   meta:
      description = "Mini Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {63 74 00 00} // ct
      $STR2 = {72 6F 74 65} // rote
      $STR3 = {75 61 6C 50} // triV
      $STR4 = {56 69 72 74} // Plau
      $STR5 = { e8 00 00 00 00 }
      $STR6 = { 64 FF 35 00 00 00 00 }
      $STR7 = {D2 C0}
      $STR8 = /\x63\x74\x00\x00.{3,20}\x72\x6F\x74\x65.{3,20}\x75\x61\x6C\x50.{3,20}\x56\x69\x72\x74/
   condition:
      (uint16(0) == 0x5A4D) and #STR5 > 4 and all of them
}

rule IMPLANT_12_v1 {
   meta:
      description = "Cosmic Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $FUNC = {A1 [3-5] 33 C5 89 [2-3] 56 57 83 [4-6] 64}
   condition:
      (uint16(0) == 0x5A4D) and $FUNC
}

*/

rule Unidentified_Malware_Two {
   meta:
      description = "Unidentified Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $my_string_one = "/zapoy/gate.php"
      $my_string_two = { E3 40 FE 45 FD 0F B6 45 FD 0F B6 14 38 88 55 FF 00 55
         FC 0F B6 45 FC 8A 14 38 88 55 FE 0F B6 45 FD 88 14 38 0F B6 45 FC 8A
         55 FF 88 14 38 8A 55 FF 02 55 FE 8A 14 3A 8B 45 F8 30 14 30 }
      $my_string_three = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb"
      $my_string_four = { 8B CF 0F AF CE 8B C6 99 2B C2 8B 55 08 D1 F8 03 C8
         8B 45 FC 03 C2 89 45 10 8A 00 2B CB 32 C1 85 DB 74 07 }
      $my_string_five = "fuckyou1"
      $my_string_six = "xtool.exe"
   condition:
      ($my_string_one and $my_string_two)
      or ($my_string_three or $my_string_four)
      or ($my_string_five and $my_string_six)
}
