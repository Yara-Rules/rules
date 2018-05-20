import "pe"

rule SAmSAmRansom2016 {
   meta:
      author = "Christiaan Beek"
      date = "2018-01-25"
      hash1 = "45e00fe90c8aa8578fce2b305840e368d62578c77e352974da6b8f8bc895d75b"
      hash2 = "946dd4c4f3c78e7e4819a712c7fd6497722a3d616d33e3306a556a9dc99656f4"
      hash3 = "979692a34201f9fc1e1c44654dc8074a82000946deedfdf6b8985827da992868"
      hash4 = "939efdc272e8636fd63c1b58c2eec94cf10299cd2de30c329bd5378b6bbbd1c8"
      hash5 = "a763ed678a52f77a7b75d55010124a8fccf1628eb4f7a815c6d635034227177e"
      hash6 = "e682ac6b874e0a6cfc5ff88798315b2cb822d165a7e6f72a5eb74e6da451e155"
      hash7 = "6bc2aa391b8ef260e79b99409e44011874630c2631e4487e82b76e5cb0a49307"
      hash8 = "036071786d7db553e2415ec2e71f3967baf51bdc31d0a640aa4afb87d3ce3050"
      hash9 = "ffef0f1c2df157e9c2ee65a12d5b7b0f1301c4da22e7e7f3eac6b03c6487a626"
      hash10 = "89b4abb78970cd524dd887053d5bcd982534558efdf25c83f96e13b56b4ee805"
      hash11 = "7aa585e6fd0a895c295c4bea2ddb071eed1e5775f437602b577a54eef7f61044"
      hash12 = "0f2c5c39494f15b7ee637ad5b6b5d00a3e2f407b4f27d140cd5a821ff08acfac"
      hash13 = "58ef87523184d5df3ed1568397cea65b3f44df06c73eadeb5d90faebe4390e3e"
      
   strings:
      $x1 = "Could not list processes locking resource. Failed to get size of result." fullword wide
      $s2 = "Could not list processes locking resource." fullword wide
      $s3 = "samsam.del.exe" fullword ascii
      $s4 = "samsam.exe" fullword wide
      $s5 = "RM_UNIQUE_PROCESS" fullword ascii
      $s6 = "KillProcessWithWait" fullword ascii
      $s7 = "killOpenedProcessTree" fullword ascii
      $s8 = "RM_PROCESS_INFO" fullword ascii
      $s9 = "Exception caught in process: {0}" fullword wide
      $s10 = "Could not begin restart session.  Unable to determine file locker." fullword wide
      $s11 = "samsam.Properties.Resources.resources" fullword ascii
      $s12 = "EncryptStringToBytes" fullword ascii
      $s13 = "recursivegetfiles" fullword ascii
      $s14 = "RSAEncryptBytes" fullword ascii
      $s15 = "encryptFile" fullword ascii
      $s16 = "samsam.Properties.Resources" fullword wide
      $s17 = "TSSessionId" fullword ascii
      $s18 = "Could not register resource." fullword wide
      $s19 = "<recursivegetfiles>b__0" fullword ascii
      $s20 = "create_from_resource" fullword ascii

      $op0 = { 96 00 e0 00 29 00 0b 00 34 23 }
      $op1 = { 96 00 12 04 f9 00 34 00 6c 2c }
      $op2 = { 72 a5 0a 00 70 a2 06 20 94 }
      
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 700KB and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}

rule SamSam_Ransomware_Latest
{
   meta:
      description = "Latest SamSA ransomware samples"
      author = "Christiaan Beek"
      reference = "http://blog.talosintelligence.com/2018/01/samsam-evolution-continues-netting-over.html"
      date = "2018-01-23"
      hash1 = "e7bebd1b1419f42293732c70095f35c8310fa3afee55f1df68d4fe6bbee5397e"
      hash2 = "72832db9b951663b8f322778440b8720ea95cde0349a1d26477edd95b3915479"
      hash3 = "3531bb1077c64840b9c95c45d382448abffa4f386ad88e125c96a38166832252"
      hash4 = "88d24b497cfeb47ec6719752f2af00c802c38e7d4b5d526311d552c6d5f4ad34"
      hash5 = "8eabfa74d88e439cfca9ccabd0ee34422892d8e58331a63bea94a7c4140cf7ab"
      hash6 = "88e344977bf6451e15fe202d65471a5f75d22370050fe6ba4dfa2c2d0fae7828"

   strings:
      $s1 = "bedf08175d319a2f879fe720032d11e5" fullword wide
      $s2 = "ksdghksdghkddgdfgdfgfd" fullword ascii
      $s3 = "osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg" fullword ascii
      $s4 = "5c2d376c976669efaf9cb107f5a83d0c" fullword wide
      $s5 = "B917754BCFE717EB4F7CE04A5B11A6351EEC5015" fullword ascii
      $s6 = "f99e47c1d4ccb2b103f5f730f8eb598a" fullword wide
      $s7 = "d2db284217a6e5596913e2e1a5b2672f" fullword wide
      $s8 = "0bddb8acd38f6da118f47243af48d8af" fullword wide
      $s9 = "f73623dcb4f62b0e5b9b4d83e1ee4323" fullword wide
      $s10 = "916ab48e32e904b8e1b87b7e3ced6d55" fullword wide
      $s11 = "c6e61622dc51e17195e4df6e359218a2" fullword wide
      $s12 = "2a9e8d549af13031f6bf7807242ce27f" fullword wide
      $s13 = "e3208957ad76d2f2e249276410744b29" fullword wide
      $s14 = "b4d28bbd65da97431f494dd7741bee70" fullword wide
      $s15 = "81ee346489c272f456f2b17d96365c34" fullword wide
      $s16 = "94682debc6f156b7e90e0d6dc772734d" fullword wide
      $s17 = "6943e17a989f11af750ea0441a713b89" fullword wide
      $s18 = "b1c7e24b315ff9c73a9a89afac5286be" fullword wide
      $s19 = "90928fd1250435589cc0150849bc0cff" fullword wide
      $s20 = "67da807268764a7badc4904df351932e" fullword wide

      $op0 = { 30 01 00 2b 68 79 33 38 68 34 77 65 36 34 74 72 }
      $op1 = { 01 00 b2 04 00 00 01 00 84 }
      $op2 = { 68 09 00 00 38 66 00 00 23 55 53 00 a0 6f 00 00 }

   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 100KB and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them ) and all of ($op*)
      ) or ( all of them )
}

