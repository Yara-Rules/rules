/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule StuxNet_Malware_1 
{

    meta:
        description = "Stuxnet Sample - file malware.exe"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8"
    
    strings:
         // 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
         // 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
         // 0x10001780 33 c9     xor     ecx, ecx
         // 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
         // 0x10001785 89 02     mov     dword ptr [edx], eax
         // 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
         $op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
         // 0x10002045 74 36     je      0x1000207d
         // 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
         // 0x1000204a 83 ff 00  cmp     edi, 0
         // 0x1000204d 74 2e     je      0x1000207d
         // 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
         // 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
         $op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
         // 0x100020cf 74 70     je      0x10002141
         // 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
         // 0x100020d8 75 1b     jne     0x100020f5
         // 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
         $op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }
  
    condition:
        all of them
}

rule Stuxnet_Malware_2 
{
   
    meta:
        description = "Stuxnet Sample - file 63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
   
    strings:
        $s1 = "\\SystemRoot\\System32\\hal.dll" fullword wide
        $s2 = "http://www.jmicron.co.tw0" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule StuxNet_dll 
{

    meta:
        description = "Stuxnet Sample - file dll.dll"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"

    strings:
        $s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and $s1
}

rule Stuxnet_Shortcut_to 
{

    meta:
        description = "Stuxnet Sample - file Copy of Shortcut to.lnk"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"

    strings:
        $x1 = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide

    condition:
        uint16(0) == 0x004c and filesize < 10KB and $x1
}

rule Stuxnet_Malware_3 
{

    meta:
        description = "Stuxnet Sample - file ~WTR4141.tmp"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "6bcf88251c876ef00b2f32cf97456a3e306c2a263d487b0a50216c6e3cc07c6a"
        hash2 = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"

    strings:
        $x1 = "SHELL32.DLL.ASLR." fullword wide
        $s1 = "~WTR4141.tmp" fullword wide
        $s2 = "~WTR4132.tmp" fullword wide
        $s3 = "totalcmd.exe" fullword wide
        $s4 = "wincmd.exe" fullword wide
        $s5 = "http://www.realtek.com0" fullword ascii
        $s6 = "{%08x-%08x-%08x-%08x}" fullword wide

    condition:
        ( uint16(0) == 0x5a4d and filesize < 150KB and ( $x1 or 3 of ($s*) ) ) or ( 5 of them )
}

rule Stuxnet_Malware_4 
{

    meta:
        description = "Stuxnet Sample - file 0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        hash2 = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
   
    strings:
        $x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
        $x2 = "MRxCls.sys" fullword wide
        $x3 = "MRXNET.Sys" fullword wide
   
    condition:
        ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )
}

rule Stuxnet_maindll_decrypted_unpacked 
{

    meta:
        description = "Stuxnet Sample - file maindll.decrypted.unpacked.dll_"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "4c3d7b38339d7b8adf73eaf85f0eb9fab4420585c6ab6950ebd360428af11712"

    strings:
        $s1 = "%SystemRoot%\\system32\\Drivers\\mrxsmb.sys;%SystemRoot%\\system32\\Drivers\\*.sys" fullword wide
        $s2 = "<Actions Context=\"%s\"><Exec><Command>%s</Command><Arguments>%s,#%u</Arguments></Exec></Actions>" fullword wide
        $s3 = "%SystemRoot%\\inf\\oem7A.PNF" fullword wide
        $s4 = "%SystemRoot%\\inf\\mdmcpq3.PNF" fullword wide
        $s5 = "%SystemRoot%\\inf\\oem6C.PNF" fullword wide
        $s6 = "@abf varbinary(4096) EXEC @hr = sp_OACreate 'ADODB.Stream', @aods OUT IF @hr <> 0 GOTO endq EXEC @hr = sp_OASetProperty @" wide
        $s7 = "STORAGE#Volume#1&19f7e59c&0&" fullword wide
        $s8 = "view MCPVREADVARPERCON as select VARIABLEID,VARIABLETYPEID,FORMATFITTING,SCALEID,VARIABLENAME,ADDRESSPARAMETER,PROTOKOLL,MAXLIMI" ascii

    condition:
         6 of them
}

rule Stuxnet_s7hkimdb 
{

    meta:
        description = "Stuxnet Sample - file s7hkimdb.dll"
        author = "Florian Roth"
        reference = "Internal Research"
        date = "2016-07-09"
        hash1 = "4071ec265a44d1f0d42ff92b2fa0b30aafa7f6bb2160ed1d0d5372d70ac654bd"

    strings:
        $x1 = "S7HKIMDX.DLL" fullword wide

        /* Opcodes by Binar.ly */

        // 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
        // 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
        // 0x10001780 33 c9     xor     ecx, ecx
        // 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
        // 0x10001785 89 02     mov     dword ptr [edx], eax
        // 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
        $op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
        // 0x10002045 74 36     je      0x1000207d
        // 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
        // 0x1000204a 83 ff 00  cmp     edi, 0
        // 0x1000204d 74 2e     je      0x1000207d
        // 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
        // 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
        $op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
        // 0x100020cf 74 70     je      0x10002141
        // 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
        // 0x100020d8 75 1b     jne     0x100020f5
        // 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
        $op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

    condition:
        ( uint16(0) == 0x5a4d and filesize < 40KB and $x1 and all of ($op*) )
}

