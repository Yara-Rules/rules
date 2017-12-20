rule remsec_executable_blob_32
    {
        meta:
            author = "remsec"
 strings:
     $code = { 31 06 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 F0 }  
 condition:
         all of them
 }
 
 rule remsec_executable_blob_64
 {
     meta:
         author = "remsec"
     strings:
         $code = { 31 06 48 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 EF }
 condition:  
   all of them  
 }
 
 rule remsec_executable_blob_parser
 {
     meta:
         author = "remsec"
     strings:
         $code ={ ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }
     condition:
         all of them
 }
 
 rule remsec_encrypted_api
 {
     meta:
         author = "remsec"
     strings:
         $open_process ={ 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }  
 condition:  
   all of them  
 }
 
 
 rule remsec_packer_u
 {
     meta:
         author = "remsec"
     strings:
     $code={ 69 ( C? | D? | E? | F? ) AB 00 00 00 ( 81 | 41 81 ) C? CD 2B 00 00 ( F7 | 41 F7 ) E? ( C1 | 41 C1 ) E? 0D ( 69 | 45 69 ) ( C? | D? | E? | F? ) 85 CF 00 00 ( 29 | 41 29 | 44 29 | 45 29 | 2B | 41 2B | 44 2B | 45 2B )} 
 condition:  
   all of them  
 }
 
 
 rule remsec_packer_B
 {
 meta:
         author = "remsec"
 strings:
         $code ={ 00 00 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) ( 44 88 6? 24 ?? | C6 44 24 ?? 00 ) 48 89 44 24 ?? 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) C7 44 24 ?? 0? 00 00 00 2B ?8 48 89 ?C 24 ?? 44 89 6? 24 ?? 83 C? 08 89 ?C 24 ?? ( FF | 41 FF ) D? ( 05 | 8D 88 ) 00 00 00 3A }
 condition:
         all of them
 } 
