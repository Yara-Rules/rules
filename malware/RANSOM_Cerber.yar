/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule cerber3{
meta:
  author = "pekeinfo"
  date = "2016-09-09"
  description = "Cerber3 "
strings:
  $a = {00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 03 6A  01 8B 85}
  $b = {68 3B DB 00 00 ?? ?? ?? ?? 00 ?? FF 15}
  
condition:
  1 of them 
}


rule cerber4{
meta:
        author = "pekeinfo"
        date = "2016-09-09"
        description = "Cerber4"
strings:
        $a = {8B 0D ?? ?? 43 00 51 8B 15 ?? ?? 43 00 52 E8 C9 04 00 00 83 C4 08 89 45 FC A1 ?? ?? 43 00 3B 05 ?? ?? 43 00 72 02}

condition:
        1 of them 
}


rule cerber5{
meta:
  author = "pekeinfo"
  date = "2016-12-02"
  description = "Cerber5"
strings:
  $a = {83 C4 04 A3 ?? ?? ?? 00 C7 45 ?? ?? ?? ?? 00 8B ?? ?? C6 0? 56 8B ?? ?? 5? 68 ?? ?? 4? 00 FF 15 ?? ?? 4? 00 50 FF 15 ?? ?? 4? 00 A3 ?? ?? 4? 00 68 1D 10 00 00 E8 ?? ?? FF FF 83 C4 04 ?? ?? ??}
  
condition:
  1 of them 
}


rule cerber5b{
meta:
  author = "pekeinfo"
  date = "2016-12-20"
  description = "Cerber5b"
strings:
  $a={8B ?? ?8 ?? 4? 00 83 E? 02 89 ?? ?8 ?? 4? 00 68 ?C ?9 4? 00 [0-6] ?? ?? ?? ?? ?? ?8 ?? 4? 00 5? FF 15 ?? ?9 4? 00 89 45 ?4 83 7D ?4 00 75 02 EB 12 8B ?? ?0 83 C? 06 89 ?? ?0 B? DD 03 00 00 85}  
condition:
  $a
}
