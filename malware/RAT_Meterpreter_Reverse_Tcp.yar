/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Meterpreter_Reverse_Tcp { 
  meta: // This is the standard backdoor/RAT from Metasploit, could be used by any actor 
    author = "chort (@chort0)" 
    description = "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64." 
  strings: 
    $a = { 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 } // METERPRETER_TRANSPORT_SSL … https://XXXXXX 
    $b = { 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 } // METERPRETER_UA 
    $c = { 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 } // GET /123456789 HTTP/1.0 
    $d = { 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } // metsrv.dll … ReflectiveLoader 
    
  condition: 
    $a or (any of ($b, $d) and $c) 
  }


