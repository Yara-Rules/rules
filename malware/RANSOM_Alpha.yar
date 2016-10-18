
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Ransom_Alpha
{
meta:
description = "Regla para detectar Ransom.Alpha (posibles falsos positivos)"
author = "CCN-CERT"
version = "1.0"
strings:
$a = { 52 00 65 00 61 00 64 00 20 00 4D 00 65 00 20 00 28 00 48 00 6F 00 77 00 20 00 44 00 65 00 63 }
condition:
$a
}

rule Ransom_Alfa
{
meta:
description = "Regla para detectar W32/Filecoder.Alfa (Posibles falsos positivos)"
author = "CCN-CERT"
version = "1.0"
strings:
$a = { 8B 0C 97 81 E1 FF FF 00 00 81 F9 19 04 00 00 74 0F 81 F9 } 
$b = { 22 04 00 00 74 07 42 3B D0 7C E2 EB 02 }
condition:
all of them
}
