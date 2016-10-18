/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule Ransom_Satana
{
    meta:
        description = "Regla para detectar Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 21 00 73 00 61 00 74 00 61 00 6E 00 61 00 21 00 2E 00 74 00 78 00 74 00 00 }
        $b = { 74 67 77 79 75 67 77 71 }
        $c = { 53 77 76 77 6E 67 75 }
        $d = { 45 6E 75 6D 4C 6F 63 61 6C 52 65 73 }
        $e = { 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 57 00 }
        $f = { 21 53 41 54 41 4E 41 21 }
    condition:
        $b or $c and $d and $a and $e and $f
}

rule Ransom_Satana_Dropper
{
    meta:
        description = "Regla para detectar el dropper de Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 25 73 2D 54 72 79 45 78 63 65 70 74 }
        $b = { 64 3A 5C 6C 62 65 74 77 6D 77 79 5C 75 69 6A 65 75 71 70 6C 66 77 75 62 2E 70 64 62 }
        $c = { 71 66 6E 74 76 74 68 62 }
    condition:
        all of them
}
