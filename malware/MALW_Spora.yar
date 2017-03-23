/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Spora
{
    meta:
        author = "pekeinfo"
        date = "2017-02-22"
        description = "Spora"
    
    strings:
        $a={7B 7F 4E 11 5D F3 FE 15 F9 55 FD 00 AD E9 CF FE E2 56 78 03 D0 21 46 00 30 68 C4 D0 01 FD 00 C3 B7 00 4A 0D 57 D2 52 91 05}
        $b={6F 51 3E 6B F9 15 29 D9 DF 26 1E 80 62 8A 0D E3 64 51 3B 0F F3 FE FF FF F3 FE FF FF F3 FE FF FF F3 FE FF FF}

    condition:
        $a and $b 
}

rule unk_packer
{
    meta:
        author = "pekeinfo"
        date = "2017-02-22"
        description = "Spora & Cerber ek"

    strings:
        $a = {0E 9E 52 69 C8 E4 73 BF 87 2B 95 15 33 1B B7 6B 46 62 D8 C1 01 A9 F9 17 FC EF 1A 6E B7 36 3C C4 72 7D 5D 1A 2D C4 7E 70 E8 0A A0 C6 A3 51 C1 1C 5E 98 E2 72 19 DF 03 C9 D4 25 25 1F EF 6B 46 75 9C BB 1D D2 57 56 35 75 31 35 56 8F B7 5B 23 3D }
        $b ={00 10 00 2E E8 77 EC FF FF 85 C0 0F 85 78 C4 FF}

    condition:
        $a and $b
}
