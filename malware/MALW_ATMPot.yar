/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Generic_ATMPot : Generic_ATMPot
{
    meta:
        description = "Generic rule for Winpot aka ATMPot"
        author = "xylitol@temari.fr"
        date = "2019-02-24"
        reference = "https://securelist.com/atm-robber-winpot/89611/"
        // May only the challenge guide you
    strings:
        $api1 = "CSCCNG" ascii wide
        $api2 = "CscCngOpen" ascii wide
        $api3 = "CscCngClose" ascii wide
        $string1 = "%d,%02d;" ascii wide
/*
0xD:
.text:004022EC FF 15 20 70 40 00             CALL DWORD PTR DS:[407020]  ; cscwcng.CscCngDispense
.text:004022F2 F6 C4 80                      TEST AH,80
winpot:
.text:004019D4 FF 15 24 60 40 00             CALL DWORD PTR DS:[406024]  ; cscwcng.CscCngDispense
.text:004019DA F6 C4 80                      TEST AH,80
*/
        $hex1 = { FF 15 ?? ?? ?? ?? F6 C4 80 }
/*
0xD...: 0040506E  25 31 5B 31 2D 34 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[1-4]VAL=%8[0-9]
winpot: 0040404D  25 31 5B 30 2D 39 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[0-9]VAL=%8[0-9]
*/
        $hex2 = { 25 31 5B ?? 2D ?? 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D }
    condition:  
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
