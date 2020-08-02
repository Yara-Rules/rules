/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/
rule MALW_PurpleWave_v1
{
    meta:
        Description ="Generic rule to identify PurpleWave v1.0"
        Author = "Xylitol <xylitol@temari.fr>"
        date = "2020-08-01"
        reference = "https://twitter.com/3xp0rtblog/status/1289125217751781376"
        hash1 = "7de7b866c46f34be28f7085fb1a1727ab939d65abd3128871fb68c42371af2df"
        hash2 = "76bffcf04104a1c4e6a5792d3795d1a03c7497a274042889b8f44c8f8facc304"
        hash3 = "832d667b00c07424f050f84e717f8db22833b1e8e131aa7a33de739c4f4b4cdd"
        hash4 = "917057a6a03252bc2525b326a63111fce050fc86e6e3b26fa9e452489f1358b9"
        hash5 = "a8577e1ccad877ae5ff4bf89aa578989404643c6fdf10baafd4335a1766abb16"
        hash6 = "d5ec98c98a8f56fdeb00cc2404c4527a39726bf43d8b9cf6c4c8c36364f94161"
        hash7 = "d820ec7f9196a5cc3dbc2b5860334a2e174fede80efc3b8463756fb8767dddf9"
        hash8 = "d4572e26b9e6ce963af590979afe3df6e1be78aa8ec0e926e77b0affb7ab1554"
        hash9 = "4b3cb90581dcd77c9ceffbd662b8dac70b68de5a03cd56940434cc035209d61d"

    strings:
        $MZ = {4D 5A}
        $decoderoutine = { 8B 45 E8 33 C9 8A 04 07 28 04 1A 42 83 FF 07 8D 47 01 0F 45 C8 8B F9 3B D6 7C E5 }
        /*
        generic routine used to decode strings (bot name, bot version, mutex, c2 url, etc..)
        /8B45 E8         /MOV EAX,[LOCAL.6]
        |33C9            |XOR ECX,ECX
        |8A0407          |MOV AL,BYTE PTR DS:[EDI+EAX]
        |28041A          |SUB BYTE PTR DS:[EDX+EBX],AL
        |42              |INC EDX
        |83FF 07         |CMP EDI,7
        |8D47 01         |LEA EAX,DWORD PTR DS:[EDI+1]
        |0F45C8          |CMOVNE ECX,EAX
        |8BF9            |MOV EDI,ECX
        |3BD6            |CMP EDX,ESI
        \7C E5           \JL SHORT 76bffcf0.0135B57F
        */

        // Regular strings that can be found into purplewave 1.0 samples
        $string1 = " at t.me/LuckyStoreSupport |" fullword wide
        $string2 = "][aes_key]" wide ascii
        $string3 = "][passwords][" wide ascii
        $string4 = "][is_encrypted]" wide ascii
        $string5 = "][cards][" wide ascii
        $string6 = "][number]" wide ascii
        $string7 = "][domain]" wide ascii
        $string8 = "][cookies][" wide ascii
        $string9 = "][flag]" wide ascii
        $string10 = "][histories][" wide ascii
        $string11 = "D877F783D5D3EF8C" wide ascii

        $alphabet1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $alphabet2 = "0123456789abcdefghijklmnopqrstuvwxyz"

    condition: 
	($MZ at 0 and $decoderoutine) and
	(
		(5 of ($string*) and all of ($alphabet*))
	)

	and filesize < 700KB // Standard size when not packed should be arround ~598/600kb
}
