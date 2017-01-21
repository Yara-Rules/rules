/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule apt_backspace
{

    meta:
        description = "Detects APT backspace"
        author = "Bit Byte Bitten"
        date = "2015-05-14"
        hash = "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"
        
    strings:
        $s1 = "!! Use Splice Socket !!"
        $s2 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
        $s3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"

    condition:
        uint16(0) == 0x5a4d and all of them
}
