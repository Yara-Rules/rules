/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule LogPOS
{
    meta:
        author = "Morphick Security"
        description = "Detects Versions of LogPOS"
        md5 = "af13e7583ed1b27c4ae219e344a37e2b"
    strings:
        $mailslot = "\\\\.\\mailslot\\LogCC"
        $get = "GET /%s?encoding=%c&t=%c&cc=%I64d&process="
        //64A130000000      mov eax, dword ptr fs:[0x30]
        //8B400C        mov eax, dword ptr [eax + 0xc]
        //8B401C        mov eax, dword ptr [eax + 0x1c]
        //8B4008        mov eax, dword ptr [eax + 8]
        $sc = {64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }
    condition:
        $sc and 1 of ($mailslot,$get)
}
