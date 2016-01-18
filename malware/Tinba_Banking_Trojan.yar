/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

rule Tinba2 {
        meta:
                author = "n3sfox <n3sfox@gmail.com>"
                date = "2015/11/07"
                description = "Tinba 2 (DGA) banking trojan"
                reference = "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world"
                filetype = "memory"
                hash1 = "c7f662594f07776ab047b322150f6ed0"
                hash2 = "dc71ef1e55f1ddb36b3c41b1b95ae586"
                hash3 = "b788155cb82a7600f2ed1965cffc1e88"

        strings:
                $str1 = "MapViewOfFile"
                $str2 = "OpenFileMapping"
                $str3 = "NtCreateUserProcess"
                $str4 = "NtQueryDirectoryFile"
                $str5 = "RtlCreateUserThread"
                $str6 = "DeleteUrlCacheEntry"
                $str7 = "PR_Read"
                $str8 = "PR_Write"
                $pubkey = "BEGIN PUBLIC KEY"
                $code1 = {50 87 44 24 04 6A ?? E8}

        condition:
                all of ($str*) and $pubkey and $code1
}
