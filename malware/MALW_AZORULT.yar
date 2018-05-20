/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "cuckoo"
rule Windows_Malware : Azorult_V2
    {
            meta:
                    author = "Xylitol xylitol@temari.fr"
                    date = "2017-09-30"
                    description = "Match first two bytes, strings, and parts of routines present in Azorult"
                    reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=4819&p=30867"
                    // May only the challenge guide you
            strings:
                    $mz = {4D 5A}
                    $string1 = "ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/" wide ascii // Azorult custom base64-like alphabet
                    $string2 = "SYSInfo.txt"
                    $string3 = "CookieList.txt"
                    $string4 = "Passwords.txt"
                    $constant1 = {85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57} // Azorult grabs .txt and .dat files from Desktop
                    $constant2 = {68 ?? ?? ?? ?? FF 75 FC 68 ?? ?? ?? ?? 8D 45 F8 BA 03 00} // Portion of code from Azorult self-delete function
            condition:
                    ($mz at 0 and all of ($string*) and ($constant1 or $constant2) or cuckoo.sync.mutex(/Ad48qw4d6wq84d56as|Adkhvhhydhasdasashbc/))
    }
