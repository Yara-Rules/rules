/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Trojan_W32_Gh0stMiancha_1_0_0
{
    meta:
        Author      = "Context Threat Intelligence"
        Date        = "2014/01/27"
        Description = "Bytes inside"
        Reference   = "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf"

    strings:
        $0x = { 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }
        $1 = { 5c e7 99 bd e5 8a a0 e9 bb 91 5c }
        $1x = { 48 f3 8d a9 f1 9e b4 fd af 85 48 }
        $2 = "DllCanLoadNow"
        $2x = { 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }
        $3x = { 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 } 
        $4 = "JXNcc2hlbGxcb3Blblxjb21tYW5k"
        $4x = { 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }
        $5 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
        $5x = { 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }
        $6 = "C:\\Users\\why\\"
        $6x = { 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }
        $7 = "g:\\ykcx\\"
        $7x = { 73 2E 48 6D 7F 77 6C 48 }
        $8 = "(miansha)"
        $8x = { 3C 79 7D 75 7A 67 7C 75 3D }
        $9 = "server(\xE5\xA3\xB3)"
        $9x = { 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }
        $cfgDecode = { 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}

   condition:
       any of them
}
