/*
This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule chromePolishStrings {   

    meta:
            author = "Vishal Thakur - malienist.medium.com"
            date = "2024-Jan-2"
            version = "1"
            description = "Detects ChromePolish Malware"
            info = "Generated from information extracted from the malware sample by manual analysis."
    strings:
            $str1 = { 28 65 72 72 50 74 72 2D 3E 45 52 52 63 49 6E 69 74 44 74 63 20 3E 3D 20 76 61 72 54 79 70 65 2D 3E 74 70 43 6C 61 73 73 2E 74 70 63 44 74 6F 72 43 6F 75 6E 74 29 20 7C 7C 20 66 6C 61 67 73 }
            $str2 = { 28 63 74 6F 72 4D 61 73 6B 20 26 20 30 78 30 31 30 30 29 20 21 3D 20 30 20 7C 7C 20 28 63 74 6F 72 4D 61 73 6B 20 26 20 30 78 30 30 32 30 29 20 3D 3D 20 30 }
            $str3 = { 4E 6F 20 73 70 61 63 65 20 66 6F 72 20 63 6F 6D 6D 61 6E 64 20 6C 69 6E 65 20 61 72 67 75 6D 65 6E 74 20 76 65 63 74 6F 72 }
            $str4 = { 41 74 74 65 6D 70 74 65 64 20 74 6F 20 72 65 6D 6F 76 65 20 63 75 72 72 65 6E 74 20 64 69 72 65 63 74 6F 72 79 }
            $str5 = { 76 61 72 54 79 70 65 2D 3E 74 70 43 6C 61 73 73 2E 74 70 63 44 74 6F 72 41 64 64 72 }
            $str6 = { 49 53 5F 43 4C 41 53 53 28 64 74 74 50 74 72 2D 3E 64 74 74 54 79 70 65 2D 3E 74 70 4D 61 73 6B 29 20 26 26 20 28 64 74 74 50 74 72 2D 3E 64 74 74 54 79 70 65 2D 3E 74 70 43 6C 61 73 73 2E 74 70 63 46 6C 61 67 73 20 26 20 43 46 5F 48 41 53 5F 44 54 4F 52 29 }
            $str7 = { 64 74 74 50 74 72 2D 3E 64 74 74 54 79 70 65 2D 3E 74 70 50 74 72 2E 74 70 70 42 61 73 65 54 79 70 65 2D 3E 74 70 43 6C 61 73 73 2E 74 70 63 46 6C 61 67 73 20 26 20 43 46 5F 48 41 53 5F 44 54 4F 52 }
            $str8 = { 74 67 74 54 79 70 50 74 72 20 21 3D 20 30 20 26 26 20 5F 5F 69 73 53 61 6D 65 54 79 70 65 49 44 28 74 6F 70 54 79 70 50 74 72 2C 20 74 67 74 54 79 70 50 74 72 29 20 3D 3D 20 30 }
            $str9 = { 76 61 72 54 79 70 65 2D 3E 74 70 41 72 72 2E 74 70 61 45 6C 65 6D 54 79 70 65 2D 3E 74 70 43 6C 61 73 73 2E 74 70 63 46 6C 61 67 73 20 26 20 43 46 5F 48 41 53 5F 44 54 4F 52 }
            $str10 = { 43 61 6E 27 74 20 61 64 6A 75 73 74 20 63 6C 61 73 73 20 61 64 64 72 65 73 73 20 28 6E 6F 20 62 61 73 65 20 63 6C 61 73 73 20 65 6E 74 72 79 20 66 6F 75 6E 64 29 }
            
    condition:
        filesize < 100KB and
        8 of them
}
