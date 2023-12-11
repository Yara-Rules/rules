/*
This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule DarkGateStrings {   

    meta:
            author = "Vishal Thakur - malienist.medium.com"
            date = "2023-Dec-11"
            version = "1"
            description = "Detects DarkGate Malware"
            info = "Generated from information extracted from the malware sample by manual analysis."
    strings:
            $str1 = { 2f 63 20 63 6d 64 6b 65 79 20 2f 67 65 6e 65 72 69 63 3a 22 31 32 37 2e 30 2e 30 2e 32 22 20 2f 75 73 65 72 3a 22 53 61 66 65 4d 6f 64 65 22 20 2f 70 61 73 73 3a 22 64 61 72 6b 67 61 74 65 70 61 73 73 77 6f 72 64 30 22 }
            $str2 = { 43 3a 5c 74 65 6d 70 5c 74 73 6b 6d }
            $str3 = { 4e 6f 20 73 74 61 72 74 75 70 20 63 6f 6e 66 69 67 75 72 65 64 2c 20 73 6b 69 70 20 75 70 64 61 74 65 }
            $str4 = { 43 6f 72 72 75 70 74 65 64 20 64 6f 77 6e 6c 6f 61 64 65 64 20 72 65 73 6f 75 72 63 65 73 }
            $str5 = { 54 68 65 72 65 27 73 20 6e 6f 20 63 72 65 64 65 6e 74 69 61 6c 73 20 74 6f 20 72 65 6d 6f 76 65 }
            $str6 = { 2f 63 20 63 3a 5c 74 65 6d 70 5c 50 73 45 78 65 63 2e 65 78 65 20 2d 61 63 63 65 70 74 65 75 6c 61 20 2d 69 20 2d 64 20 2d 73 }
            $str7 = { 53 43 6f 72 72 75 70 74 65 64 20 64 6f 77 6e 6c 6f 61 64 65 64 20 72 65 73 6f 75 72 63 65 73 }
            $str8 = { 63 3a 5c 74 65 6d 70 5c 63 72 61 73 68 2e 74 78 74 }
            $str9 = { 64 61 72 6b 67 61 74 65 70 61 73 73 77 6f 72 64 30 }
            
    condition:
        7 of them
}

rule DarkGateElevation {
    meta:
            author = "Vishal Thakur - malienist.medium.com"
            date = "2023-Dec-11"
            version = "1"
            description = "Detects DarkGate Malware"
            info = "Generated from information extracted from the malware sample by manual analysis. Rule to detect DarkGate related to elevation."
    strings:
        $str1 = { 53 59 53 54 45 4d 20 45 6c 65 76 61 74 69 6f 6e 3a 20 43 61 6e 6e 6f 74 20 66 69 6e 64 20 52 41 57 20 50 45 }
        $str2 = { 50 45 49 20 6e 65 65 64 20 41 64 6d 69 6e 20 72 69 67 68 74 73 20 74 6f 20 65 6c 65 76 61 74 65 20 74 6f 20 53 59 53 54 45 4d }
        $str3 = { 45 6c 65 76 61 74 69 6f 6e 3a 20 41 54 20 52 41 57 20 53 54 55 42 20 45 4c 45 56 41 54 49 4f 4e 20 49 53 20 4e 4f 54 20 41 56 41 49 4c 41 42 4c 45 }
        $str4 = { 53 59 53 54 45 4d 20 45 6c 65 76 61 74 69 6f 6e 3a 20 43 6f 6d 70 6c 65 74 65 64 2c 20 6e 65 77 20 44 61 72 6b 47 61 74 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 77 69 74 68 20 53 59 53 54 45 4d 20 70 72 69 76 69 6c 65 67 65 73 2c 20 45 78 65 63 75 74 65 64 20 66 72 6f 6d 3a }
        $str5 = { 45 6c 65 76 61 74 69 6f 6e 3a 20 3f 3f 3f }
        $str6 = { 45 6c 65 76 61 74 69 6f 6e 3a 20 46 41 49 4c 55 52 45 }
        
    condition:
        4 of them
}

rule DarkGateMisc {
    meta:
              author = "Vishal Thakur - malienist.medium.com"
              date = "2023-Dec-11"
              version = "1"
              description = "Detects DarkGate Malware"
              info = "Generated from information extracted from the malware sample by manual analysis. Rule to detect DarkGate related to misc strings."
    strings: 
              $str1= { 2f 63 20 63 3a 5c 74 65 6d 70 5c 50 73 45 78 65 63 2e 65 78 65 20 2d 61 63 63 65 70 74 65 75 6c 61 20 2d 69 20 2d 64 20 2d 73 }
              $str2= { 4e 6f 20 73 74 61 72 74 75 70 20 63 6f 6e 66 69 67 75 72 65 64 2c 20 73 6b 69 70 20 75 70 64 61 74 65 }
              $str3= { 43 6f 72 72 75 70 74 65 64 20 64 6f 77 6e 6c 6f 61 64 65 64 20 72 65 73 6f 75 72 63 65 73 }
              $str4= { 63 3a 5c 74 65 6d 70 5c 50 73 45 78 65 63 2e 65 78 65 }
              $str5= { 63 3a 5c 74 65 6d 70 5c 70 69 64 67 69 6e 2e 65 78 65 }
              $str6= { 63 3a 5c 74 65 6d 70 5c 63 72 61 73 68 2e 74 78 74 }
              $str7= { 63 3a 5c 74 65 6d 70 5c 70 2e 74 78 74 }
              $str8= { 63 3a 5c 74 65 6d 70 5c 64 2e 74 78 74 }
              $str9= { 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 56 47 }
              $str10= { 63 3a 5c 74 65 6d 70 5c 41 75 74 6f 69 74 33 2e 65 78 65 }
    condition:
            8 of them
}

rule DarkGateRndm {
      meta:
              author = "Vishal Thakur - malienist.medium.com"
              date = "2023-Dec-11"
              version = "1"
              description = "Detects DarkGate Malware"
              info = "Generated from information extracted from the malware sample by manual analysis. Rule to detect DarkGate related to strings found in the binary."
      strings:
              $str1= { 20 2d 2d 6d 75 74 65 2d 61 75 64 69 6f 20 2d 2d 64 69 73 61 62 6c 65 2d 61 75 64 69 6f 20 2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 6e 65 77 2d 77 69 6e 64 6f 77 20 2d 2d 64 69 73 61 62 6c 65 2d 33 64 2d 61 70 69 73 20 2d 2d 64 69 73 61 62 6c 65 2d 67 70 75 20 2d 2d 64 69 73 61 62 6c 65 2d 64 33 64 31 31 20 2d 2d 77 69 6e 64 6f 77 2d 73 69 7a 65 3d 0a }
              $str2= { 7a 4c 41 78 75 55 30 6b 51 4b 66 33 73 57 45 37 65 50 52 4f 32 69 6d 79 67 39 47 53 70 56 6f 59 43 36 72 68 6c 58 34 38 5a 48 6e 76 6a 4a 44 42 4e 46 74 4d 64 31 49 35 61 63 77 62 71 54 2b 3d }
              $str3= { 2f 63 20 78 63 6f 70 79 20 2f 45 20 2f 49 20 2f 59 20 22 25 73 22 20 22 25 73 22 20 26 26 20 65 78 69 74 }
              $str4= { 6b 61 63 6c 6a 63 62 65 6a 6f 6a 6e 61 70 6e 6d 69 69 66 67 63 6b 62 61 66 6b 6f 6a 63 6e 63 66 }
              $str5= { 65 70 63 6e 6e 66 62 6a 66 63 67 70 68 67 64 6d 67 67 6b 61 6d 6b 6d 67 6f 6a 64 61 67 64 6e 6e }
              $str6= { 6c 61 6c 66 70 6a 64 62 68 70 6d 6e 68 66 6f 66 6b 63 6b 64 70 6b 6c 6a 65 69 6c 6d 6f 67 66 6c }
              $str7= { 52 53 41 63 74 69 6f 6e 53 65 6e 64 48 51 53 63 72 65 65 6e 73 68 6f 74 }
                            
    condition:
            5 of them
}
