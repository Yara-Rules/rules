/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule BlackEnergy_BE_2 {
        meta:
                description = "Detects BlackEnergy 2 Malware"
                author = "Florian Roth"
                reference = "http://goo.gl/DThzLz"
                date = "2015/02/19"
                hash = "983cfcf3aaaeff1ad82eb70f77088ad6ccedee77"
        strings:
                $mz = { 4d 5a }
                $s0 = "<description> Windows system utility service  </description>" fullword ascii
                $s1 = "WindowsSysUtility - Unicode" fullword wide
                $s2 = "msiexec.exe" fullword wide
                $s3 = "WinHelpW" fullword ascii
                $s4 = "ReadProcessMemory" fullword ascii
        condition:
                ( $mz at 0 ) and filesize < 250KB and all of ($s*)
}
