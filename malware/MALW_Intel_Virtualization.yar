/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Intel_Virtualization_Wizard_exe {
  meta:
    author = "cabrel@zerklabs.com"
    description = "Dynamic DLL abuse executable"

    file_1_seen = "2013-05-21"
    file_1_sha256 = "7787757ae851f4a162f46f794be1532ab78e1928185212bdab83b3106f28c708"

  strings:
    $a = {4C 6F 61 64 53 54 52 49 4E 47}
    $b = {49 6E 69 74 69 61 6C 69 7A 65 4B 65 79 48 6F 6F 6B}
    $c = {46 69 6E 64 52 65 73 6F 75 72 63 65 73}
    $d = {4C 6F 61 64 53 54 52 49 4E 47 46 72 6F 6D 48 4B 43 55}
    $e = {68 63 63 75 74 69 6C 73 2E 44 4C 4C}
  condition:
    all of them
}

rule Intel_Virtualization_Wizard_dll {
  meta:
    author = "cabrel@zerklabs.com"
    description = "Dynamic DLL (Malicious)"

    file_1_seen = "2013-05-21"
    file_1_sha256 = "485ae043b6a5758789f1d33766a26d8b45b9fde09cde0512aa32d4bd1ee04f28"

  strings:
    $a = {48 3A 5C 46 61 73 74 5C 50 6C 75 67 28 68 6B 63 6D 64 29 5C}
    $b = {64 6C 6C 5C 52 65 6C 65 61 73 65 5C 48 69 6A 61 63 6B 44 6C 6C 2E 70 64 62}

  condition:
    ($a and $b) and Intel_Virtualization_Wizard_exe
}
