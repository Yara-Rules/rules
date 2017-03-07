/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
import "pe"
import "math"
rule susp_file_enumerator_with_encrypted_resource_101 {
  meta:
    copyright = "Kaspersky Lab"
    description = "Generic detection for samples that enumerate files with encrypted resource called 101"
    hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
    hash = "c843046e54b755ec63ccb09d0a689674"
    version = "1.4"
  strings:
    $mz = "This program cannot be run in DOS mode."
    $a1 = "FindFirstFile" ascii wide nocase
    $a2 = "FindNextFile" ascii wide nocase
    $a3 = "FindResource" ascii wide nocase
    $a4 = "LoadResource" ascii wide nocase
condition:
uint16(0) == 0x5A4D and
all of them and
filesize < 700000 and
pe.number_of_sections > 4 and
pe.number_of_signatures == 0 and
pe.number_of_resources > 1 and pe.number_of_resources < 15 and
for any i in (0..pe.number_of_resources - 1):
( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and
pe.resources[i].id == 101 and
pe.resources[i].length > 20000 and
pe.resources[i].language == 0 and
not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
)
}
rule StoneDrill_main_sub {
meta:
 author = "Kaspersky Lab"
 description = "Rule to detect StoneDrill (decrypted) samples"
 hash = "d01781f1246fd1b64e09170bd6600fe1"
 hash = "ac3c25534c076623192b9381f926ba0d"
 version = "1.0"
strings:
 $code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF
30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}
condition:
 uint16(0) == 0x5A4D and
 $code and
 filesize < 5000000
}
