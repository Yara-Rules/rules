/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"

rule APT_DeputyDog_Fexel
{

meta:
    author = "ThreatConnect Intelligence Research Team"

strings:
    $180 = "180.150.228.102" wide ascii
    $0808cmd = {25 30 38 78 30 38 78 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 [2-6] 43 00 61 00 6E 00 27 00 74 00 20 00 6F 00 70 00 65 00 6E 00 20 00 73 00 68 00 65 00 6C 00 6C 00 21}
    $cUp = "Upload failed! [Remote error code:" nocase wide ascii
    $DGGYDSYRL = {00 44 47 47 59 44 53 59 52 4C 00}
    $GDGSYDLYR = "GDGSYDLYR_%" wide ascii

condition:
    any of them
}

rule APT_DeputyDog
{

    meta:
        Author      = "FireEye Labs"
        Date        = "2013/09/21"
        Description = "detects string seen in samples used in 2013-3893 0day attacks"
        Reference   = "https://www.fireeye.com/blog/threat-research/2013/09/operation-deputydog-zero-day-cve-2013-3893-attack-against-japanese-targets.html"

    strings:
        $mz = {4d 5a}
        $a = "DGGYDSYRL"

    condition:
        ($mz at 0) and $a
}
