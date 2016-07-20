/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Korplug_FAST {
    meta:
        description = "Rule to detect Korplug/PlugX FAST variant"
        author = "Florian Roth"
        date = "2015-08-20"
        hash = "c437465db42268332543fbf6fd6a560ca010f19e0fd56562fb83fb704824b371"
    strings:
        $x1 = "%s\\rundll32.exe \"%s\", ShadowPlay" fullword ascii

        $a1 = "ShadowPlay" fullword ascii

        $s1 = "%s\\rundll32.exe \"%s\"," fullword ascii
        $s2 = "nvdisps.dll" fullword ascii
        $s3 = "%snvdisps.dll" fullword ascii
        $s4 = "\\winhlp32.exe" fullword ascii
        $s5 = "nvdisps_user.dat" fullword ascii
        $s6 = "%snvdisps_user.dat" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 
        (
            $x1 or
            ($a1 and 1 of ($s*)) or 
            4 of ($s*)
        )
}
