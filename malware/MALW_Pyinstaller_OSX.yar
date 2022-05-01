/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule MachO_File_pyinstaller
{
    meta:
        author = "KatsuragiCSL (https://katsuragicsl.github.io)"
        description = "Detect Mach-O file produced by pyinstaller"
    strings:
        $a = "pyi-runtime-tmpdir"
        $b = "pyi-bootloader-ignore-signals"
    condition:
        any of them
}
