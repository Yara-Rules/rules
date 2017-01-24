/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule GEN_PowerShell 
{

    meta:
        description = "Generic PowerShell Malware Rule"
        author = "https://github.com/interleaved"
    
    strings:
        $s1 = "powershell"
        $s2 = "-ep bypass" nocase
        $s3 = "-nop" nocase
        $s10 = "-executionpolicy bypass" nocase
        $s4 = "-win hidden" nocase
        $s5 = "-windowstyle hidden" nocase
        $s11 = "-w hidden" nocase
        /*$s6 = "-noni" fullword ascii*/
        /*$s7 = "-noninteractive" fullword ascii*/
        $s8 = "-enc" nocase
        $s9 = "-encodedcommand" nocase
    
    condition:
        $s1 and (($s2 or $s3 or $s10) and ($s4 or $s5 or $s11) and ($s8 or $s9))
}
