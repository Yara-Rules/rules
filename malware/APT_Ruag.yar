/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Yara Rule Set
  Author: Florian Roth
  Date: 2016-05-23
  Identifier: Swiss RUAG APT Case
  Reference: https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case 
*/

rule RUAG_Tavdig_Malformed_Executable {
  meta:
    description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
    author = "Florian Roth"
    reference = "https://goo.gl/N5MEj0"
    score = 60
  condition:
    uint16(0) == 0x5a4d and /* MZ Header */
    uint32(uint32(0x3C)) == 0x0000AD0B /* malformed PE header > 0x0bad */
}

rule RUAG_Bot_Config_File {
  meta:
    description = "Detects a specific config file used by malware in RUAG APT case"
    author = "Florian Roth"
    reference = "https://goo.gl/N5MEj0"
    score = 60
  strings:
    $s1 = "[CONFIG]" ascii
    $s2 = "name = " ascii
    $s3 = "exe = cmd.exe" ascii
  condition:
    $s1 at 0 and $s2 and $s3 and filesize < 160 
}

rule RUAG_Cobra_Malware {
  meta:
    description = "Detects a malware mentioned in the RUAG Case called Carbon/Cobra"
    author = "Florian Roth"
    reference = "https://goo.gl/N5MEj0"
    score = 60
  strings:
    $s1 = "\\Cobra\\Release\\Cobra.pdb" ascii
  condition:
    uint16(0) == 0x5a4d and $s1
}

rule RUAG_Cobra_Config_File {
  meta:
    description = "Detects a config text file used by malware Cobra in RUAG case"
    author = "Florian Roth"
    reference = "https://goo.gl/N5MEj0"
    score = 60
  strings:
    $h1 = "[NAME]" ascii

    $s1 = "object_id=" ascii
    $s2 = "[TIME]" ascii fullword
    $s3 = "lastconnect" ascii 
    $s4 = "[CW_LOCAL]" ascii fullword
    $s5 = "system_pipe" ascii
    $s6 = "user_pipe" ascii
    $s7 = "[TRANSPORT]" ascii
    $s8 = "run_task_system" ascii
    $s9 = "[WORKDATA]" ascii 
    $s10 = "address1" ascii
  condition:
    $h1 at 0 and 8 of ($s*) and filesize < 5KB
}

rule RUAG_Exfil_Config_File {
  meta:
    description = "Detects a config text file used in data exfiltration in RUAG case"
    author = "Florian Roth"
    reference = "https://goo.gl/N5MEj0"
    score = 60
  strings:
    $h1 = "[TRANSPORT]" ascii

    $s1 = "system_pipe" ascii
    $s2 = "spstatus" ascii
    $s3 = "adaptable" ascii 
    $s4 = "post_frag" ascii
    $s5 = "pfsgrowperiod" ascii
  condition:
    $h1 at 0 and all of ($s*) and filesize < 1KB
}
