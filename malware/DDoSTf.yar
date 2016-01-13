/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule DDosTf : DDoS
{
  meta:
    author = "benkow_ - MalwareMustDie"
    reference = "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html"
    description = "Rule to detect ELF.DDosTf infection"
  strings:
    $st0 = "ddos.tf"
    $st1 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 49 4E 54 56 4C E9 94 99 E8 AF AF EF BC 9A 00} /*TCP_KEEPINTVL*/
    $st2 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 43 4E 54 E9 94 99 E8 AF AF EF BC 9A 00} /*TCP_KEEPCNT*/
    $st3 = "Accept-Language: zh"
    $st4 = "%d Kb/bps|%d%%"
   
  condition:
    all of them
}
