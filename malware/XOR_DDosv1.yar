/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule XOR_DDosv1 : DDoS
{
  meta:
    author = "Akamai CSIRT"
    description = "Rule to detect XOR DDos infection"
  strings:
    $st0 = "BB2FA36AAA9541F0"
    $st1 = "md5="
    $st2 = "denyip="
    $st3 = "filename="
    $st4 = "rmfile="
    $st5 = "exec_packet"
    $st6 = "build_iphdr"
  condition:
    all of them
}
