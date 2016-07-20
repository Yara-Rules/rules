
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule PoS_Malware_fastpos : FastPOS POS keylogger
{
meta:
author = "Trend Micro, Inc."
date = "2016-05-18"
description = "Used to detect FastPOS keyloggger + scraper"
reference = "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
sample_filetype = "exe"
strings:
$string1 = "uniqyeidclaxemain"
$string2 = "http://%s/cdosys.php"
$string3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
$string4 = "\\The Hook\\Release\\The Hook.pdb" nocase
condition:
all of ($string*)
}
