/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule ws_f0xy_downloader {
  meta:
    description = "f0xy malware downloader"
    author = "Nick Griffin (Websense)"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="
  
  condition:
    ($mz at 0) and (all of ($string*))
}
