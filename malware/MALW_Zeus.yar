/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Windows_Malware : Zeus_1134
    {
            meta:
                    author = "Xylitol xylitol@malwareint.com"
                    date = "2014-03-03"
                    description = "Match first two bytes, protocol and string present in Zeus 1.1.3.4"
                    reference = "http://www.xylibox.com/2014/03/zeus-1134.html"
                    
            strings:
                    $mz = {4D 5A}
                    $protocol1 = "X_ID: "
                    $protocol2 = "X_OS: "
                    $protocol3 = "X_BV: "
                    $stringR1 = "InitializeSecurityDescriptor"
                    $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
            condition:
                    ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))
    }
