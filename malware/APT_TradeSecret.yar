
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule apt_all_JavaScript_ScanboxFramework_obfuscated

{
              meta:
                    
                    ref = "https://www.fidelissecurity.com/TradeSecret"

                  strings:

              $sa1 = /(var|new|return)\s[_\$]+\s?/

                  $sa2 = "function"

                  $sa3 = "toString"

                  $sa4 = "toUpperCase"

                  $sa5 = "arguments.length"

                  $sa6 = "return"

                  $sa7 = "while"

                  $sa8 = "unescape("

                  $sa9 = "365*10*24*60*60*1000"

                  $sa10 = ">> 2"

                  $sa11 = "& 3) << 4"

                  $sa12 = "& 15) << 2"

                  $sa13 = ">> 6) | 192"

                  $sa14 = "& 63) | 128"

                  $sa15 = ">> 12) | 224"

                  condition:

                  all of them

}
