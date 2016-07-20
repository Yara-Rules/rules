/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Version 0.0.1 2016/03/21
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo's ;-) :

  History:
    2016/03/21: start
*/

rule Contains_VBE_File : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}
