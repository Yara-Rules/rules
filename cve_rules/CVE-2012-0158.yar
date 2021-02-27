/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

/*
*
* Signature for the CVE-2012-0158 used in KeyBoy operation
* Ref https://citizenlab.org/2016/11/parliament-keyboy/
*
*/
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"

  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}
