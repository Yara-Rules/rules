/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ppaction {

meta:
	ref = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
	Description = "Malicious PowerPoint Documents Abusing Mouse Over Actions"
  hash = "68fa24c0e00ff5bc1e90c96e1643d620d0c4cda80d9e3ebeb5455d734dc29e7"

strings:
$a = "ppaction" nocase
condition:
$a
}

rule powershell {
strings:
$a = "powershell" nocase
condition:
$a
}
