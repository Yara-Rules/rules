/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

rule davivienda : mail {
	strings:
		$nombre = "davivienda" nocase
	condition:
		all of them
}
