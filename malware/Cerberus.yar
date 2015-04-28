/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Cerberus : rat
{
	meta:
		description = "Cerberus"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 

	strings:
		$checkin = "Ypmw1Syv023QZD"
		$clientpong = "wZ2pla"
		$serverping = "wBmpf3Pb7RJe"
		$generic = "cerberus" nocase

	condition:
		any of them
}
