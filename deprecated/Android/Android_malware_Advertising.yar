/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule leadbolt : advertising android
{
	meta:
	  author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Leadbolt"
		
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}
