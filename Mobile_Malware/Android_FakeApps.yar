/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule whatsapp:fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}

rule king_games:fake
{
	condition:
		(androguard.app_name("AlphaBetty Saga")
		or androguard.app_name("Candy Crush Soda Saga")
		or androguard.app_name("Candy Crush Saga")
		or androguard.app_name("Farm Heroes Saga")
		or androguard.app_name("Pet Rescue Saga")
		or androguard.app_name("Bubble Witch 2 Saga")
		or androguard.app_name("Scrubby Dubby Saga")
		or androguard.app_name("Diamond Digger Saga")
		or androguard.app_name("Papa Pear Saga")
		or androguard.app_name("Pyramid Solitaire Saga")
		or androguard.app_name("Bubble Witch Saga")
		or androguard.app_name("King Challenge"))
		and not androguard.certificate.sha1("9E93B3336C767C3ABA6FCC4DEADA9F179EE4A05B")
}

rule facebook:fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Facebook")
		and not androguard.certificate.sha1("A0E980408030C669BCEB38FEFEC9527BE6C3DDD0")
}

rule instagram:fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("76D72C35164513A4A7EBA098ACCB2B22D2229CBE")
}
