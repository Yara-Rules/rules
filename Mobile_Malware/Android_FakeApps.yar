/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule fake_facebook: fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Facebook")
		and not androguard.certificate.sha1("A0E980408030C669BCEB38FEFEC9527BE6C3DDD0")
}


rule fake_facebook_2 : fake
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Detects fake facebook applications"
		hash_0 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_1 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_2 = "70d5cc909d5718674474a54b44f83bd194cbdd2d99354d52cd868b334fb5f3de"
		hash_3 = "38e757abd5e015e3c3690ea0fdc2ff1e04b716651645a8c4ca6a63185856fe29"
		hash_4 = "ba0b8fe37b4874656ad129dd4d96fdec181e2c3488985309241b0449bb4ab84f"
		hash_5 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_6 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_7 = "7345c3124891b34607a07e93c8ab6dcbbf513e24e936c3710434b085981b815a"
		
	condition:
		androguard.app_name("Facebook") and
		not androguard.package_name(/com.facebook.katana/) and 
		not androguard.certificate.issuer(/O=Facebook Mobile/)	
}

rule fake_instagram: fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("76D72C35164513A4A7EBA098ACCB2B22D2229CBE")
}

rule fake_king_games: fake
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

rule fake_market: fake
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"

	condition:
		androguard.package_name("com.minitorrent.kimill") 
}


rule fake_minecraft: fake
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or 
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}

rule fake_whatsapp: fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}