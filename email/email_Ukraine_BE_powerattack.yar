/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule content {
	meta:
		author = "@yararules"
		description = "Detects a possible .eml used in the Ukraine BE power attack"
		ref1 = "https://twitter.com/lowcalspam/status/692625258394726400"
		
	strings:
		$subject = "Subject: Указ Президента України № 15/2015 "Про часткову мобілізацію" від 14.01.15 р." nocase
		$body_string1 = "організацій необхідно надати списки співробітників організацій за зразком"
		$body_string2 = "підлягають мобілізації представлені у додатку 2. Указ Президента України та"
		$body_string3 = "порядок надання інформації представлені у додатку"
		$body_string4 = "http://176.53.127.194/bWFpbF9rYW5jQG9lLmlmLnVh.png"
	condition:
		3 of them
}
rule attachment {
	meta:
		author = " @yararules"
		description = "Detects a possible .eml used in the Ukraine BE power attack"
		ref1 = "https://twitter.com/lowcalspam/status/692625258394726400"

	strings:
		$filename = "filename=\"Додаток1.xls\""
				
	condition:
		all of them
}
