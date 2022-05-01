/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule BaDoink : official android
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:
		
		//$url_string_1 = "http://police-mobile-stop.com"
		//$url_string_2 = "http://mobile-policeblock.com"
		
		$type_a_1 ="6589y459gj4058rt"
	
		$type_b_1 = "Q,hu4P#hT;U!XO7T,uD"
		$type_b_2 = "+Gkwg#M!lf>Laq&+J{lg"

//		$type_c_1 = "ANIM_STYLE_CLOSE_ENTER"
//		$type_c_2 = "TYPE_VIEW_ACCESSIBILITY_FOCUSED"
//		$type_c_3 = "TYPE_VIEW_TEXT_SELECTION_CHANGED"
//		$type_c_4 = "FLAG_REQUEST_ENHANCED_WEB_ACCESSIBILITY"

	condition:
		androguard.app_name("BaDoink") or
		//all of ($url_string_*) or
		$type_a_1 or
		all of ($type_b*) 
//		all of ($type_c_*)
		
}
