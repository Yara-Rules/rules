/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule andr_tordow
{
	meta:
		description = "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
		author = "https://twitter.com/5h1vang"

	condition:
		androguard.package_name("com.di2.two") or		
		(androguard.activity(/API2Service/i) and
		androguard.activity(/CryptoUtil/i) and
		androguard.activity(/Loader/i) and
		androguard.activity(/Logger/i) and 
		androguard.permission(/android.permission.INTERNET/)) or
		
		//Certificate check based on @stevenchan's comment
		androguard.certificate.sha1("78F162D2CC7366754649A806CF17080682FE538C") or
		androguard.certificate.sha1("BBA26351CE41ACBE5FA84C9CF331D768CEDD768F") or
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}
