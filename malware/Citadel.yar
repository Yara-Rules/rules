/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule citadel13xy : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Citadel 1.5.x.y trojan banker"
		date = "2013-01-12" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$a = "Coded by BRIAN KREBS for personnal use only. I love my job & wife."
		$b = "http://%02x%02x%02x%02x%02x%02x%02x%02x.com/%02x%02x%02x%02x/%02x%02x%02x%02x%02x.php"
		$c = "%BOTID%"
		$d = "%BOTNET%"
		$e = "cit_video.module"
		$f = "bc_remove"
		$g = "bc_add"
		$ggurl = "http://www.google.com/webhp"

	condition:
		3 of them
}
