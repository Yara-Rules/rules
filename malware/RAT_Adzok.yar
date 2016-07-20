/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Adzok : binary RAT Adzok
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Adzok Rat"
		Versions = "Free 1.0.0.3,"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Adzok"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
    	$a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"
        
	condition:
    7 of ($a*)
}
