/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule fraudulents_2 : certificates android
{
	meta:
		description = "This rule automatically adds certificates present in malware"
		author = "https://twitter.com/fdrg21"

	condition:
		androguard.certificate.sha1("A5D9C9A40A3786D631210E8FCB9CF7A1BC5B3062") or
		androguard.certificate.sha1("B4142B617997345809736842147F97F46059FDE3") or
		androguard.certificate.sha1("950A545EA156A0E44B3BAB5F432DCD35005A9B70") or
		androguard.certificate.sha1("DE18FA0C68E6C9E167262F1F4ED984A5F00FD78C") or
		androguard.certificate.sha1("81E8E202C539F7AEDF6138804BE870338F81B356") or
		androguard.certificate.sha1("5A051047F2434DDB2CAA65898D9B19ED9665F759")
		
}
