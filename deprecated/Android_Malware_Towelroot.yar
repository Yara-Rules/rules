/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule towelhacking_behaviour
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Search probably apks relationships"


	condition:
		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or 
		( androguard.activity(/net.prospectus.*/i) and androguard.permission(/android.permission.WRITE_CONTACT/) and
		androguard.permission(/android.permission.ACCESS_COARSE_UPDATES/))
		
}

rule towelhacking_analysis
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "From static analysis"
		sample = "258c34428e214d2a49d3de776db98d26e0bd0abc452249c8be8cdbcb10218e8c"

	strings:
		$analysis_a = "LoganberryApplication"
		$analysis_b = "attachBaseContext"
		$analysis_c = "Obstetric"

	condition:
		all of them
		
}

rule towelhacking_cromosome
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "From cromosome.py"

	strings:
		$cromosome_a = "res/xml/device_admin_data.xml]"
	  	$cromosome_b = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACABAMAAAAxEHz4AAAAGFBMVEVMaXGUwUWTwEaTwEaTwEaTwEaVwUWTwEalNfqIAAAAB3RSTlMALozOuetYmPN8xgAAAbFJREFUeF7t2E9L+zAcx/FP1i3n7PfHXauivW7K3HWAY1dFoNci2l61Lvs8fUOxZYW22RdBBub1AN4kX7KQDqcvCILgDC0aUlcGhzaQ+j/HAb2HlC5buTXEEoMGlgZikzkAledTAKM95HSJPxs6T9eYrSGHZMMvuyXkoLZs2AxyCQ98GEi9sqWEkGYb1/INMGUtFW9iRDLWdWGhtuQCEgW5a+ZIgwn5AQFVjQ0zViwQkYwFgYjVCorDFfBdtgMyU80MkFC2h5SOXfGLXbIqyg9B2xzHGrODZAgzdioFM+y0E5zjThbHurzthl9Bb24M8HLfzQCXT+cYsiX3QMJuBn9Jazz3CLOBwIrko+8IzvsDmk7pO4Lv/YExPT/rxBOI6NjTCIRACIRACITA2BeY0XnoD4x8D5WITtwfUKnnraVScof+AArfk/cfbTwU0CveYdDUYCgANYXPYKBx+oEQKL772I7YaS/+cG+zMY6m8vyFDnOnqpV5nkFkVI+tvmWAXxkIgRDQdGxzO7xBSqX1B9qEzhpiBcmHei3WQEyn9d9fr+QCcji7yFDB8zV+QhAEQfAJcs5K2TAQqxAAAAAASUVORK5CYII="

		$cromosome_c = "device_admin_desc"
		$cromosome_d = "PillagedActivity"
		$cromosome_e = "EpigraphyService"

	condition:
		($cromosome_a and $cromosome_b) or ($cromosome_c and $cromosome_d and $cromosome_e)
		
}
