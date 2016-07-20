/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule jRAT_conf : RAT 
{
	meta:
		description = "jRAT configuration" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-10-11"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py" 
		ref2 = "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html" 

	strings:
		$a = /port=[0-9]{1,5}SPLIT/ 

	condition: 
		$a
}
