

rule hancitor {
	meta:
		description = "Memory string yara for Hancitor"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/"
		reference2 = "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/"
		reference3 = "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/"
		date = "2018-09-18"
		maltype1 = "Botnet"
		filetype = "memory"

	strings:
		$a = "GUID="	ascii
                $b = "&BUILD="	ascii
                $c = "&INFO="	ascii
                $d = "&IP="	ascii
                $e = "&TYPE=" 	ascii
                $f = "php|http"	ascii
		$g = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d" ascii fullword


	condition:
		5 of ($a,$b,$c,$d,$e,$f) or $g

}
