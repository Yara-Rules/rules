rule sitrof_fortis_scar {

    meta:
        author = "J from THL <j@techhelplist.com>"
        date = "2018/23"
        reference1 = "https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community"
	reference2 = "ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST"
	version = 2
        maltype = "Stealer"
        filetype = "memory"

    strings:
	
	$a = "?get&version"
	$b = "?reg&ver="
	$c = "?get&exe"
	$d = "?get&download"
	$e = "?get&module"
	$f = "&ver="
	$g = "&comp="
	$h = "&addinfo="
	$i = "%s@%s; %s %s \"%s\" processor(s)"
	$j = "User-Agent: fortis"

    condition:
        6 of them
}
