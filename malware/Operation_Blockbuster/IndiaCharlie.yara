rule IndiaCharlie_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "WMPNetworkSvcUpdate"
		$ = "backSched.dll"
		$ = "\\mspaint.exe"
		$aesKey = "X,LLIe{))%%l2i<[AM|aq!Ql/lPlw]d7@C-#j.<c|#*}Kx4_H(q^F-F^p/[t#%HT"
	condition:
		2 of them or $aesKey
}

rule IndiaCharlie_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$s1 = "%s is an essential element in Windows System configuration and management. %s"
		$s2 = "%SYSTEMROOT%\\system32\\svchost.exe -k "
		$s3 = "%s\\system32\\%s"
		$s4 = "\\mspaint.exe"
		$s5 = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		$aesKey = "}[eLkQAeEae0t@h18g!)3x-RvE%+^`n.6^()?+00ME6a&F7vcV}`@.dj]&u$o*vX"

	condition:
		3 of ($s*) or $aesKey
}