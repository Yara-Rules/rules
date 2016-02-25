// yara rules that can cross boundaries between the various sets/types... more general detection signatures
import "pe"

rule wiper_unique_strings
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
	 	company = "novetta"

	 strings:
	 	$a = "C!@I#%VJSIEOTQWPVz034vuA"
		$b = "BAISEO%$2fas9vQsfvx%$"
		$c = "1.2.7.f-hanba-win64-v1"
		$d = "md %s&copy %s\\*.* %s"
		$e = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
		$f = "Ge.tVol. .umeIn..for  mati.onW"
	
	condition:
		$a or $b or $c or $d or $e or $f
}


rule wiper_encoded_strings
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
 		company = "novetta"

	 strings:
	 	$scr = {89 D4 C4 D5 00 00 00}
	 	$explorer = {E2 DF D7 CB C8 D5 C2 D5 89 C2 DF C2 00 00 00 }
	 	$kernel32 = {CC C2 D5 C9 C2 CB 94 95  89 C3 CB CB 00 00 }

	condition:
		$scr or $explorer or $kernel32 
}


rule createP2P
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "CreatP2P Thread" wide

	condition:
		any of them
}

rule firewallOpener
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
	 $ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
	 
	condition:
		any of them
		
}

