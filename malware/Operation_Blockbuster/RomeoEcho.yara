import "pe"

rule RomeoEcho
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "%s %-20s %10lu %s"
		$ = "_quit"
		$ = "_exe"
		$ = "_put"
		$ = "_get"

	condition:
		all of them
}