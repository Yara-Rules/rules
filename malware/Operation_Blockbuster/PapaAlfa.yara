rule PapaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "pmsconfig.msi" wide
		$ = "pmslog.msi" wide
		$ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"
		$ = "CreatP2P Thread" wide
		$ = "GreatP2P Thread" wide
	condition:
		3 of them
}