// yara sigs for detecting common suicide scripts

rule SuicideScriptL1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = ":L1\ndel \"%s\"\nif exist \"%s\" goto L1\ndel \"%s\"\n"
	condition:
		any of them
}

rule SuicideScriptR1_Multi
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
	
	strings:
		$ = "\" goto R1\ndel /a \""
		$ = "\"\nif exist \""
		$ = "@echo off\n:R1\ndel /a \""
	condition:
		all of them
}

rule SuicideScriptR
{
	// joanap, joanapCleaner
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		
	condition:
		all of them

}