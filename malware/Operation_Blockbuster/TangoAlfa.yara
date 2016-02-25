rule TangoAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		// $firewall is a shared code string
		$firewall = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
		
		$testStatus1 = "*****[Start Test -> %s:%d]" wide
		$testStatus2 = "*****[Relay Connect " wide
		$testStatus3 = "*****[Listen Port %d] - " wide
		$testStatus4 = "*****[Error Socket]" wide
		$testStatus5 = "*****[End Test]" wide

	condition:
		2 of them
}
