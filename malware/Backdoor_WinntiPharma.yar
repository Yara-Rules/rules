rule WinntiPharma
{
meta:
	author = "Jose Ramon Palanco"
	copyright = "Drainware, Inc."
	date = "2015-06-23"
	description = "Backdoor Win64 Winnti Pharma"
	ref = "https://securelist.com/blog/research/70991/games-are-over/"

strings:
	$s0 = "Cookie: SN="
	$s1 = "{3ec05b4a-ea88-1378-3389-66706ba27600}"
	$s2 = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
	$s3 = "master secret"
	$s4 = "MyEngineNetEvent"
condition:
	all of ($s*)
}
