/*
Wabot Signature
*/

rule Wabot : Worm
{
	meta:
		author="Kevin Falcoz"
		date="14/08/2015"
		description="Wabot Trojan Worm"

	strings:
		$signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}
		$signature2={73 49 52 43 34}

	condition:
		$signature1 and $signature2
}