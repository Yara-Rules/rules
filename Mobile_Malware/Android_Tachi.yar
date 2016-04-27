rule tachi : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		source = "https://analyst.koodous.com/rulesets/1332"
		description = "This rule detects tachi apps (not all malware)"
		sample = "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"

	strings:
		$a = "svcdownload"
		$xml_1 = "<config>"
		$xml_2 = "<apptitle>"
		$xml_3 = "<txinicio>"
		$xml_4 = "<txiniciotitulo>"
		$xml_5 = "<txnored>"
		$xml_6 = "<txnoredtitulo>"
		$xml_7 = "<txnoredretry>"
		$xml_8 = "<txnoredsalir>"
		$xml_9 = "<laurl>"
		$xml_10 = "<txquieresalir>"
		$xml_11 = "<txquieresalirtitulo>"
		$xml_12 = "<txquieresalirsi>"
		$xml_13 = "<txquieresalirno>"
		$xml_14 = "<txfiltro>"
		$xml_15 = "<txfiltrourl>"
		$xml_16 = "<posicion>"


	condition:
		$a and 4 of ($xml_*)
}
