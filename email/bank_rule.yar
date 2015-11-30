rule davivienda {
	strings:
		$nombre = "davivienda" nocase
	condition:
		all of them
}
