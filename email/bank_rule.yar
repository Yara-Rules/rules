rule davivienda : mail {
	strings:
		$nombre = "davivienda" nocase
	condition:
		all of them
}
