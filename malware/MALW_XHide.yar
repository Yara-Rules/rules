rule XHide: MALW
{
	meta:
		description = "XHide - Process Faker"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-12-01"
		version = "1.0"
		MD5 = "c644c04bce21dacdeb1e6c14c081e359"
		SHA256 = "59f5b21ef8a570c02453b5edb0e750a42a1382f6"
	strings:
		$a = "XHide - Process Faker"
		$b = "Fakename: %s PidNum: %d"
	condition:
		all of them
}
