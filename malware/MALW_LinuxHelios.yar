rule LinuxHelios: MALW
{
	meta:
		description = "Linux.Helios"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-10-19"
		version = "1.0"
		MD5 = "1a35193f3761662a9a1bd38b66327f49"
		SHA256 = "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719"
	strings:
		$a = "LIKE A GOD!!! IP:%s User:%s Pass:%s"
		$b = "smack"
		$c = "PEACE OUT IMMA DUP\n"
	condition:
		all of them
}
