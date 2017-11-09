rule LinuxBew: MALW
{
	meta:
		description = "Linux.Bew Backdoor"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-07-10"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06"
	strings:
		$a = "src/secp256k1.c"
		$b = "hfir.u230.org"
		$c = "tempfile-x11session"
	condition:
		all of them
}
