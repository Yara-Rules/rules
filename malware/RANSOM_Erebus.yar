rule Erebus: ransom
{
	meta:
		description = "Erebus Ransomware"
		author = "Joan Soriano / @joanbtl"
		date = "2017-06-23"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f"
		ref1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/"
	strings:
		$a = "/{5f58d6f0-bb9c-46e2-a4da-8ebc746f24a5}//log.log"
		$b = "EREBUS IS BEST."
	condition:
		all of them
}
