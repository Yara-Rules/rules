rule TrumpBot : MALW
{
	meta:
		description = "TrumpBot"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "77122e0e6fcf18df9572d80c4eedd88d"
		SHA1 = "108ee460d4c11ea373b7bba92086dd8023c0654f"

	strings:
		$string = "trumpisdaddy"
		$ip = "198.50.154.188"
	condition:
		 all of them
}
