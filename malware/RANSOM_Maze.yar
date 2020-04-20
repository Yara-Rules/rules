rule Maze
{
meta:
	description = "Identifies Maze ransomware in memory or unpacked."
	author = "@bartblaze"
	date = "2019-11"
	tlp = "White"

strings:	
	$ = "Enc: %s" ascii wide
	$ = "Encrypting whole system" ascii wide
	$ = "Encrypting specified folder in --path parameter..." ascii wide
	$ = "!Finished in %d ms!" ascii wide
	$ = "--logging" ascii wide
	$ = "--nomutex" ascii wide
	$ = "--noshares" ascii wide
	$ = "--path" ascii wide
	$ = "Logging enabled | Maze" ascii wide
	$ = "NO SHARES | " ascii wide
	$ = "NO MUTEX | " ascii wide
	$ = "Encrypting:" ascii wide
	$ = "You need to buy decryptor in order to restore the files." ascii wide
	$ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
	$ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
	$ = "DECRYPT-FILES.txt" ascii wide fullword

condition:
	5 of them
}
