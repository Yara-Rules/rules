import "hash"

rule Hajime_generic_ARCH : MALW
{
meta:
description = "Hajime Botnet - generic arch"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "77122e0e6fcf18df9572d80c4eedd88d"
SHA1 = "108ee460d4c11ea373b7bba92086dd8023c0654f"
ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

strings:
	$userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
	$etcTZ = "/etc/TZ"
	$Mvrs = ",M4.1.0,M10.5.0"
	$bld = "%u.%u.%u.%u.in-addr.arpa"

condition:
	$userpass and $etcTZ and $Mvrs and $bld

}

rule Hajime_MIPS : MALW
{
meta:
description = "Hajime Botnet - MIPS"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "77122e0e6fcf18df9572d80c4eedd88d"
SHA1 = "108ee460d4c11ea373b7bba92086dd8023c0654f"
ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

strings:
	$userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
	$etcTZ = "/etc/TZ"
	$Mvrs = ",M4.1.0,M10.5.0"
	$bld = "%u.%u.%u.%u.in-addr.arpa"

condition:
	$userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0,filesize) == "108ee460d4c11ea373b7bba92086dd8023c0654f"

}

rule Hajime_ARM5 : MALW
{
meta:
description = "Hajime Botnet - ARM5"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "d8821a03b9dc484144285d9051e0b2d3"
SHA1 = "89ec638b95b289dbce0535b4a2c5aad90c169d06"
ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

strings:
	$userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
	$etcTZ = "/etc/TZ"
	$Mvrs = ",M4.1.0,M10.5.0"
	$bld = "%u.%u.%u.%u.in-addr.arpa"

condition:
	$userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0,filesize) == "89ec638b95b289dbce0535b4a2c5aad90c169d06"

}

rule Hajime_SH4 : MALW
{
meta:
description = "Hajime Botnet - SH4"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "6f39d7311091166a285fb0654b454761"
SHA1 = "3ed95ead04e59a2833538541978b79a9a8cb5290"
ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

strings:
	$userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
	$etcTZ = "/etc/TZ"
	$Mvrs = ",M4.1.0,M10.5.0"
	$bld = "%u.%u.%u.%u.in-addr.arpa"

condition:
	$userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0,filesize) == "3ed95ead04e59a2833538541978b79a9a8cb5290"

}

rule Hajime_DOWNLOADER : MALW
{
meta:
description = "Hajime Botnet - Downloader"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "f1cc4275d29b7eaa92a4cca015af227e"
SHA1 = "e649e0d97cc23c8c4bbd78be430a49a4babbccd7"
ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

strings:
	$get = "GET /r/sr.arm5 HTTP/1.0"
	$nif = "NIF\n"


condition:
	$get and $nif and filesize < 700KB and hash.sha1(0,filesize) == "e649e0d97cc23c8c4bbd78be430a49a4babbccd7"

}
