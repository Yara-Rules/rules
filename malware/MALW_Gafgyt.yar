/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Gafgyt_Botnet_generic : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "e3fac853203c3f1692af0101eaad87f1"
SHA1 = "710781e62d49419a3a73624f4a914b2ad1684c6a"

strings:
	$etcTZ = "/bin/busybox;echo -e 'gayfgt'"
	$s2 = "/proc/net/route"
	$s3 = "admin"
	$s4 = "root"

condition:
	$etcTZ and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_oh : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-025"
version = "1.0"
MD5 = "97f5edac312de349495cb4afd119d2a5"
SHA1 = "916a51f2139f11e8be6247418dca6c41591f4557"

    strings:
            $s1 = "busyboxterrorist"
            $s2 = "BOGOMIPS"
            $s3 = "124.105.97.%d"
            $s4 = "fucknet"
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_bash : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-25"
version = "1.0"
MD5 = "c8d58acfe524a09d4df7ffbe4a43c429"
SHA1 = "b41fefa8470f3b3657594af18d2ea4f6ac4d567f"

    strings:
            $s1 = "PONG!"
            $s2 = "GETLOCALIP"
            $s3 = "HTTPFLOOD"
            $s4 = "LUCKYLILDUDE"
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_hoho : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-25"
version = "1.0"
MD5 = "369c7c66224b343f624803d595aa1e09"
SHA1 = "54519d2c124cb536ed0ddad5683440293d90934f"

    strings:
            $s1 = "PING"
            $s2 = "PRIVMSG"
            $s3 = "Remote IRC Bot"
            $s4 = "23.95.43.182"
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_jackmy : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-25"
version = "1.0"
MD5 = "419b8a10a3ac200e7e8a0c141b8abfba"
SHA1 = "5433a5768c5d22dabc4d133c8a1d192d525939d5"

    strings:
            $s1 = "PING"
            $s2 = "PONG"
            $s3 = "jackmy"         
            $s4 = "203.134.%d.%d"       
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_HIHI: MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "cc99e8dd2067fd5702a4716164865c8a"
SHA1 = "b9b316c1cc9f7a1bf8c70400861de08d95716e49"

    strings:
            $s1 = "PING"
            $s2 = "PONG"
            $s3 = "TELNET LOGIN CRACKED - %s:%s:%s"
            $s4 = "ADVANCEDBOT"
            $s5 = "46.166.185.92"
            $s6 = "LOLNOGTFO"

    condition:
            $s1 and $s2 and $s3 and $s4 and $s5 and $s6
}
