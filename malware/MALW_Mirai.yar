
import "hash"
import "pe"


rule Mirai_Generic_Arch : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - Generic Architecture" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet
}

rule Mirai_MIPS_LSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS LSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5 = "bf650d39eb603d92973052ca80a4fdda"
		SHA1 = "03ecd3b49aa19589599c64e4e7a51206a592b4ef"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and
		hash.sha1(0,filesize) == "03ecd3b49aa19589599c64e4e7a51206a592b4ef"
}
rule Mirai_MIPS_MSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS MSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5 = "0eb51d584712485300ad8e8126773941"	
		SHA1 = "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and 
		hash.sha1(0,filesize) == "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
}

rule Mirai_ARM_LSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - ARM LSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5= "eba670256b816e2d11f107f629d08494"
		SHA1 = "8a25dee4ea7d61692b2b95bd047269543aaf0c81"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and 
		hash.sha1(0,filesize) == "8a25dee4ea7d61692b2b95bd047269543aaf0c81"
}

rule Mirai_Renesas_SH : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - Renesas SH LSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5 = "863dcf82883c885b0686dce747dcf502"
		SHA1 = "bdc86295fad70480f0c6edcc37981e3cf11d838c"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and 
		hash.sha1(0,filesize) == "bdc86295fad70480f0c6edcc37981e3cf11d838c"
}
rule Mirai_PPC_Cisco : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - PowerPC or Cisco 4500" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5= "dbd92b08cbff8455ff76c453ff704dc6"
		SHA1 = "6933d555a008a07b859a55cddb704441915adf68"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		( $miname and $iptables1 and $iptables2 and $procnet ) and 
		hash.sha1(0,filesize) == "6933d555a008a07b859a55cddb704441915adf68"
}

rule Mirai_SPARC_MSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - SPARC MSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5= "05891dbabc42a36f33c30535f0931555"
		SHA1 = "3d770480b6410cba39e19b3a2ff3bec774cabe47"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		( $miname and $iptables1 and $iptables2 and $procnet ) and 
		hash.sha1(0,filesize) == "3d770480b6410cba39e19b3a2ff3bec774cabe47"
}


rule Mirai_1 : MALW
{
	meta:
		description = "Mirai Variant 1"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "655c3cf460489a7d032c37cd5b84a3a8"
		SHA1 = "4dd3803956bc31c8c7c504734bddec47a1b57d58"

	strings:
		$dir1 = "/dev/watchdog"
		$dir2 = "/dev/misc/watchdog"
		$pass1 = "PMMV"
		$pass2 = "FGDCWNV"
		$pass3 = "OMVJGP"
	condition:
		$dir1 and $pass1 and $pass2 and not $pass3 and not $dir2

}
rule Mirai_2 : MALW
{
meta:
	description = "Mirai Variant 2"
	author = "Joan Soriano / @joanbtl"
	date = "2017-04-16"
	version = "1.0"
	MD5 = "0e5bda9d39b03ce79ab8d421b90c0067"
	SHA1 = "96f42a9fad2923281d21eca7ecdd3161d2b61655"

    strings:
	$dir1 = "/dev/watchdog"
	$dir2 = "/dev/misc/watchdog"
        $s1 = "PMMV"
        $s2 = "ZOJFKRA"
        $s3 = "FGDCWNV"
        $s4 = "OMVJGP"
    condition:
        $dir1 and $dir2 and $s1 and $s2 and $s3 and not $s4 

}

rule Mirai_3 : MALW
{
    meta:
	description = "Mirai Variant 3"
	author = "Joan Soriano / @joanbtl"
	date = "2017-04-16"
	version = "1.0"
	MD5 = "bb22b1c921ad8fa358d985ff1e51a5b8"
	SHA1 = "432ef83c7692e304c621924bc961d95c4aea0c00"

    strings:
            $dir1 = "/dev/watchdog"
            $dir2 = "/dev/misc/watchdog"
            $s1 = "PMMV"
            $s2 = "ZOJFKRA"
            $s3 = "FGDCWNV"
            $s4 = "OMVJGP"
	    $ssl = "ssl3_ctrl"
    condition:
            $dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and not $ssl

}

rule Mirai_4 : MALW
{
	meta:
		description = "Mirai Variant 4"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "f832ef7a4fcd252463adddfa14db43fb"
		SHA1 = "4455d237aadaf28aafce57097144beac92e55110"
	strings:
		$s1 = "210765"
		$s2 = "qllw"
		$s3 = ";;;;;;"
	condition:
		$s1 and $s2 and $s3
}

rule Mirai_Dwnl : MALW
{
	meta:
		description = "Mirai Downloader"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "85784b54dee0b7c16c57e3a3a01db7e6"
		SHA1 = "6f6c625ef730beefbc23c7f362af329426607dee"
	strings:
		$s1 = "GET /mirai/"
		$s2 = "dvrHelper"
	condition:
		$s1 and $s2
}

rule Mirai_5 : MALW
{
	meta:
		description = "Mirai Variant 5"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "7e17c34cddcaeb6755c457b99a8dfe32"
		SHA1 = "b63271672d6a044704836d542d92b98e2316ad24"

	strings:
		    $dir1 = "/dev/watchdog"
		    $dir2 = "/dev/misc/watchdog"
		    $s1 = "PMMV"
		    $s2 = "ZOJFKRA"
		    $s3 = "FGDCWNV"
		    $s4 = "OMVJGP"
		    $ssl = "ssl3_ctrl"
	condition:
		    $dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and $ssl

}
