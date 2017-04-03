/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule apt_RU_MoonlightMaze_customlokitools {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	last_modified = "2017-03-22"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
	hash = "14cce7e641d308c3a177a8abb5457019"
	hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
	hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
	hash = "1980958afffb6a9d5a6c73fc1e2795c2"
	hash = "e59f92aadb6505f29a9f368ab803082e"

strings:

	$a1="Write file Ok..." ascii wide 
	$a2="ERROR: Can not open socket...." ascii wide
	$a3="Error in parametrs:"  ascii wide
	$a4="Usage: @<get/put> <IP> <PORT> <file>"  ascii wide
	$a5="ERROR: Not connect..."  ascii wide
	$a6="Connect successful...."  ascii wide
	$a7="clnt <%d> rqstd n ll kll"  ascii wide
	$a8="clnt <%d> rqstd swap"  ascii wide
	$a9="cld nt sgnl prcs grp" ascii wide
	$a10="cld nt sgnl prnt" ascii wide

	//keeping only ascii version of string ->
	$a11="ork error" ascii fullword

condition:

	((any of ($a*)))

}


rule apt_RU_MoonlightMaze_customsniffer {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze sniffer tools"
	hash = "7b86f40e861705d59f5206c482e1f2a5"
	hash = "927426b558888ad680829bd34b0ad0e7"
	original_filename = "ora;tdn"
	
strings:


	//strings from ora ->
	$a1="/var/tmp/gogo" fullword
	$a2="myfilename= |%s|" fullword
	$a3="mypid,mygid=" fullword
	$a4="mypid=|%d| mygid=|%d|" fullword

	//strings from tdn ->
	$a5="/var/tmp/task" fullword
	$a6="mydevname= |%s|" fullword

condition:

	((any of ($a*)))

}


rule loki2crypto {

meta:
	
	author = "Costin Raiu, Kaspersky Lab"
	date = "2017-03-21"
	version = "1.0"
	description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	hash = "19fbd8cbfb12482e8020a887d6427315"
	hash = "ea06b213d5924de65407e8931b1e4326"
	hash = "14ecd5e6fc8e501037b54ca263896a11"
	hash = "e079ec947d3d4dacb21e993b760a65dc"
	hash = "edf900cebb70c6d1fcab0234062bfc28"

strings:

	$modulus={DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

condition:

	(any of them)

}




rule apt_RU_MoonlightMaze_de_tool {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
	hash = "4bc7ed168fb78f0dc688ee2be20c9703"
	hash = "8b56e8552a74133da4bc5939b5f74243"

strings:

	$a1="Vnuk: %d" ascii fullword
	$a2="Syn: %d" ascii fullword

	//%s\r%s\r%s\r%s\r ->
	$a3={25 73 0A 25 73 0A 25 73 0A 25 73 0A}

condition:

	((2 of ($a*)))

}


rule apt_RU_MoonlightMaze_cle_tool {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
	hash = "647d7b711f7b4434145ea30d0ef207b0"

	
strings:

	$a1="./a filename template_file" ascii wide
	$a2="May be %s is empty?"  ascii wide
	$a3="template string = |%s|"   ascii wide
	$a4="No blocks !!!"
	$a5="No data in this block !!!!!!"  ascii wide
	$a6="No good line"

condition:

	((3 of ($a*)))

}


rule apt_RU_MoonlightMaze_xk_keylogger {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'xk' keylogger"

strings:

	$a1="Log ended at => %s"
	$a2="Log started at => %s [pid %d]"
	$a3="/var/tmp/task" fullword
	$a4="/var/tmp/taskhost" fullword
	$a5="my hostname: %s"
	$a6="/var/tmp/tasklog"
	$a7="/var/tmp/.Xtmp01" fullword
	$a8="myfilename=-%s-"
	$a9="/var/tmp/taskpid"
	$a10="mypid=-%d-" fullword
	$a11="/var/tmp/taskgid" fullword
	$a12="mygid=-%d-" fullword


condition:

	((3 of ($a*)))

}

rule apt_RU_MoonlightMaze_encrypted_keylog {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze encrypted keylogger logs"

strings:

	$a1={47 01 22 2A 6D 3E 39 2C}

condition:

	($a1 at 0)

}

rule apt_RU_MoonlightMaze_IRIX_exploit_GEN {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Irix exploits from David Hedley used by Moonlight Maze hackers"
	reference2 = "https://www.exploit-db.com/exploits/19274/"
	hash = "008ea82f31f585622353bd47fa1d84be" //df3
	hash = "a26bad2b79075f454c83203fa00ed50c" //log
	hash = "f67fc6e90f05ba13f207c7fdaa8c2cab" //xconsole
	hash = "5937db3896cdd8b0beb3df44e509e136" //xlock
	hash = "f4ed5170dcea7e5ba62537d84392b280" //xterm

strings:

	$a1="stack = 0x%x, targ_addr = 0x%x"
	$a2="execl failed"

condition:

	(uint32(0)==0x464c457f) and (all of them)

}


rule apt_RU_MoonlightMaze_u_logcleaner {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect log cleaners based on utclean.c"
	reference2 = "http://cd.textfiles.com/cuteskunk/Unix-Hacking-Exploits/utclean.c"
	hash = "d98796dcda1443a37b124dbdc041fe3b"
	hash = "73a518f0a73ab77033121d4191172820"

strings:

	$a1="Hiding complit...n"
	$a2="usage: %s <username> <fixthings> [hostname]"
	$a3="ls -la %s* ; /bin/cp  ./wtmp.tmp %s; rm  ./wtmp.tmp"

condition:

	(uint32(0)==0x464c457f) and (any of them)

}


rule apt_RU_MoonlightMaze_wipe {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect log cleaner based on wipe.c"
	reference2 = "http://www.afn.org/~afn28925/wipe.c"
	hash = "e69efc504934551c6a77b525d5343241"

strings:

	$a1="ERROR: Unlinking tmp WTMP file."
	$a2="USAGE: wipe [ u|w|l|a ] ...options..."
	$a3="Erase acct entries on tty :   wipe a [username] [tty]"
	$a4="Alter lastlog entry       :   wipe l [username] [tty] [time] [host]"

condition:

	(uint32(0)==0x464c457f) and (2 of them)

}

