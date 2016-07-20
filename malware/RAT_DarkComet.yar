/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule DarkComet_1 : RAT
{
    meta:
        description = "DarkComet RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $bot1 = /(#)BOT#OpenUrl/ wide ascii
        $bot2 = /(#)BOT#Ping/ wide ascii
        $bot3 = /(#)BOT#RunPrompt/ wide ascii
        $bot4 = /(#)BOT#SvrUninstall/ wide ascii
        $bot5 = /(#)BOT#URLDownload/ wide ascii
        $bot6 = /(#)BOT#URLUpdate/ wide ascii
        $bot7 = /(#)BOT#VisitUrl/ wide ascii
        $bot8 = /(#)BOT#CloseServer/ wide ascii

        $ddos1 = /(D)DOSHTTPFLOOD/ wide ascii
        $ddos2 = /(D)DOSSYNFLOOD/ wide ascii
        $ddos3 = /(D)DOSUDPFLOOD/ wide ascii

        $keylogger1 = /(A)ctiveOnlineKeylogger/ wide ascii
        $keylogger2 = /(U)nActiveOnlineKeylogger/ wide ascii
        $keylogger3 = /(A)ctiveOfflineKeylogger/ wide ascii
        $keylogger4 = /(U)nActiveOfflineKeylogger/ wide ascii

        $shell1 = /(A)CTIVEREMOTESHELL/ wide ascii
        $shell2 = /(S)UBMREMOTESHELL/ wide ascii
        $shell3 = /(K)ILLREMOTESHELL/ wide ascii

    condition:
        4 of ($bot*) or all of ($ddos*) or all of ($keylogger*) or all of ($shell*)
}

rule DarkComet_2 : rat
{
	meta:
		description = "DarkComet" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 

	strings:
		$a = "#BEGIN DARKCOMET DATA --"
		$b = "#EOF DARKCOMET DATA --"
		$c = "DC_MUTEX-"
		$k1 = "#KCMDDC5#-890"
		$k2 = "#KCMDDC51#-890"

	condition:
		any of them
}
rule DarkComet_3 : RAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		// Versions 2x
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		// Versions 3x & 4x & 5x
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"
	condition:
		all of ($a*) or all of ($b*)
}

rule DarkComet_Keylogger_File  : RAT
{
	meta:
		author = "Florian Roth"
		description = "Looks like a keylogger file created by DarkComet Malware"
		date = "25.07.14"
		reference = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		score = 50
	strings:
		$magic = "::"
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
	condition:
		($magic at 0) and #entry > 10 and #timestamp > 10
}
rule DarkComet_4  : RAT
{	meta:
		reference = "https://github.com/bwall/bamfdetect/blob/master/BAMF_Detect/modules/yara/darkcomet.yara"
	strings:
	    $a1 = "#BOT#"
	    $a2 = "WEBCAMSTOP"
	    $a3 = "UnActiveOnlineKeyStrokes"
	    $a4 = "#SendTaskMgr"
	    $a5 = "#RemoteScreenSize"
	    $a6 = "ping 127.0.0.1 -n 4 > NUL &&"
	condition:
		all of them
}
