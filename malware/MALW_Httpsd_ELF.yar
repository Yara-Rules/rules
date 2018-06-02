/* Yara rule to detect Linux/Httpsd generic
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
    and  open to any user or organization, as long as you use it under this license.
*/

private rule is__LinuxHttpsdStrings {

    meta:
	description = "Strings of ELF Linux/Httpsd (backdoor, downloader, remote command execution)"
	ref1 = "https://imgur.com/a/8mFGk"
	ref2 = "https://otx.alienvault.com/pulse/5a49115f93199b171b90a212"
	ref3 = "https://misppriv.circl.lu/events/view/9952"
	author = "unixfreaxjp"
	org = "MalwareMustDie"
	date = "2018-01-02"
	sha256 = "dd1266561fe7fcd54d1eb17efbbb6babaa9c1f44b36cef6e06052e22ce275ccd"
	sha256 = "1b3718698fae20b63fbe6ab32411a02b0b08625f95014e03301b49afaee9d559"
		
	strings:
		$st01 = "k.conectionapis.com" fullword nocase wide ascii
		$st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" fullword nocase wide ascii
		$st03 = "id=%d&result=%s" fullword nocase wide ascii
		$st04 = "rtime" fullword nocase wide ascii
		$st05 = "down" fullword nocase wide ascii
		$st06 = "cmd" fullword nocase wide ascii
		$st07 = "0 */6 * * * root" fullword nocase wide ascii
		$st08 = "/etc/cron.d/httpsd" fullword nocase wide ascii
		$st09 = "cat /proc/cpuinfo |grep processor|wc -l" fullword nocase wide ascii
		$st10 = "k.conectionapis.com" fullword nocase wide ascii
		$st11 = "/api" fullword nocase wide ascii
		$st12 = "/tmp/.httpslog" fullword nocase wide ascii
		$st13 = "/bin/.httpsd" fullword nocase wide ascii
		$st14 = "/tmp/.httpsd" fullword nocase wide ascii
		$st15 = "/tmp/.httpspid" fullword nocase wide ascii
		$st16 = "/tmp/.httpskey" fullword nocase wide ascii

	condition:
		all of them
}

rule Linux_Httpsd_malware_ARM {
  
	meta:
		description = "Detects Linux/Httpsd ARMv5"
		date = "2017-12-31"

	strings:
		$hexsts01 = { f0 4f 2d e9 1e db 4d e2 ec d0 4d e2 01 40 a0 e1 } // main
		$hexsts02 = { f0 45 2d e9 0b db 4d e2 04 d0 4d e2 3c 01 9f e5 } // self-rclocal
		$hexsts03 = { f0 45 2d e9 01 db 4d e2 04 d0 4d e2 bc 01 9f e5 } // copy-self

	condition:
		all of them
        	and is__elf
		and is__LinuxHttpsdStrings
		and filesize < 200KB 
}

rule Linux_Httpsd_malware_i686 {

	meta:
		description = "Detects ELF Linux/Httpsd i686"
		date = "2018-01-02"

	
	strings:
		$hexsts01 = { 8d 4c 24 04 83 e4 f0 ff 71 fc 55 89 e5 57 56 53 } // main
		$hexsts02 = { 55 89 e5 57 56 53 81 ec 14 2c 00 00 68 7a 83 05 } // self-rclocal
		$hexsts03 = { 55 89 e5 57 56 53 81 ec 10 04 00 00 68 00 04 00 } // copy-self

	condition:
		all of them
        	and is__elf
		and is__LinuxHttpsdStrings
		and filesize < 200KB 
}
