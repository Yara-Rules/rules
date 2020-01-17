/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule LinuxAESDDoS
{
    meta:
	Author = "@benkow_"
	Date = "2014/09/12"
	Description = "Strings inside"
        Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "3AES"
        $b = "Hacker"
        $c = "VERSONEX"

    condition:
        2 of them
}

rule LinuxBillGates 
{
    meta:
       Author      = "@benkow_"
       Date        = "2014/08/11" 
       Description = "Strings inside"
       Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3429" 

    strings:
        $a= "12CUpdateGates"
        $b= "11CUpdateBill"

    condition:
        $a and $b
}

rule LinuxElknot
{
    meta:
	Author      = "@benkow_"
        Date        = "2013/12/24" 
        Description = "Strings inside"
        Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3099"

    strings:
        $a = "ZN8CUtility7DeCryptEPciPKci"
	$b = "ZN13CThreadAttack5StartEP11CCmdMessage"

    condition:
	all of them
}

rule LinuxMrBlack
{
    meta:
	Author      = "@benkow_"
        Date        = "2014/09/12" 
        Description = "Strings inside"
        Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "Mr.Black"
	$b = "VERS0NEX:%s|%d|%d|%s"
    condition:
        $a and $b
}

rule LinuxTsunami
{
    meta:
	
		Author      = "@benkow_"
		Date        = "2014/09/12" 
		Description = "Strings inside"
		Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "PRIVMSG %s :[STD]Hitting %s"
        $b = "NOTICE %s :TSUNAMI <target> <secs>"
        $c = "NOTICE %s :I'm having a problem resolving my host, someone will have to SPOOFS me manually."
    condition:
        $a or $b or $c
}

rule rootkit
{
	meta:
                author="xorseed"
                reference= "https://stuff.rop.io/"
	strings:
		$sys1 = "sys_write" nocase ascii wide	
		$sys2 = "sys_getdents" nocase ascii wide
		$sys3 = "sys_getdents64" nocase ascii wide
		$sys4 = "sys_getpgid" nocase ascii wide
		$sys5 = "sys_getsid" nocase ascii wide
		$sys6 = "sys_setpgid" nocase ascii wide
		$sys7 = "sys_kill" nocase ascii wide
		$sys8 = "sys_tgkill" nocase ascii wide
		$sys9 = "sys_tkill" nocase ascii wide
		$sys10 = "sys_sched_setscheduler" nocase ascii wide
		$sys11 = "sys_sched_setparam" nocase ascii wide
		$sys12 = "sys_sched_getscheduler" nocase ascii wide
		$sys13 = "sys_sched_getparam" nocase ascii wide
		$sys14 = "sys_sched_setaffinity" nocase ascii wide
		$sys15 = "sys_sched_getaffinity" nocase ascii wide
		$sys16 = "sys_sched_rr_get_interval" nocase ascii wide
		$sys17 = "sys_wait4" nocase ascii wide
		$sys18 = "sys_waitid" nocase ascii wide
		$sys19 = "sys_rt_tgsigqueueinfo" nocase ascii wide
		$sys20 = "sys_rt_sigqueueinfo" nocase ascii wide
		$sys21 = "sys_prlimit64" nocase ascii wide
		$sys22 = "sys_ptrace" nocase ascii wide
		$sys23 = "sys_migrate_pages" nocase ascii wide
		$sys24 = "sys_move_pages" nocase ascii wide
		$sys25 = "sys_get_robust_list" nocase ascii wide
		$sys26 = "sys_perf_event_open" nocase ascii wide
		$sys27 = "sys_uname" nocase ascii wide
		$sys28 = "sys_unlink" nocase ascii wide
		$sys29 = "sys_unlikat" nocase ascii wide
		$sys30 = "sys_rename" nocase ascii wide
		$sys31 = "sys_read" nocase ascii wide
		$sys32 = "kobject_del" nocase ascii wide
		$sys33 = "list_del_init" nocase ascii wide
		$sys34 = "inet_ioctl" nocase ascii wide
	condition:
		9 of them
}

rule exploit
{
        meta:
                author="xorseed"
                reference= "https://stuff.rop.io/"
	strings:
		$xpl1 = "set_fs_root" nocase ascii wide
		$xpl2 = "set_fs_pwd" nocase ascii wide
		$xpl3 = "__virt_addr_valid" nocase ascii wide
		$xpl4 = "init_task" nocase ascii wide
		$xpl5 = "init_fs" nocase ascii wide
		$xpl6 = "bad_file_ops" nocase ascii wide
		$xpl7 = "bad_file_aio_read" nocase ascii wide
		$xpl8 = "security_ops" nocase ascii wide
		$xpl9 = "default_security_ops" nocase ascii wide
		$xpl10 = "audit_enabled" nocase ascii wide
		$xpl11 = "commit_creds" nocase ascii wide
		$xpl12 = "prepare_kernel_cred" nocase ascii wide
		$xpl13 = "ptmx_fops" nocase ascii wide
		$xpl14 = "node_states" nocase ascii wide
	condition:
		7 of them
}

