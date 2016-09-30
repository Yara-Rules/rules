rule Backdoor_Jolob
{
	meta:
		maltype = "Backdoor.Jolob"
    ref = "https://github.com/reed1713"
		reference = "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks"
		description = "the backdoor registers an auto start service with the display name \"Network Access Management Agent\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."
	strings:   
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4673"
		$data1 = "Security"
		$data2 = "SeCreateGlobalPrivilege"
		$data3 = "Windows\\System32\\sysprep\\sysprep.exe" nocase
        
		$type1 = "Microsoft-Windows-Security-Auditing"
		$eventid1 = "4688"
		$data4 = "Windows\\System32\\sysprep\\sysprep.exe" nocase
        
		$type2 = "Service Control Manager"
		$eventid2 = "7036"
		$data5 = "Network Access Management Agent"
		$data6 = "running"
        
		$type3 = "Service Control Manager"
		$eventid3 = "7045"
		$data7 = "Network Access Management Agent"
		$data8 = "user mode service"
		$data9 = "auto start"      
    condition:
    	all of them
}
