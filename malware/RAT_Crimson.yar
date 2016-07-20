rule Crimson: RAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Crimson Rat"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Crimson"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "com/crimson/PK"
		$a2 = "com/crimson/bootstrapJar/PK"
		$a3 = "com/crimson/permaJarMulti/PermaJarReporter$1.classPK"
		$a4 = "com/crimson/universal/containers/KeyloggerLog.classPK"
        $a5 = "com/crimson/universal/UploadTransfer.classPK"
        
	condition:
        all of ($a*)
}
