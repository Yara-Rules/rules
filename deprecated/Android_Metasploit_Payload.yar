import "androguard"

rule Metasploit_Payload
{
meta:
author = "https://www.twitter.com/SadFud75"
information = "Detection of payloads generated with metasploit"
strings:
$s1 = "-com.metasploit.meterpreter.AndroidMeterpreter"
$s2 = ",Lcom/metasploit/stage/MainBroadcastReceiver;"
$s3 = "#Lcom/metasploit/stage/MainActivity;"
$s4 = "Lcom/metasploit/stage/Payload;"
$s5 = "Lcom/metasploit/stage/a;"
$s6 = "Lcom/metasploit/stage/c;"
$s7 = "Lcom/metasploit/stage/b;"
condition:
androguard.package_name("com.metasploit.stage") or any of them
}
