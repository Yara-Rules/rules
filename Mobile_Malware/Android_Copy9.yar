import "androguard"

rule Android_Copy9
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "This rule try to detect commercial spyware from Copy9"
		source = "http://copy9.com/"

	condition:
		androguard.service(/com.ispyoo/i) and
        androguard.receiver(/com.ispyoo/i)
}
