/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_FakeBank_Fanta
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android FakeBank_Fanta"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"

	condition:
		androguard.service(/SocketService/i) and 
		androguard.receiver(/MyAdmin/i) and 
		androguard.receiver(/Receiver/i) and 
		androguard.receiver(/NetworkChangeReceiver/i)
		
}
