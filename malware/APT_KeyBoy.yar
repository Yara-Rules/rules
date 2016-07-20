/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule KeyBoy_Dropper  : dropper
{  
    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:
        $1 = "I am Admin"  
        $2 = "I am User"  
        $3 = "Run install success!"  
        $4 = "Service install success!"  
        $5 = "Something Error!"  
        $6 = "Not Configed, Exiting"  

    condition:  
        all of them  
}

rule KeyBoy_Backdoor  : Backdoor APT
{
    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:  
        $1 = "$login$"  
        $2 = "$sysinfo$"  
        $3 = "$shell$"  
        $4 = "$fileManager$"  
        $5 = "$fileDownload$"  
        $6 = "$fileUpload$"  

    condition:  
        all of them  
} 
