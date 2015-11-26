/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule pony {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-16"
        description = "Identify Pony"
	strings:
    	$s1 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
    	$s2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
    	$s3 = "POST %s HTTP/1.0"
    	$s4 = "Accept-Encoding: identity, *;q=0"

    	//$useragent1 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)"
    	//$useragent2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)"
    condition:
        $s1 and $s2 and $s3 and $s4
}
