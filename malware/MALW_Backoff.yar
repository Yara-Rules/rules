/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule backoff {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-21"
        description = "Identify Backoff"
	strings:
    	$s1 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s"
        $s2 = "%s @ %s"
        $s3 = "Upload KeyLogs"
    condition:
        all of them
}
