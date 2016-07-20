/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule genome {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-07"
        description = "Identify Genome"
	strings:
	    $s1 = "Attempting to create more than one keyboard::Monitor instance"
        $s2 = "{Right windows}"
        $s3 = "Access violation - no RTTI data!"
    condition:
        all of them
}
