/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/



rule sendsafe {

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2016/09"
        reference = "http://pastebin.com/WPWWs406"
		version = 2
        maltype = "Spammer"
        filetype = "memory"

    strings:
        $a = "Enterprise Mailing Service"
        $b = "Blacklisted by rule: %s:%s"
        $c = "/SuccessMails?CampaignNum=%ld"
        $d = "/TimedOutMails?CampaignNum=%ld"
        $e = "/InvalidMails?CampaignNum=%ld"
        $f = "Failed to download maillist, retrying"
        $g = "No maillist loaded"
        $h = "Successfully sent using SMTP account %s (%d of %ld messages to %s)"
        $i = "Successfully sent %d of %ld messages to %s"
        $j = "Sending to %s in the same connection"
        $k = "New connection required, will send to %s"
		$l = "Mail transaction for %s is over."
		$m = "Domain %s is bad (found in cache)"
		$n = "Domain %s found in cache"
		$o = "Domain %s isn't found in cache, resolving it"
		$p = "All tries to resolve %s failed."
		$q = "Failed to receive response for %s from DNS server"
		$r = "Got DNS server response: domain %s is bad"
		$s = "Got error %d in response for %s from DNS server"
		$t = "MX's IP for domain %s found in cache:"
		$u = "Timeout waiting for domain %s to be resolved"
		$v = "No valid MXes for domain %s. Marking it as bad"
		$w = "Resolving MX %s using existing connection to DNS server"
		$x = "All tries to resolve MX for %s are failed"
		$y = "Resolving MX %s using DNS server"
		$z = "Failed to receive response for MX %s from DNS server"

    condition:
        13 of them
}
