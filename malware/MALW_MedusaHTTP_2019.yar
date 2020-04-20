
rule MedussaHTTP_2019
{

    meta:
        author = "J from THL <j@techhelplist.com>"
        date = "2019-08-12"
        reference1 = "https://app.any.run/tasks/68c8f400-eba5-4d6c-b1f1-8b07d4c014a4/"
        reference2 = "https://www.netscout.com/blog/asert/medusahttp-ddos-slithers-back-spotlight"
        reference3 = "https://twitter.com/malware_traffic/status/1161034462983008261"
        version = 1
        maltype = "Bot"
        filetype = "memory"
        description = "MedussaHTTP v20190812"

    strings:
        $text01 = "|check|" ascii
        $text02 = "POST!" ascii
        $text03 = "httpactive" ascii
        $text04 = "httpstrong" ascii
        $text05 = "httppost" ascii
        $text06 = "slavicdragon" ascii
        $text07 = "slavicnodragon" ascii
        $text08 = "smartflood" ascii
        $text09 = "stop-all" ascii
        $text10 = "botkill" ascii
        $text11 = "updatehash" ascii
        $text12 = "xyz=" ascii
        $text13 = "abc=" ascii



    condition:
        9 of them
}

