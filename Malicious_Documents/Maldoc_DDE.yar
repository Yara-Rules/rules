rule Contains_DDE_Protocol
{
        meta:
                author = "Nick Beede"
                description = "Detect Dynamic Data Exchange protocol in doc/docx"
                reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
                date = "2017-10-19"
                filetype = "Office documents"
        
        strings:
                $doc = {D0 CF 11 E0 A1 B1 1A E1}
                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto
                $s2 = { 13 64 64 65 20 } // !!dde
                $s3 = "dde" nocase
                $s4 = "ddeauto" nocase

        condition:
                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)
}
