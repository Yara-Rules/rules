rule Maldoc_CVE_2017_11882 : Exploit {
    meta:
        description = "Detects maldoc With exploit for CVE_2017_11882"
        author = "Marc Salinas (@Bondey_m)"
        reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
        date = "2017-10-20"
    strings:
        $doc = "d0cf11e0a1b11ae1"
        $s0 = "Equation"
        $s1 = "1c000000020"
        $h0 = {1C 00 00 00 02 00}

    condition: 
        (uint32be(0) == 0x7B5C7274 or $doc at 0 ) and $s0 and ($h0 or $s1)
}
