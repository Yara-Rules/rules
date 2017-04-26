/*
    Author: Jaume Martin
    Date: 26/04/2017
    Description: This finds the magics on dump files, like raw dd image. This can though false positives.
*/

rule contains_pdf: PDF
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {25 50 44 46}
        $b = {0A 25 25 45 4F 46 (??|0A)}
        $c = {0D 0A 25 25 45 4F 46 0D 0A}
        $d = {0D 25 25 45 4F 46 0D}

    condition:
       $a and for any of ($b, $c, $d): ( @ > @a )
}
