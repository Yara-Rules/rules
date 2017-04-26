/*
    Author: Jaume Martin
    Date: 26/04/2017
    Description: This finds the magics on dump files, like raw dd image. This can though false positives.
*/

rule contains_doc: DOC
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {CF 11 E0 A1 B1 1A E1 00}

    condition:
       $a
}
