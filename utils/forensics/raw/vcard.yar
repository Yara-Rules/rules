/*
    Author: Jaume Martin
    Date: 26/04/2017
    Description: This finds the magics on dump files, like raw dd image. This can though false positives.
*/

rule contains_vcard: vCard
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {42 45 47 49 4E 3A 56 43 41 52 44 0D 0A}

    condition:
       $a
}
