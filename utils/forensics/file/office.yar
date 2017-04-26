/*
    Author: Jaume Martin
    Date: 24/04/2017
    Description: This finds the magics on individual files.
*/

rule doc_magic: DOC
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {CF 11 E0 A1 B1 1A E1 00}

    condition:
       $a at 0
}
