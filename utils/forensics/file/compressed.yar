/*
    Author: Jaume Martin
    Date: 24/04/2017
    Description: This finds the magics on individual files.
*/

rule _7z_magic: _7z
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {37 7A BC AF 27 1C}

    condition:
       $a at 0
}
