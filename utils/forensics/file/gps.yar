/*
    Author: Jaume Martin
    Date: 24/04/2017
    Description: This finds the magics on individual files.
*/

rule gps_magic: GPS GPX
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {3C 67 70 78 20 76 65 72 73 69 6F 6E 3D 22 31 2E 31}

    condition:
       $a at 0
}
