/*
    Author: Jaume Martin
    Date: 26/04/2017
    Description: This finds the magics on dump files, like raw dd image.
    Disclaimer: This can though false positives.
*/

rule contains_ogg: OGG
{
    meta:
        author = "Jaume Martin"
        file_info = "Ogg Vorbis Codec"

    strings:
        $a = {4F 67 67 53 00 02 00 00 00 00 00 00 00 00}

    condition:
       $a
}
