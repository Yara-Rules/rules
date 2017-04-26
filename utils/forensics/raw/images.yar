/*
    Author: Jaume Martin
    Date: 26/04/2017
    Description: This finds the magics on dump files, like raw dd image. This can though false positives.
*/

rule contains_jpeg: JFIF JPE JPEG JPG
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {FF D8 FF E0 ?? ?? 4A 46 49 46 00}

    condition:
       $a
}


rule contains_jpg_with_EXIF: JPG
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {FF D8 FF E1 ?? ?? 45 78 69 66 00}

    condition:
       $a
}

rule contains_jpeg_like_Canon_EOS: JPEG
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {FF D8 FF E2 ?? ?? 53 50 49 46 46 00}

    condition:
       $a
}

rule contains_jpeg_like_Samsung_D500: JPEG
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {FF D8 FF E3 ?? ?? 53 50 49 46 46 00}

    condition:
       $a
}

rule contains_jpg_with_SPIFF: JPG
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {FF D8 FF E8 ?? ?? 53 50 49 46 46 00}

    condition:
       $a
}

rule contains_jpeg_2000: JPEG2000
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {00 00 00 0C 6A 50 20 20 0D 0A}

    condition:
       $a
}
