/*
    Finds PHP code in JP(E)Gs, GIFs, PNGs.
    Magic numbers via Wikipedia.
*/
rule php_in_image
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Finds image files w/ PHP code in images"
    strings:
        $gif = /^GIF8[79]a/
        $jfif = { ff d8 ff ee 00 10 4a 46 49 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }

        $php_tag = "<?php"
    condition:
        (($gif at 0) or
        ($jfif at 0) or
        ($png at 0)) and

        $php_tag
}
