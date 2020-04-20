/*
    I first found this in May 2016, appeared in every PHP file on the
    server, cleaned it with `sed` and regex magic. Second time was
    in June 2016, same decoded content, different encoding/naming.

    https://www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99
*/
rule php_anuna
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a PHP Trojan"
    strings:
        $a = /<\?php \$[a-z]+ = '/
        $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
        $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
        $d = /if \(!function_exists\('[a-z]+'\)\)/
    condition:
        all of them
}
