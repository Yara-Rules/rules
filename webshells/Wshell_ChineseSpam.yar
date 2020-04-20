/*
    PHP file(s) (spreader) that, using multiple remote
    servers, use file_get_contents() to get more PHP
    content that it writes in files with random name
    (echoers), file(s) which use file_get_contents()
    to get and echo the HTML (chinese blog/shop/???).
*/
rule chinese_spam_spreader : webshell
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches chinese PHP spam files (autospreaders)"
    strings:
        $a = "User-Agent: aQ0O010O"
        $b = "<font color='red'><b>Connection Error!</b></font>"
        $c = /if ?\(\$_POST\[Submit\]\) ?{/
    condition:
        all of them
}

rule chinese_spam_echoer : webshell
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches chinese PHP spam files (printers)"
    strings:
        $a = "set_time_limit(0)"
        $b = "date_default_timezone_set('PRC');"
        $c = "$Content_mb;"
        $d = "/index.php?host="
    condition:
        all of them
}
