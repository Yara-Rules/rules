/*
    Webshell "fire2013.php" - shell apended to PHP!Anuna code,
    found in the wild both appended and single.

    Shell prints a fake "404 not found" Apache message, while
    the user has to post "pass=Fuck1950xx=" to enable it.

    As written in the original (decoded PHP) file,
    @define('VERSION', 'v4 by Sp4nksta');

    Shell is also backdoored, it mails the shell location and
    info on "h4x4rwow@yahoo.com" as written in the "system32()"
    function.
*/
rule fire2013
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a webshell"
    strings:
        $a = "eval(\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61"
        $b = "yc0CJYb+O//Xgj9/y+U/dd//vkf'\\x29\\x29\\x29\\x3B\")"
    condition:
        all of them
}
