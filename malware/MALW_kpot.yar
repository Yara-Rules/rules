
rule kpot
{

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2018-08-29"
        reference1 = "https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection"
        reference2 = "ETPRO TROJAN KPOT Stealer Check-In [2832358]"
        reference3 = "ETPRO TROJAN KPOT Stealer Exfiltration [2832359]"
        version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
        $text01 = "bot_id=%s"
        $text02 = "x64=%d"
        $text03 = "is_admin=%d"
        $text04 = "IL=%d"
        $text05 = "os_version=%d"
        $text06 = "IP: %S"
        $text07 = "MachineGuid: %s"
        $text08 = "CPU: %S (%d cores)"
        $text09 = "RAM: %S MB"
        $text10 = "Screen: %dx%d"
        $text11 = "PC: %s"
        $text12 = "User: %s"
        $text13 = "LT: %S (UTC+%d:%d)"
        $text14 = "%s/%s.php"
        $text15 = "Host: %s"
        $text16 = "username_value"
        $text17 = "password_value"
        $text18 = "name_on_card"
        $text19 = "last_four"
        $text20 = "exp_month"
        $text21 = "exp_year"
        $text22 = "bank_name"


    condition:
        16 of them
}

