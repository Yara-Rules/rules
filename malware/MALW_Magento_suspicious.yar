/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
ref : https://github.com/gwillem/magento-malware-scanner/
author : https://github.com/gwillem

*/

rule fromCharCode_in_unicode {
    strings: 
        $ = "\\u0066\\u0072\\u006f\\u006d\\u0043\\u0068\\u0061\\u0072\\u0043\\u006f\\u0064\\u0065"
    condition: 
        any of them and filesize < 500KB
}
rule function_through_object {
    strings: 
        $ = "['eval']"
        $ = "['unescape']"
        $ = "['charCodeAt']"
        $ = "['fromCharCode']"
    condition: 
        any of them and filesize < 500KB
}
rule hex_script {
    strings:
        $ = "\\x73\\x63\\x72\\x69\\x70\\x74\\x22"
    condition: 
        any of them and filesize < 500KB
}

rule php_malfunctions {
    strings:
        $ = "eval("
        $ = "gzinflate("
        $ = "str_rot13("
        $ = "base64_decode("
    condition: 
        3 of them and filesize < 500KB
}

rule php_obf_malfunctions {
    strings:
        $ = "eval(base64_decode"
        $ = "eval(gzinflate"
        $ = "str_rot13(base64_decode"
    condition: 
        any of them and filesize < 500KB
}
        
rule fopo_obfuscator {
    strings:
        $ = "www.fopo.com.ar"
    condition: 
        any of them and filesize < 500KB
}

rule obf_base64_decode {
    strings: 
        $ = "\\x62\\x61\\x73\\145\\x36\\x34\\x5f\\x64\\x65\\143\\x6f\\144\\145"
    condition: 
        any of them and filesize < 500KB
}

rule html_upload {
    strings: 
        $ = "<input type='submit' name='upload' value='upload'>"
        $ = "if($_POST['upload'])"
    condition: 
        any of them and filesize < 500KB
}

rule php_uname {
    strings: 
        $ = "php_uname()"
    condition: 
        any of them and filesize < 500KB
}

rule scriptkiddies {
    strings:
        $ = "lastc0de@Outlook.com" nocase
        $ = "CodersLeet" nocase
        $ = "AgencyCaFc" nocase
        $ = "IndoXploit" nocase
        $ = "Kapaljetz666" nocase
    condition: 
        any of them and filesize < 500KB
}

rule eval_with_comments {
	strings:
		$ = /(^|\s)eval\s*\/\*.{,128}\*\/\s*\(/
	condition: 
        any of them and filesize < 500KB
}
