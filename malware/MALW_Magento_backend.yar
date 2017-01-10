/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
ref : https://github.com/gwillem/magento-malware-scanner/blob/master/rules/backend.yar
author : https://github.com/gwillem

*/

rule dump_sales_quote_payment {
    strings: $ = "include '../../../../../../../../../../app/Mage.php'; Mage::app(); $q = Mage::getModel('sales/quote_payment')->getCollection();"
    condition: any of them
}
rule dump_sales_order {
    strings: $ = "../../../../../../app/Mage.php'; Mage::app(); var_dump(Mage::getModel('sales/order')"
    condition: any of them
}
rule md5_64651cede2467fdeb1b3b7e6ff3f81cb {
    strings: $ = "rUl6QttVEP5eqf9usxfJjgoOvdNWFSGoHDgluk+4ONwXQNbGniQLttfyrgkB8d9"
    condition: any of them
}
rule md5_6bf4910b01aa4f296e590b75a3d25642 {
    strings: $ = "base64_decode('b25lcGFnZXxnY19hZG1pbg==')"
    condition: any of them
}
rule fopo_webshell {
    strings: 
        $ = "DNEcHdQbWtXU3dSMDA1VmZ1c29WUVFXdUhPT0xYb0k3ZDJyWmFVZlF5Y0ZEeHV4K2FnVmY0OUtjbzhnc0"
        $ = "U3hkTVVibSt2MTgyRjY0VmZlQWo3d1VlaFJVNVNnSGZUVUhKZXdEbGxJUTlXWWlqWSt0cEtacUZOSXF4c"
        $ = "rb2JHaTJVdURMNlhQZ1ZlTGVjVnFobVdnMk5nbDlvbEdBQVZKRzJ1WmZUSjdVOWNwWURZYlZ0L1BtNCt"
    condition: any of them
}
rule eval_post {
    strings:
        $ = "eval(base64_decode($_POST"
        $ = "eval($undecode($tongji))"
        $ = "eval($_POST"
    condition: any of them
}
rule spam_mailer {
    strings:
        $ = "<strong>WwW.Zone-Org</strong>"
        $ = "echo eval(urldecode("
    condition: any of them
}
rule md5_0105d05660329704bdb0ecd3fd3a473b {
    /*
		)){eval (${ $njap58}['q9e5e25' ])
		) ) { eval ( ${$yed7 }['
    */
    strings: $ = /\)\s*\)\s*\{\s*eval\s*\(\s*\$\{/
    condition: any of them
}
rule md5_0b1bfb0bdc7e017baccd05c6af6943ea {
	/*
		eval(hnsqqh($llmkuhieq, $dbnlftqgr));?>
		eval(vW91692($v7U7N9K, $v5N9NGE));?>
    */
    strings: $ = /eval\([\w\d]+\(\$[\w\d]+, \$[\w\d]+\)\);/
    condition: any of them
}
rule md5_2495b460f28f45b40d92da406be15627 {
    strings: $ = "$dez = $pwddir.\"/\".$real;copy($uploaded, $dez);"
    condition: any of them
}
rule md5_2c37d90dd2c9c743c273cb955dd83ef6 {
    strings: $ = "@$_($_REQUEST['"
    condition: any of them
}
rule md5_3ccdd51fe616c08daafd601589182d38 {
    strings: $ = "eval(xxtea_decrypt"
    condition: any of them
}
rule md5_4b69af81b89ba444204680d506a8e0a1 {
    strings: $ = "** Scam Redirector"
    condition: any of them
}
rule md5_71a7c769e644d8cf3cf32419239212c7 {
	/*
    // $GLOBALS['ywanc2']($GLOBALS['ggbdg61']
    */
    strings: $ = /\$GLOBALS\['[\w\d]+'\]\(\$GLOBALS\['[\w\d]+'\]/
    condition: any of them
}
rule md5_825a3b2a6abbe6abcdeda64a73416b3d {
	/*
    // $ooooo00oo0000oo0oo0oo00ooo0ooo0o0o0 = gethostbyname($_SERVER["SERVER_NAME"]);
    // if(!oo00o0OOo0o00O("fsockopen"))
    // strings: $ = "$ooooo00oo0000oo0"
    */
    strings: $ = /[o0O]{3}\("fsockopen"\)/
    condition: any of them
}
rule md5_87cf8209494eedd936b28ff620e28780 {
    strings: $ = "curl_close($cu);eval($o);};die();"
    condition: any of them
}
rule md5_9b59cb5b557e46e1487ef891cedaccf7 {
    strings: 
        $jpg = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 01 }
		/*
        // https://en.wikipedia.org/wiki/List_of_file_signatures
        // magic module is not standard compiled in on our platform
        // otherwise: condition: magic.mime_type() == /^image/
        // $jpg = { 4A 46 49 46 00 01 }
        */
        $php = "<?php"
    condition: ($jpg at 0) and $php
}
rule md5_c647e85ad77fd9971ba709a08566935d {
    strings: $ = "fopen(\"cache.php\", \"w+\")"
    condition: any of them
}
rule md5_fb9e35bf367a106d18eb6aa0fe406437 {
    strings: $ = "0B6KVua7D2SLCNDN2RW1ORmhZRWs/sp_tilang.js"
    condition: any of them
}
rule md5_8e5f7f6523891a5dcefcbb1a79e5bbe9 {
    strings: $ = "if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])) {echo '<b>up!!!</b><br><br>';}}"
    condition: any of them
}
rule indoexploit_autoexploiter {
    strings: $ = "echo \"IndoXploit - Auto Xploiter\""
    condition: any of them
}
rule eval_base64_decode_a {
    strings: $ = "eval(base64_decode($a));"
    condition: any of them
}
rule obfuscated_eval {
    strings: 
	$ = /\\x65\s*\\x76\s*\\x61\s*\\x6C/
	$ = "\"/.*/e\""
    condition: any of them
}
rule md5_50be694a82a8653fa8b31d049aac721a {
    strings: $ = "(preg_match('/\\/admin\\/Cms_Wysiwyg\\/directive\\/index\\//', $_SERVER['REQUEST_URI']))"
    condition: any of them
}
rule md5_ab63230ee24a988a4a9245c2456e4874 {
    strings: $ = "eval(gzinflate(base64_decode(str_rot13(strrev("
    condition: any of them
}
rule md5_b579bff90970ec58862ea8c26014d643 {
    /* forces php execution of image files, dropped in an .htaccess file under media */
    strings: $ = /<Files [^>]+.(jpg|png|gif)>\s*ForceType application\/x-httpd-php/
    condition: any of them
}
rule md5_d30b23d1224438518d18e90c218d7c8b {
    strings: $ = "attribute_code=0x70617373776f72645f68617368"
    condition: any of them
}
rule md5_24f2df1b9d49cfb02d8954b08dba471f {
    strings: $ = "))unlink('../media/catalog/category/'.basename($"
    condition: any of them
}
rule base64_hidden_in_image {
    strings: $ = /JPEG-1\.1[a-zA-Z0-9\-\/]{32}/
    condition: any of them
}
rule hide_data_in_jpeg {
    strings: $ = /file_put_contents\(\$.{2,3},'JPEG-1\.1'\.base64_encode/
    condition: any of them
}
rule hidden_file_upload_in_503 {
    strings: $ = /error_reporting\(0\);\$f=\$_FILES\[\w+\];copy\(\$f\[tmp_name\],\$f\[name\]\);error_reporting\(E_ALL\);/
    condition: any of them
}
rule md5_fd141197c89d27b30821f3de8627ac38 {
    strings: $ = "if(isset($_GET['do'])){$g0='adminhtml/default/default/images'"
    condition: any of them
}
rule visbot {
    strings:
		$ = "stripos($buf, 'Visbot')!==false && stripos($buf, 'Pong')!==false"
		$ = "stripos($buf, 'Visbot') !== false && stripos($buf, 'Pong')"
    condition: any of them
}
rule md5_39ca2651740c2cef91eb82161575348b {
    strings: $ = /if\(md5\(@\$_COOKIE\[..\]\)=='.{32}'\) \(\$_=@\$_REQUEST\[.\]\).@\$_\(\$_REQUEST\[.\]\);/
    condition: any of them
}
rule md5_4c4b3d4ba5bce7191a5138efa2468679 {
    strings:
        $ = "<?PHP /*** Magento** NOTICE OF LICENSE** This source file is subject to the Open Software License (OSL 3.0)* that is bundled with this package in the file LICENSE.txt.* It is also available through the world-wide-web at this URL:* http://opensource.org/licenses/osl-3.0.php**/$"
        $ = "$_SERVER['HTTP_USER_AGENT'] == 'Visbot/2.0 (+http://www.visvo.com/en/webmasters.jsp;bot@visvo.com)'"
    condition: any of them
}
rule md5_6eb201737a6ef3c4880ae0b8983398a9 {
    strings:
        $ = "if(md5(@$_COOKIE[qz])=="
        $ = "($_=@$_REQUEST[q]).@$_($_REQUEST[z]);"
    condition: all of them
}
rule md5_d201d61510f7889f1a47257d52b15fa2 {
    strings: $ = "@eval(stripslashes($_REQUEST[q]));"
    condition: any of them
}
rule md5_06e3ed58854daeacf1ed82c56a883b04 {
    strings: $ = "$log_entry = serialize($ARINFO)"
    condition: any of them
}
rule md5_28690a72362e021f65bb74eecc54255e {
    strings: $ = "curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query(array('data'=>$data,'utmp'=>$id)));"
    condition: any of them
}
rule overwrite_globals_hack {
    strings: $ = /\$GLOBALS\['[^']{,20}'\]=Array\(/
    condition: any of them
}
rule md5_4adef02197f50b9cc6918aa06132b2f6 {
    /* { eval($cco37(${ $kasd1}[ 'n46b398' ] ) );} */
    strings: $ = /\{\s*eval\s*\(\s*\$.{1,5}\s*\(\$\{\s*\$.{1,5}\s*\}\[\s*'.{1,10}'\s*\]\s*\)\s*\);\}/
    condition: any of them
}
rule obfuscated_globals {
    /* $GLOBALS['y63581'] = "\x43 */
    strings: $ = /\$GLOBALS\['.{1,10}'\] = "\\x/
    condition: any of them
}
rule ld_preload_backdoor {
    strings: $ = "killall -9 \".basename(\"/usr/bin/host"
    condition: any of them
}
rule fake_magentoupdate_site {
    strings: $ = "magentopatchupdate.com"
    condition: any of them
}
rule md5_b3ee7ea209d2ff0d920dfb870bad8ce5 {
    strings:
        $ = /\$mysql_key\s*=\s*@?base64_decode/
        $ = /eval\(\s*\$mysql_key\s*\)/
    condition: all of them
}
rule md5_e03b5df1fa070675da8b6340ff4a67c2 {
    strings:
        $ = /if\(preg_match\("\/onepage\|admin\/",\s*\$_SERVER\['REQUEST_URI'\]\)\)\{\s*@?file_put_contents/
        $ = /@?base64_encode\(serialize\(\$_REQUEST\)\."--"\.serialize\(\$_COOKIE\)\)\."\\n",\s*FILE_APPEND\)/
    condition: any of them
}
rule md5_023a80d10d10d911989e115b477e42b5 {
    strings: $ = /chr\(\d{,3}\)\.\"\"\.chr\(\d{,3}\)/
    condition: any of them
}
rule md5_4aa900ddd4f1848a15c61a9b7acd5035 {
    strings: $ = "'base'.(128/2).'_de'.'code'"
    condition: any of them
}
rule md5_f797dd5d8e13fe5c8898dbe3beb3cc5b {
    strings: $ = "echo(\"FILE_Bad\");"
    condition: any of them
}
