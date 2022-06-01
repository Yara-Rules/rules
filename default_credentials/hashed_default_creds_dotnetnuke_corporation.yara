/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="59dcf537d3bcf1a8d5371d976acb1caf"
    $a2="67b3dba8bc6778101892eb77249db32e"
    $a3="918b9b18a0534279f5513dc90e884b03"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="98ccf140be68f65068348e0a16b162e88f3338c3"
    $a2="86dd1cf45142e904cb2e99c2721fac3ca198c6ca"
    $a3="a8853b73a6af93946b77f9e9cd340e3e90581a61"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="350ea305609f5d653d208f9cbb0b057fa85e78e9c944ba92deb41016fb717e2b79ce26ae336424139fe40bcaedea33ee"
    $a2="32906d5059ffeeb04d1b2827668275a056f3aa9c3fe2d7d208b20a6ce51e765b7ffae3a603169691b3726a9451ae9a32"
    $a3="8de8398339c56a88dfd7de766d27aff5908aa46946cc736497727b9e0eec9ace205f3884bdf8b101ad8421cdb1d7dae9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="14c4b1c76b7626d2f3edb1001fb4ca6b435788d0cee8093f297caa7b"
    $a2="7c101be7cc7ede3574e285c9ab5c9509a82fc0397b8124c1fedd4220"
    $a3="f013b1eadd0f30bb1098f1f0d6a3a85e8580d4d1c74c67631af8977a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="f45c729468e5fe1656e8e74422b147596997cc93b2d0c1acab378c45b09cc2fb6c4aec9747abdd0adae32b0a73e4f336844e85a88ff07bc4db47756215a57a71"
    $a2="274a91d963475a541cb072db6e7009f74a90382830c61f522d1a3b04830852c134ee445a9a7c6edabd54c55f4b702e876891502af9bcf4a09bd0fb1686f17f75"
    $a3="f7f521459599be132ab6b8398cc7992441496e525063f6094cc0d0aadb283cb5ede95bf26758acc6a8c4868c20fd53b97c3c2ce6e21459eaa3be0f7d234ffc3e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="6529da56f1a1f6ae50652d544c131050256bc52568611b75049a90ca047bb221"
    $a2="4740ae6347b0172c01254ff55bae5aff5199f4446e7f6d643d40185b3f475145"
    $a3="06f25bcf0acf336cdee0f93659c7647d8ab7b9c3c7d1d6274887a8c1d1b758cb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="ecb5d0ac5867af43cd3248351aaf3c9a37a7f43941afb1e2dcd8f06dbf77ef5613d3e0ee9cdcb55a62b058798d16b1a6ddc4a01764a16723e52e83524e3a92ef"
    $a2="e632aa49869df1d3f18924570d119e21d74eba22c223fe2c7a44fda534be1775b16f3f820bf4581e53da8995549822a25295d411a01ef020b71ce79902056a3b"
    $a3="4bac5cf787ff4972e4736aa7c8cf99ed090f8faf156f7d11dee474c67e829625508673a7ef7706ddb3f978c856bb66a4fd345e5d9dfbe7831ca6fe44ebc3a9a2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="f7b113ff801fb50023a83c2c33c2732f3506a821f7c5a80dcdf8d5a9f43eb043"
    $a2="473a20f542b5b6a611556a801d03a37bc325d068ae6a88f9e071046f8b37d01f"
    $a3="6c59e495a609f814a354b7e23f9999b165ca4ace840cb56ead4c51d66fb9e978"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="7a055b5ab54022db10e15626f800150723eda262a61cfc0be59f2376"
    $a2="db5e30a47322c761740480c3247b59f6bf662982e2d03c72de2c9b83"
    $a3="7bf3bc56cef319a06b0c3916ee4f27712e4bf172abd4be1a3be61e67"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="d2eaf15b42968a73155fa0d24cd4c95040b9c00456c56a0ce9fc59f384d34586"
    $a2="cd6eabc83530c226c655cb021ea0d14f5e5675059796de05ac6cd7ea26bebaa5"
    $a3="52c775b5506476a324efb4f580bc568d0cf4338f58d0ea44dc50cf03344cc532"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="419782da9de8f9546cb015f8b2b56708f278c1873e9e265a5a75990e518b852a2061cc54ef843065d3b84d171b6d474e"
    $a2="5f3d970704a7b947de561ac8104a0585f6136e13ba72de77a03a2cc1acce9e7e37b11897829fc8f010f1d5524f4d8390"
    $a3="5f66cdfd90f5e779e36b0f0713f2e038860b455fc4d43313b039fd752ff54c49ac296984f9a80d96436b9cfeacc01432"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="4987d07bd730b884a4e4e023a369d7353c94750f5872c5af88bda4a1533b51300c6c39ad11ee3cca319313c1074d5acef66ccfd9d9ab885a40d0346af6d1c8d8"
    $a2="ea54b4ab3e70c14e67688dc056c75014512d97162cfe3de27f694c5c342dc330d8dea865a615636c851064a93bded42ec5612758030cdf214b41016ba1496464"
    $a3="2642081248f96d73d4dd806c53e7a39b18227c46640ee506caf2ae6f741821e26a0fff9c9a5b8298b075e129592c12eb29d0e393aa385b261126de76dd2e70a8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_dotnetnuke_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dotnetnuke_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="ZG5uYWRtaW4="
    $a2="aG9zdA=="
    $a3="ZG5uaG9zdA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

