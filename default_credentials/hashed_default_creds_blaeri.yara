/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69b9813b448289baddadfc3002708789"
    $a1="6762b8b9c5ee6eb5c2e9f5098e49de02"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f0273184f6f40849afa9949cff65ec1c0a368349"
    $a1="246c51e58f0f6b698f257266e776774d7739c44a"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="750a96e77d7cd98497f73687cd5252b9c3f7def02e6c3b6dcc0b10b44fc1e24fc6ab91d642d04252e69edac6dde0555e"
    $a1="2358c960f2c8b666b3ac4c09ef55d38889d2149932684a328f4572d616dfc0d0f19b565e20b3b3d5f5a38ad456b23dea"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6c4ac34998136eba9ae29e1d2fe68aefd82ac881de00dd02c67f80fe"
    $a1="2d5664b2e148857b670b8b303297efae9f0047f1b70cedc7702ccadd"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="836acd2addb8cef4e48237ed8e7e4dbea814c991f8519f753147e2ab112bdd2d47c0432c60d0a68478aa9898c2c97fb70a60fd745d5bf61af294120bed04aa5a"
    $a1="332d4a3c66da88c1a4dc0a522b0f5afdcc4fad3646ce0e3c65fc606d0fc913817b97576dc7d98c69391ac3925d16c01f3827a45c9a7352d819b14bb5b8c95f59"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="245dc8004d15c6b26faae1c7ac5421f3c1fd417cbbd632cb197dcaf5ea96140c"
    $a1="11638794f5a56a79a897b913ece5183b74de53f2553bf81214edd7c212051239"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="087f2a0c3e81a71ce032eaeaceb67f598cb3f6fe40450544f95609d591c28026813a1046e040629c410e0d7b08b60a0a94993239fea0bb913f13bf8e32b1ad37"
    $a1="25f6a4deb4df829aa8b18ba2dcdaa905a9f708afb8897acd67780bf14727f5d5c41e7b061d62620c450332d02dcbb0555a2f940052cb5b734cf388a533138e28"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2522a692892d9967e3f408ba96dfe017ed399393084751231e198618f3b1d505"
    $a1="45e3823c08777743b3559f4719c0d1caf9870a0a7ff21176447d288b3433fa9c"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="55f933c5b65609f6219012b62da613ae9d936978017e79f8413ae4fe"
    $a1="9cac184d2cc227557bf672b3abb078a950408358aec3175864d44ec4"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f889e440a20c266a1465a46c857e15097bdd74c5677eea575363ba1668388594"
    $a1="f5168c85667a567430d7ad26ea6d4994a4f8c975b52c80f7d9c25d2178ac6d9b"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eb6bc5d2c16512dba428f109452ab6c9d45977d38cdd0bf681b1b29361ac6b7793c8fe7ac9fea7b37017728a82071f58"
    $a1="195a1be4260035e37ff4042deacef04ab5e629efad8f5fa64de929ae8f793f930f74edb463f775773af98ff78538e3c2"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59ddc1fbc4e29c4e57c7de1a7e8525a7e0d46fbaae4b4483668d7e37327adfc2d16910b87c42bd2f41a7c239365f6d60c16793c189c8fe6155e7886bee2c4723"
    $a1="3aa8ac9ae6eaa5b7cb1f732874cebf934f04a76337e81a2452988b5ec67ad0cb5f4f1b32229d20a187bbbb0b44be7fa8bd2abc98860dfa8c33378c3a597e3860"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_blaeri
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for blaeri. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QmxhZXJp"
    $a1="MjIzMzIzMjM="
condition:
    ($a0 and $a1)
}

