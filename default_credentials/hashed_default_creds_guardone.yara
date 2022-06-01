/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="cc5b1e379c9d7827238d2efd043509c2"
    $a2="f3eca8a95941360f5e1fca5ffeb04917"
    $a3="cc5b1e379c9d7827238d2efd043509c2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="7a7b91151636e0dc8db99c93eb06ec6fa8d1dbc4"
    $a2="e7f645c7d47b345d70c5bea9fbb41d94bbfafbc6"
    $a3="7a7b91151636e0dc8db99c93eb06ec6fa8d1dbc4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="6df6203da3bc5d7ee3c31d4cfb2a625381b677c7966268314a2dbe00fe400464a359f9bf7d2ccfd1aecaca2b4b3412a4"
    $a2="183c8b5575ad115092768178d8f3d3c98c54d01504662bbb5381f74105d2ecb82e8dae6254a4cbc2b78688dc03b77484"
    $a3="6df6203da3bc5d7ee3c31d4cfb2a625381b677c7966268314a2dbe00fe400464a359f9bf7d2ccfd1aecaca2b4b3412a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="04ce1fd1988903ad3701106413b25d49468fc7c4562918538edc6fd6"
    $a2="a7d8eb0a6e01add341f25df790b1d7258358daa90e1c5f1925248e53"
    $a3="04ce1fd1988903ad3701106413b25d49468fc7c4562918538edc6fd6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="f8e387cedef6ec30192678c258b1a7eee29e90337a570eb40bcd8139f56e166c1e4199bf72a70f719dc2d4109300744d4a10eca9f6b979135a61a27ec420b63e"
    $a2="0d74e7fbc3640f1ededab305ff0009ca90db7330e01002f6220ed66c319fd736a6752e0538867535b1488dcbed178ea140a20844d45e32ecfe21e8bef49a0240"
    $a3="f8e387cedef6ec30192678c258b1a7eee29e90337a570eb40bcd8139f56e166c1e4199bf72a70f719dc2d4109300744d4a10eca9f6b979135a61a27ec420b63e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="69fb5444c9427eaa8a70ce32e5ab950b9a81920fd7640a04cabb65c46c55d0c5"
    $a2="fb259aad25841d6cc5f0fcb3576e11a33002802a09980190488895d6239a9e39"
    $a3="69fb5444c9427eaa8a70ce32e5ab950b9a81920fd7640a04cabb65c46c55d0c5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="8545495a00f90df3fd67024713f7764f1a1a57290e791cff49d2e3ca2917442d26eac358d0279075c60ff1d951d889e92dbb8d9c5c74daf4ec686fe5a3669b3a"
    $a2="41965264f09107147961b6403f12de5b1d8953ec7ee249e917acab68724d6c5000c8726c50b40e093a0881eeb4e92c7efec4a9925fab561294bd96092bbd82de"
    $a3="8545495a00f90df3fd67024713f7764f1a1a57290e791cff49d2e3ca2917442d26eac358d0279075c60ff1d951d889e92dbb8d9c5c74daf4ec686fe5a3669b3a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="23ca0413cde6e0bd25bad7939c03ae138381f759855bb5d5ef73e7f0b6cd293d"
    $a2="51dec5e150e324ac88fa9664d19521e335f32bfb0b343a2053eacf2575e75145"
    $a3="23ca0413cde6e0bd25bad7939c03ae138381f759855bb5d5ef73e7f0b6cd293d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="bc775e50b91b96a8b602da52e3e43fb3d74c1e7a217683f60a5cb447"
    $a2="7262d70b6c09248613dd148955d76f203a9e519eaca4aa1f91f928f4"
    $a3="bc775e50b91b96a8b602da52e3e43fb3d74c1e7a217683f60a5cb447"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="7e5184f08aea8115aed0c70e297c5a9b618aea4efe96f5fd87fce169dc020f6a"
    $a2="5e4d2874a8e089b5180b497f41a141122145b624ef72bde5ea9f78a4f8e9036e"
    $a3="7e5184f08aea8115aed0c70e297c5a9b618aea4efe96f5fd87fce169dc020f6a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="b58da853115eb388c5e9210e21fbf56aa8aff19a5b4a03cb989afdea87eb01db936947b1a57cb25c1897d56f3596ab28"
    $a2="5f0168368ba48f6fd4464d8fc0ec4f21bba83fa2f7de57b0b6c2bcd6bde90185fc93a6a44ca59c4d6e15c44e4ab8a60a"
    $a3="b58da853115eb388c5e9210e21fbf56aa8aff19a5b4a03cb989afdea87eb01db936947b1a57cb25c1897d56f3596ab28"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="89ad8fdd72a8909f03f5fb53e309d26dc38a55d240620ab9034100e60c410edcf0c6f57771bad72f889f4a1e4dee4704741ec2082f85749540beb69cfa87f9e7"
    $a2="15a4b64a7d06755f56d0e82eeb2c3f4de7ee32f1f6c16647e04e43a71096f598fb4ed44a7f0c425289c4ba3c9d7bc8cae31a50e123a43a949878da526b833239"
    $a3="89ad8fdd72a8909f03f5fb53e309d26dc38a55d240620ab9034100e60c410edcf0c6f57771bad72f889f4a1e4dee4704741ec2082f85749540beb69cfa87f9e7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_guardone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for guardone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="Z3VhcmRvbmU="
    $a2="bi5h"
    $a3="Z3VhcmRvbmU="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

