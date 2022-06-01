/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="7477891215264c0dee229bf01a8287fd"
    $a2="2245023265ae4cf87d02c8b6ba991139"
    $a3="95489be1eb8ce69afbd38a8a86aac351"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="08b98c5731597d2d0b3c4f1c384dd9d81d6e36fa"
    $a2="dfba7aade0868074c2861c98e2a9a92f3178a51b"
    $a3="f7862dae84d4b04f84d46ea8ae0ea67458d8e607"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="57f3c93536420fc43451649543c97b66c63c45a415d6c789ed72ac5dfcef32081b1a506f22a73d92dbaf1671f3ce009a"
    $a2="37d7a199fa800dbef1b994f0aeaaef95504f851f594b54a5f833fe2ec755767dd9623685cc33a2860f953d7d0ef95a38"
    $a3="b972b3e3836c057362f312ac377b236b70efe347eb7c36ad5810142aa459f6fcf79e3066d95b91dab6c4d507d65b4b04"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="c52acea9f4d248db8681f58e4b8ca4d6058b1540da47da5bd7ed29e3"
    $a2="025532c1aa1197af9d28be763be3251832611db7cfa2116a84176d4f"
    $a3="8a0fd6a504596b4db8e51c2c0618553a2fbfa4dabc00ff04b14e0675"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="4757bddb41013106ee3c214365dc0e76fa960c33b336149dfc694fc5ea51d887b78ad2f73254fbe1ec840e30a7ad8349ea92ed0ede0c75f00fe52ddc7abace39"
    $a2="9fcffe1acb716f176ca73cbb1cfea77b1b9c8d904171efa19b2471e293149194010fd3ca56a3b9374d19fbd441854dd92d06563b4d7a14a8a566fb76e359847f"
    $a3="352e8d9cbd72cbe625f450060bdc0ddde545cfce4b52da9ea7d3b9823bf130f5bf9262d899f6ce756444f83f5e59331496c51699b40314c6b3757761de5496f8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="348260ed7e9266777cc0c720fd0ec7a6fd93707e25d70739633d182427792842"
    $a2="b79606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910"
    $a3="c497cdfb9e89265c0af6aadeffcf2c551151513aeeee36a145669b734b2e8d1c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="b92e437a5a8be1cf44e03be4b66de2fbf67e10431fcd3ad24f9b812b781fd7eec0bbe021c06577cdc50758732a82e8e2f48bad3de90321541123a09c1864289e"
    $a2="572d1805d672afb62249e016f90c350e3a9f834b65b1a8b2b40aa3c9e5d059e6224408d7c9114294e0e65ac0a707aad48eee61242fb14f820f22ca207e9861bd"
    $a3="8035e91023a1762a7449c9f82a6d78c3bbb66d45f8635e5d8f58b56f982a6c12e039ff09c59831867c70e4504a1a8b09a6179140ffda45b7319f246b1f1dd9f0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="cd73469ee28d14544db208a0c7e812f15ddca5e39963ca34f7c7104fff814f80"
    $a2="8b306df5215c0269425964de47d9c006ca0b069438231c2a68e9b4b535d81c0c"
    $a3="2e6122b8fc74b91de51c5f3be9a59b4ce575d9fc952d6f8ed5165b486cc6b69b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="0d7b5f8a5530a6a6f377a12d43c6a0365975f2210c7e2ed39ded7728"
    $a2="55a9b4860fe8d3ab31a726bfcd7175f68f0d74846131187d9f7751fd"
    $a3="1b295bfa304f37e3c5d0960e19c29832d7e3cf2d2088ebbf1eb48cfd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="4425654233dc3b9b486257bbb3fd854f682e35307ff3c86667d91fa070578236"
    $a2="1ea838694151cac8901271a9dd8fa6e5ce4202becae780bf4c04024d4f76695f"
    $a3="11458aa3f98d695bb3b1a69458847323cf5b764182fec35c00bac65ad524b705"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="ef9f2fe7a56347816490c1dae457342d990bc20ee709b9994bae91007749854f1c2e8ad32fd4038f1758cb929b5fdd75"
    $a2="9b815df57e54c070959b601385da424d2b7b1b9d55045e3e9af4bb2b11e563ddaf7d0070a343e8d5f7224d911ec638fd"
    $a3="d8530f35f614ef2f40a0f294dd9aa2a7d493535978a595bf063479de204b09632e14b489c902fbb31ac2772da93900b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="2d2d05bece382754aa772aa03c0f627a05b6310b06ba19038786e91aaf0ae00a9d360caaf9d3c46231d37a4bb970d1de30f29e95babc07cf25c78cabd0a8c0ed"
    $a2="ed8d212a4425108e64febf6fc56df6894eb6f8dd283f4adf5382de2c6193e3a02ef3c2c32852adb30fef787d66570369c909a651b2f4771f97238a14d49d562b"
    $a3="751d604e4af4e401161f72a9f456c8fadc9147a7cd2fd03a8f337ea7c37141c51e5a601f932993ca739b61733317a531986054ee5adcc715054ca954347cf6a0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_biodata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for biodata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="QmFieWxvbg=="
    $a2="Y29uZmln"
    $a3="YmlvZGF0YQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

