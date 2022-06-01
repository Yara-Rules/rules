/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="257c2d1a0423a6a7c108632a8f963932"
    $a1="667f90b9ddee2049cd27685ebf10db90"
    $a2="257c2d1a0423a6a7c108632a8f963932"
    $a3="947f01331ab0db1b086a4fc91e7bda93"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8f198fad85c1ade2c1fa575158726672d789eeea"
    $a1="08772351b878d7d36631955c017fd53079c2445b"
    $a2="8f198fad85c1ade2c1fa575158726672d789eeea"
    $a3="ece362775003aa2cc452ed00d3c1fa5e0f7bf77a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
    $a1="288ce6530319077f60476ac0e066c777c5551c67dacdb48af81cc65aa09adb3622e4ec3bcc495487094ef3442bb98602"
    $a2="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
    $a3="f87c1ebc04f901041f18dfb7d24bebc6d45e1cbbb2d9f005605e47afbc6d5d56356e3ee5f7762c5373219eb2ffd6554f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
    $a1="583ae0e505c9e885b69d5affb67d103507b20edb7d2e3bb65928c441"
    $a2="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
    $a3="cd67b76f75f4577b8c0f9541bb4658e24a34ee90a9fbe4f3a46bed80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
    $a1="3da2b7056f0d39bb20a39339bcaae05851870a2385844b7347f7cb262c7fedf3e77c6604caa27ec58044e83e780c9b5c299622469f86c6180ebb7293dd20b7a8"
    $a2="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
    $a3="dc3283f0dcc070a4434448ab2bf8caaa3b546bb32ea44a1173c7f7fb896d21c087786050eef69ad3e7541b546ee7a8f61e163a5749de0089502a401e51f19b9e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
    $a1="4743e040acfb96f4022126d636a3ffd5a41fc9080c21ce0b11e7116a7804470c"
    $a2="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
    $a3="92563d2553584ef62ef475e3600bb4acb6c40ebd3ba5262e764272a05074a7f2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
    $a1="3d94aefd59330b06708147e027d556f6edcf975da2cca1ff3ee0d1a77c5cacaa8a78c8abca0ba6167d2695b75e272552803bc582193bca3592f54946c16e9f39"
    $a2="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
    $a3="69baf6e415c26242d39904368c39f644eeb36eab71912c8aff38911aabab0ddc03317e9c93d209a8306a8789a51a6b90abd5e04a4454de5afdedc95314ff45c9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
    $a1="d1301d264ca4b80b488d1785349ebe7e9cab4f7ce4866c5c2ee7870986a2a79e"
    $a2="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
    $a3="a3866d06cdac0a0e9d7286439fa10193cc2f8a9991444dff01a5c1b8955ee428"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
    $a1="8c58aaeb2dd12ac365f66c9d43cdd1d1cbaa9ed1166c8777b3973d8c"
    $a2="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
    $a3="9976702f28a05a97104c42c54485cc5ba9934c2678cfb760019f2b3b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
    $a1="623c5a5d9d7a4ae4f669448e0294f976cb09b58536b4d45d3917a593ce34d6d0"
    $a2="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
    $a3="24af0329dd22bcdf3805f1fdd579b30681ebe2c4c0b89eceb528158b64cced67"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
    $a1="4beb0cb4b86e5fe2ae0992939d94cae2659133a7fb645e875999c5753286fdae94717a16b53fbd5af6c99011925ea61c"
    $a2="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
    $a3="1d243ea48da2020cde4f09bd8d38a01876f099d53bacb37cffed21309dd399c9cd57a4dfa671c06ab2627c6eb5e23f99"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
    $a1="4e94e157726d1fe780cc7ccfa21937152e6339d93386e3425afa5471afb29a36ff0e7c41bdd87fe0f0ca090c1ab61d2727c5934d60bf5d03e86bbf91ac19a28e"
    $a2="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
    $a3="92412f3f01247436f1201394d18e7ad4ed5d4e378f50e01a0604051924a9470882b53f8cd3818e0d736a2a013d7dd4099c3ee8bcd8b38c3f9c796fe4a915589f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_comcast_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for comcast_smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y3VzYWRtaW4="
    $a1="Q2FudFRvdWNoVGhpcw=="
    $a2="Y3VzYWRtaW4="
    $a3="aGlnaHNwZWVk"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

