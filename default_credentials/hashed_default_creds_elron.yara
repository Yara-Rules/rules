/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b2d58692a9818cc1bc6a1914173564a1"
    $a1="48a365b4ce1e322a55ae9017f3daf0c0"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ea0d244f6be819ff692c90a5a1b8dc607681f9eb"
    $a1="a159b7ae81ba3552af61e9731b20870515944538"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="78639df3be1d3f46cc7e87416f223419effd0aa3d6213a93d25843bcb8a55d13cbe63a15caa493bb8f442aa948b01954"
    $a1="da9b3e0e3764965ea1ea652d0d504c40c14ffb05d26a1eadda70833bba54782b7e427a6c75003c8c8ecd96ffea88cdb8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="870c1a7be9fe6162dc2d17945bddec9dd99d75dadbef149068794fcf"
    $a1="02f382b76ca1ab7aa06ab03345c7712fd5b971fb0c0f2aef98bac9cd"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc52c702e721b98546f625ebec85b514f4ff51b91931de4db43ea15e2b5c2cb250aca633de7a3735f8152091759ce9f40348beb5751a33ce33c0ae226b923197"
    $a1="f6235735d47e6ccc82cc743bb0f4578e2f21572003d61e62c719fd9345101031e6aeed4b2ba8b059916b3764dac90fbdb6a0a88fe5fa7d7f483013a63cc089e0"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4bc65a6aac470f214132fc1520360e5b8d2af6f01750dfd3c7b661663c974cc3"
    $a1="d577adc54e95f42f15de2e7c134669888b7d6fb74df97bd62cb4f5b73c281db4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="057bec4f7dd5c8046eb79629fdbf2825a3bd79b618014c47d7e79b845ac8506962b9bf77f2f7cc8cdbfb807abcf515479458a48da9c31482d0f00cf3548c89bc"
    $a1="da668ac94129340a5db3fa3d91341413bbfd477fb277272bbee5122fc1ebef04a33a76c01ed027ea066b3b7f3819f487ba6dfeaaaff9a326b49c39519ec7f474"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5bbea18fdd5c29d3ac964a33ca963bae69c34a7c7af0ebea671b7ebdfb33e307"
    $a1="0eac0ddb08d482a2cb9e297e499508a9e4f4b229229d43a6f2f78d129ebfb203"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5d0de3f73cf2ce24bee71a4bd81c1c93db065b3c8c71e0533b4cbd20"
    $a1="b3c613fcea10ca76dab2bae1ff0054b92d46aead56580e60898b6f82"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5cf90dda74684293aec44e147e6b3a5786b925b4ce322fe4133c25aa51c3c006"
    $a1="78377bddcc5fb7199a28965a65772069ce9de533aa0b7ac7c63fde2e2cc95966"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e8a6cde497d1208e18a67189cf95299618b7c43ddaa2609e8bf0b7d7ed81acfa0506c6540c441e145d0620edad49a291"
    $a1="f5276408a10d9c8841ac9fc0a3002818b5d55ef8065c3dca312cf764e4ef7213ae21d3f35423123de91061a2ee8a0bb5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fcad9dd50f758a37f879a8a5c292705efa892c777dbd4cf7b768b2149753f415d9372a9c8bd56ac13d9f49386780229f14cfcea3bbda4fb5f5d83eff64063bf8"
    $a1="100bcb6ac8e9f7bff18df1d6f6d0a41e7dfbddfdd55971bdd087c6c8039e02ae42ee60dcbc967ef03164de21fa0374152686c3c322f6e1bf56aeccc43fdfe3cd"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_elron
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for elron. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="KGhvc3RuYW1lL2lwYWRkcmVzcyk="
    $a1="c3lzYWRtaW4="
condition:
    ($a0 and $a1)
}

