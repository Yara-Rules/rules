/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="352c5b820151ecb7412e3492373b6b1a"
    $a1="f8976d7778c70a12a6ab8d82a3a1e706"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6f54d151a69c9eeab330ef0b085bf62f08e1117"
    $a1="dec92378430ea646ab990932dfdf550f2e1c2882"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0ff95eb4231cf9597a637d687c3a73e7e26508dae50a7b551f9504f9a3cb1fc1270787d2912477ca83bec4dd00c20ecc"
    $a1="18831487ce39551b439095ccef32c8919b11ce12453d11845bc69db5e9e0b5e3f86aa216b406af95f5159adcacbe1428"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0dd86c1eb1645cc43ea738d02b3977e9cf4ba85905d4668b31d9e9ba"
    $a1="2a1a6b7738e0a5f459b026147da6aced8acec43d5fd784cf7a800459"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8ba5c19a95974328afc1e856c2c15cb9278453433ad44985dcd501e56f9acfdf95e4cc1edd1b83a2df359abdcaab35c1ba4dc0918641733c6b153ae6c3b872c3"
    $a1="97a38fcd6afd9b1f06093ebb718d8cd30c582c61341528eeb1712cb04a12dd5b92609fe45ef312b5d1f2049c3a77ca3da444fe8d2e890b6cf37bd0ae1376d4ca"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1c172b325c6dc1cdf786c4e08054652ee10ad7980e734642d30468c61929c3d8"
    $a1="37cd50bae5134bee88aabc828f0143379daca5b0770cf4c2dff424bad7fca66f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="66d50e4f1fede8e36f3e240363bbe4a9fbfe919309dfc486c731c6ab6501f2a93193994357cc6e5212d63099130595bf9d16c4f0e686c357ffe94cd096d0e9ae"
    $a1="8b6b5cfacea86e407550e3712bdd3377a5105051d3828299534ab19e5434680288753c5a65adea6bc9f5a0e1016f7db73b83cd2e5631f358bd9dcdbed7b1f810"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0832c8666f225f948d035e92421cd69df40564a00abe967468ebce97f4840ef7"
    $a1="1e6847563766821ce5d47b2d772968290e28e5d71d1619749795e60e43c056ef"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1530373591e46c4439b25a06b232e6b4e112fc7c05372c30b4590778"
    $a1="f7a36a8807752f1028ccccbdb4238cb1ded5e24eae285b405e733298"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c5d709800ee9c8af4f30112c787ddf0bcf89ea5bce9262ccf80d1de493095b2"
    $a1="41aec15b9816e4c6d6f36f251633a57cffad499265b673c00d30d41b323f63da"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac9367d2f40609bace83c499e928ebbaeacbef76bc2e5ae5e81cd25b79966ac36fc47ebc0aac4f28c6f1d9c1b0320db7"
    $a1="29ffe8dfc4f2e79ef5f64abac8123a0a37c5dbe5104f986f56f2bf191041c49501b8fad99a32c692a3e2addfa03c2aac"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d588bd9e7ce98732c4de05d9a3f4304a3b85658ae5a5b51c9fbfe29155ef6da9d42fea20e2c4017eecd3dff440cbc68473e35e56aee47371645955e22fed24cf"
    $a1="fef5c52d529b768b94d6f78cb8e74328556bc7fe6242ff051ce60af1117bc9ff1872303067fd1d0fb6735223f7bd00ed59c58631dd246d8fd724e745e2756ed6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_stuccoboy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for stuccoboy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c3R1Y2NvYm95"
    $a1="MTAwMTk4"
condition:
    ($a0 and $a1)
}

