/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0194dc69729f1592fc9e442596f55830"
    $a1="0194dc69729f1592fc9e442596f55830"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1645c067bb5aaa0b40dc346e5afb853e559ab3e2"
    $a1="1645c067bb5aaa0b40dc346e5afb853e559ab3e2"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="354e2762cb1981256970955effe084db746b5e41169db01452e2da88f0ec518f70b18a5de9961624075c56dfd52dacc4"
    $a1="354e2762cb1981256970955effe084db746b5e41169db01452e2da88f0ec518f70b18a5de9961624075c56dfd52dacc4"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="44ccebae9da9f551d1222ece8b18d50e70ea4ab42472229307577368"
    $a1="44ccebae9da9f551d1222ece8b18d50e70ea4ab42472229307577368"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="05ef6e81d1805a3e2f045afb16463102ee6338ddc02b5c89cd5e029ffe7b38f0d20be158940ec035f8528e9783937729ec71958daa4a80604eccc77b1e76651a"
    $a1="05ef6e81d1805a3e2f045afb16463102ee6338ddc02b5c89cd5e029ffe7b38f0d20be158940ec035f8528e9783937729ec71958daa4a80604eccc77b1e76651a"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="458a6e44e631c1080436a21e73a681e04fcecef7768feedb2b0002fe6e4d9024"
    $a1="458a6e44e631c1080436a21e73a681e04fcecef7768feedb2b0002fe6e4d9024"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8f765e0b2c9063d4360f60927cd783190c0aab36bfb8f4de60006860b1f52b64cb6d7b59bb7d96e2cbeafc86572e5b284cf43edf917fb97b6cee50c9bf4ef900"
    $a1="8f765e0b2c9063d4360f60927cd783190c0aab36bfb8f4de60006860b1f52b64cb6d7b59bb7d96e2cbeafc86572e5b284cf43edf917fb97b6cee50c9bf4ef900"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe53f356ecaa92ac93d5c5a615a3e47e5dc8f783e6a4f72b261a0f261003e90d"
    $a1="fe53f356ecaa92ac93d5c5a615a3e47e5dc8f783e6a4f72b261a0f261003e90d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8f1d53ec21fd8673b9b2be2db4054d0aadadb8942ee980555c4400c9"
    $a1="8f1d53ec21fd8673b9b2be2db4054d0aadadb8942ee980555c4400c9"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="79f94a2bbc86bc6b3dac27793cf574d3d9733f31d689721a191d3d9efc93d696"
    $a1="79f94a2bbc86bc6b3dac27793cf574d3d9733f31d689721a191d3d9efc93d696"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="262ebc33bfdf58bd2e6537dba1c34f3fa7c528a5e560e3f7a79d90a5d44ced9bf76cab8a0cb34a73e735ca1c8b04efca"
    $a1="262ebc33bfdf58bd2e6537dba1c34f3fa7c528a5e560e3f7a79d90a5d44ced9bf76cab8a0cb34a73e735ca1c8b04efca"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b512bb3767004c6f6adcd9e9cb4399483b26f035834d1d7427ef3edee6ca5d3be8f2f1de3265a1e44f4ff644e7733e9ef13361c72649d3d8fdbff688d546b7c9"
    $a1="b512bb3767004c6f6adcd9e9cb4399483b26f035834d1d7427ef3edee6ca5d3be8f2f1de3265a1e44f4ff644e7733e9ef13361c72649d3d8fdbff688d546b7c9"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_jd_edwards
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jd_edwards. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="SkRF"
    $a1="SkRF"
condition:
    ($a0 and $a1)
}

