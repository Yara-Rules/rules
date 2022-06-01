/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c6179fb4e2c1138afa123a87a8d5351e"
    $a1="fd16427eee902f9e4e13a3621d9ac4db"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ccdf87d62ae4218e4f64f940105951f7a0a9ddbd"
    $a1="773b81b445938aafe1747d7f433880fc8d531683"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6076f333edef23c401fd1e10ca7e7042e2cf3bdf0f7e0b2cd438ca749ae015c893a8e9c47152939813f68c6aa9fe0750"
    $a1="83e38f641f936ac169870158b6d196f2323f16feb2dc6e1987f8baff4400779dc83f7211c6297b88046cd1acee448e51"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3cda3fea6fdfa32c2114cc6a41b00c30dac9d941cdf0965ebcb83b6"
    $a1="ff91bd66de760b7574c79b093e99ec9ead972bcfcbc80259561e0da9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e82a0b12edbc1de6a225de1c542586a356c539fd4208f230cc7302cc5c3107a87659dff8b3a0097396389acebc3c6401b962509464a6b7bef82bccf3f274550"
    $a1="546041c1bb85813fc72b061f6aabbfe7b58635391490b1f4b3e9f260c1531aa2913b765ace1969608228f7c54b356c2085173cfe86adc97c6948eac7f6b9828d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="acd6b2aa4d95bdd3879b5146f2e19fb383366bbe2829a80f98595aeb0347955f"
    $a1="28dd6c64a860d565465819cc04371dbf5489d4b57f89f1edf3f6d0f8d2e384b5"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc41e431fac045f3ed6543dbefada68bfcf639d47c099778321ab5148a9f74e08081581f0c91a2300c78903f1d57c16f2123eaa34a6d7342e9a1cd5604aecf59"
    $a1="6462f2c64a1382bbfa3973dc9527c3cce7ad1c4d616c64114bb3ecbe3a9f5077da0569949b9658b1acf6ddda67bd28f21029d46704e13753498ed61cc75a9827"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="152b0b5901a13eaeaa8a65f242d62700385d408d59e1946c46c3d9873e6d1ece"
    $a1="3570b491ef3028908b17d37e63b8ed84ba81df053db5f1a7c7d6298d5c730b0f"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="823cd505006e0cc9e255635f48e3f3c7d6d763363078d714f5feff1e"
    $a1="1a26d79123e7ad8851c6dd154000166ea9b5fe2f3093aaed0f6e3530"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="454e9beb105fb6c3a6d6b9a83210f7b758abc780bddcd5bb3d37bfd80484ec06"
    $a1="7984550cf0df965abbac7a655b1cb51e0db27e9f5b20ed27f15772a95f7e4b94"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c481e21469702f0726e4b047d94dc759fb68e72d16db2cc90a3cf21aec62fc0e9cfba9aa92f71521ac484581328f9d9d"
    $a1="3b109743d123aa714871566b503b978c728ca1b72776941fa8774a43d23778e17b89f2f1882d655e6d1209f91186bc98"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="924e728391cbb8f8819bfd968672715e2b81e289857a46d831130c442e65dac8da730c26ab302e890eb9388c0887c1922d0f10c1d05af1ed593081a350a2d81d"
    $a1="2b4f96712290edd94e1e0212c3aa629748e1f8f8247665840361fc484eb655b533bad48052581ecce6b76dd5767d2432bfa492fa7f8bdcad1472c3b937e6ccc3"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_medocheck_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for medocheck_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWNVc2Vy"
    $a1="bWVkb2NoZWNrMTIz"
condition:
    ($a0 and $a1)
}

