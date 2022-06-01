/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="afe18ed979afdfc8b7f0f6e657481f2c"
    $a1="8e8ad5bd55ccba73a679ac720dc08b8a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b69a64655a47c8cd16cf25861604830aa20b2325"
    $a1="ecfe34975c3a148d8add6b763e672ad2c9183482"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1e36ea89d247187ef3b14575b43f69c00b8d57a430153aef9afd15afa50c8ce240d84d0a3f135bae0346b74947f3faf3"
    $a1="38c073519ffb52e35501d9bc6d365a50b78b5a9b0395c9603fc37d8354b8718e64598ceed5bcfca0ab1546289b2a4bce"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9b2a5127af200409d86d1c6a9ae60a0f77c7d009f0bad609148ab9f2"
    $a1="29c809e9500fe9cda2f28b4fc0342fd83e63babc3a3ed43d49680d1b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6bbd8cf74e7727ae177dc83a74f957c9f5f4f24d06d8b51bfce6f39080cccd64f83cdfcfe1bff45666463298a9f382185b892b8cb658fba894eab90c94f9d544"
    $a1="47ec0b882ceb3b00906576bf0c7b9ff11684a48cd4fb4241412461b11ca620311cc667edd9b9af868e945ad66ffdfc880f6db2ec71102becaf410088ee46a67d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="234b5b671f805415ff7f3d26e37f78d1e40ea60fdfa5f61dce7624662afa7307"
    $a1="ca5eefeb706f0dd49cc433d89e9a32ea2d697632a04f0b86a06639f6b1a3c509"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="46f1d97852823c7e52ad4594d2b90cc2872d20578aca45692ff66b31f836a4fe2f214ed485429eee8dd72894a87f659fcf60b0f1462d202f0a00f8ae6d80b08d"
    $a1="8dcfdfac6ba0ae53b9b8b5afdd7d9630efaefa495b094c02c93af898c09431bf0e73a27d46e14996a4645658b1bcb2917b4d5183475332f719435fe83ad3c932"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="43284b59b64013012d7db7d5a6f702cc9a4c1166c2cdfa1d5e322c27ed9d05c5"
    $a1="dc8c87d0750eeea89c73128745d3a8207be731e9576f938e6b4789b7ff2c3106"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4fa0e6dbca1713b9a603a442b486695d269d56b18297d15035fbe474"
    $a1="62a1706ae91f1222ecae6d34169de186dc788325bcd55ade97407c29"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0532c8b41fe70a3ef2db7874da2b0398f4313882498adbb4718674676085bc9d"
    $a1="3bab7ecbf3cc409b88632c0d2c75f757e83313986f52b3498662a0123e8db3a0"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="583b231df453bd0a71c72f24f95fa19df5ac3629da17281df33145f3331213c43a7dc7b4481b58967431e63d79be6302"
    $a1="25f6418375b2d7125fea13bf096ec3429d239faee52394f73ef5d1b65b30bd0b068b3d6c0551a6a0b64b767dea51d8a1"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9c2fbce30019a5c0e4403dbceaf9abe2157d15bfdfac01cece8e7c966a127bc7067fac64d83a18f6b3137dfb1ad7f64ae0d2bd8f3c006dffb232e1b118b48dd3"
    $a1="8005cbbea90f003347b5ff08b97f1888ae8d2d8a91b93364c5646d789c3c6e29a86a2b4f22d8ebcc050ef194780fc954c84a1606a05924b7339ed62c3f462127"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_opengts_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for opengts_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Z3Rz"
    $a1="b3Blbmd0cw=="
condition:
    ($a0 and $a1)
}

