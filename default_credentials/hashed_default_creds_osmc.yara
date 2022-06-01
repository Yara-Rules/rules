/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b89f9407c1b9536224d7f8add901c6c0"
    $a1="b89f9407c1b9536224d7f8add901c6c0"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="444f498da953ec0313a4eb5fe993d410dfd4e71b"
    $a1="444f498da953ec0313a4eb5fe993d410dfd4e71b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd3c55039e3108a10d3ab32e362ac9c78a9b5f962b198b81ee1d684503580396e76aceab20ac13da656b173cb34fd863"
    $a1="fd3c55039e3108a10d3ab32e362ac9c78a9b5f962b198b81ee1d684503580396e76aceab20ac13da656b173cb34fd863"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1a098a7d89964b844f638c3d9ce12a8bc347b42e56d237097a8154a0"
    $a1="1a098a7d89964b844f638c3d9ce12a8bc347b42e56d237097a8154a0"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="67726cd98cc5ad4db112664ffe2942cc9c8ec559f75d2d321c32db88b9a31af0c97abb8afa216da9c3c8131769594a8b2f39d438e75b3a76472585253b1d0143"
    $a1="67726cd98cc5ad4db112664ffe2942cc9c8ec559f75d2d321c32db88b9a31af0c97abb8afa216da9c3c8131769594a8b2f39d438e75b3a76472585253b1d0143"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c4ebf8e6c66f6a8f14f9d655c8fa7db06e4dcea9dcfd3eaa81843e44e4f78c34"
    $a1="c4ebf8e6c66f6a8f14f9d655c8fa7db06e4dcea9dcfd3eaa81843e44e4f78c34"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="74ddf5061180e757b1d6e52b8247c6723cd3beba3ad39f606611c46a42acb48258e86df477eb699d8929e7d6d8b32f42339b5bd3f20942f042463e8224810405"
    $a1="74ddf5061180e757b1d6e52b8247c6723cd3beba3ad39f606611c46a42acb48258e86df477eb699d8929e7d6d8b32f42339b5bd3f20942f042463e8224810405"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6770953ce8a65186626a1a09b9cdc2ee0d9813716569c158bc7bb7ba7013880"
    $a1="e6770953ce8a65186626a1a09b9cdc2ee0d9813716569c158bc7bb7ba7013880"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="957c00f5da89d3c0f111c22f36aa0e1a58c6ce68101b0f9f5c887540"
    $a1="957c00f5da89d3c0f111c22f36aa0e1a58c6ce68101b0f9f5c887540"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="de54545570dfd1da63b12384e5439e70776b9ab1412b8cd67857e8e4e3864d03"
    $a1="de54545570dfd1da63b12384e5439e70776b9ab1412b8cd67857e8e4e3864d03"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da18d049be7c22110363e1c90a68f6daef0eeaa11266ee3d134e599f979b19fef65b4f36a3381bd350b4fdf7bcd92d88"
    $a1="da18d049be7c22110363e1c90a68f6daef0eeaa11266ee3d134e599f979b19fef65b4f36a3381bd350b4fdf7bcd92d88"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb4847400871f2f03125d1819e0f68fe6ce045a3475ffb6a789351cae00fdda2b9f6bba94cc1737ce419fc83c1fb91798de7a91bb7da64da70652d4354d034a3"
    $a1="fb4847400871f2f03125d1819e0f68fe6ce045a3475ffb6a789351cae00fdda2b9f6bba94cc1737ce419fc83c1fb91798de7a91bb7da64da70652d4354d034a3"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_osmc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osmc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3NtYw=="
    $a1="b3NtYw=="
condition:
    ($a0 and $a1)
}

