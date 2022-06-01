/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e61e27957059e5bc259f1d4a864d2e27"
    $a1="e61e27957059e5bc259f1d4a864d2e27"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d55f200f850fbea841206295eb9ed59e9369156c"
    $a1="d55f200f850fbea841206295eb9ed59e9369156c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eb0c628670f5f51cf994a81f97d7d492dd85e23ddf3b89f51cb2ab70d95d646e3ebd8eeb6bf56fb60377a5f832a04d6a"
    $a1="eb0c628670f5f51cf994a81f97d7d492dd85e23ddf3b89f51cb2ab70d95d646e3ebd8eeb6bf56fb60377a5f832a04d6a"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c6459316ca8efc42fa5455ad474af1b353f963a932df56d287022736"
    $a1="c6459316ca8efc42fa5455ad474af1b353f963a932df56d287022736"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c5289262a2dd33c53c6d8905f57b5d957bd60e1f4d4cf4e5a6823cdab4b8fa4df6b7418af6be7493a14286b674bc3d12a961900835e7ba9d734f1bf0f2c7c32e"
    $a1="c5289262a2dd33c53c6d8905f57b5d957bd60e1f4d4cf4e5a6823cdab4b8fa4df6b7418af6be7493a14286b674bc3d12a961900835e7ba9d734f1bf0f2c7c32e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a4504e28aa94444e45e863c10375d676ad522b17601ea633b48928e6969a5dc"
    $a1="3a4504e28aa94444e45e863c10375d676ad522b17601ea633b48928e6969a5dc"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d0053284fed98afcec92bfbad2bda4bf58fcad95899ba2c70f6981d454a2ca847d7f55278fd05be1f6c5fd13228f09873b86607177be6e4fba3075483c1ccac4"
    $a1="d0053284fed98afcec92bfbad2bda4bf58fcad95899ba2c70f6981d454a2ca847d7f55278fd05be1f6c5fd13228f09873b86607177be6e4fba3075483c1ccac4"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a5d5c68c067122876d9119be44e65d4c95d9e5634a8dd2b12ca54dc9170f851a"
    $a1="a5d5c68c067122876d9119be44e65d4c95d9e5634a8dd2b12ca54dc9170f851a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="abb9f30a3d7b30dc88fd80afe85dc9aec931cfbcfb9e7da153445e93"
    $a1="abb9f30a3d7b30dc88fd80afe85dc9aec931cfbcfb9e7da153445e93"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a6d84bff090c74efc2d8bd2186449d5066849447857f86e600081c1330cf22ee"
    $a1="a6d84bff090c74efc2d8bd2186449d5066849447857f86e600081c1330cf22ee"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed9a753f586338d24652bc9b686765d247bfee1a2cea89a0a4d42ef20ac186f1159ddd601f191f0ece7cbc5fd1ba2ca2"
    $a1="ed9a753f586338d24652bc9b686765d247bfee1a2cea89a0a4d42ef20ac186f1159ddd601f191f0ece7cbc5fd1ba2ca2"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="91026640bf22bb6596c215a764554a0eb1325cb01bfd71596d33cac1514965578a313eda1f8b48a4e9637f5e27577a4cdea8ef211086b8e28a4e4ab3e77019ba"
    $a1="91026640bf22bb6596c215a764554a0eb1325cb01bfd71596d33cac1514965578a313eda1f8b48a4e9637f5e27577a4cdea8ef211086b8e28a4e4ab3e77019ba"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_telco_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telco_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dGVsY28="
    $a1="dGVsY28="
condition:
    ($a0 and $a1)
}

