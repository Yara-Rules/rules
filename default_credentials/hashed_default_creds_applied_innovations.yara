/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b34d70bee747e7d6341ff9f03b318ae"
    $a1="6b34d70bee747e7d6341ff9f03b318ae"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6a87c09459170d72585c168169837af76c870cc4"
    $a1="6a87c09459170d72585c168169837af76c870cc4"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ba214cabc52159fa3e4da4c89e33124c74596c795112f1a691847c11d6addaa7600186419f47a8b367ab1de496fa55af"
    $a1="ba214cabc52159fa3e4da4c89e33124c74596c795112f1a691847c11d6addaa7600186419f47a8b367ab1de496fa55af"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="68dc33ba37cc8c646e413e57bab0b498bee375bf1ba4ea5371d8392f"
    $a1="68dc33ba37cc8c646e413e57bab0b498bee375bf1ba4ea5371d8392f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4c0410db0dd79433438f9e19950dc9ca5e49f822010e3d63f30afd64e7a25ffd7b1839319819f9c9a1c4c56a15ffdbd96958a12d8c11afcc56b59e7328ac791c"
    $a1="4c0410db0dd79433438f9e19950dc9ca5e49f822010e3d63f30afd64e7a25ffd7b1839319819f9c9a1c4c56a15ffdbd96958a12d8c11afcc56b59e7328ac791c"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3608e4bd0e693177369e17f48cdf750eb962b86aaac1bf6b50c7a46d52f7d94b"
    $a1="3608e4bd0e693177369e17f48cdf750eb962b86aaac1bf6b50c7a46d52f7d94b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7cc5f24d15ba4a33efa4bdf7f2ec730a2810d77dcff37fc85f96ad8f774a6f4be551b6463d15acf295f2d808e87667a60c8a9c2dbcea6a3bae06d02b609e92ee"
    $a1="7cc5f24d15ba4a33efa4bdf7f2ec730a2810d77dcff37fc85f96ad8f774a6f4be551b6463d15acf295f2d808e87667a60c8a9c2dbcea6a3bae06d02b609e92ee"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc02ef56193d205e8bd829b602cebedaea4d83c55cdd3918c96f1dd16c5c1ac4"
    $a1="dc02ef56193d205e8bd829b602cebedaea4d83c55cdd3918c96f1dd16c5c1ac4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c6e98a3471e661a64c7c72cfef362f1a2fa735162b711e1e827940d"
    $a1="0c6e98a3471e661a64c7c72cfef362f1a2fa735162b711e1e827940d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cea0cc4da813d358fa257acb2f04834aa59914824d807a72d63240694496df7"
    $a1="0cea0cc4da813d358fa257acb2f04834aa59914824d807a72d63240694496df7"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc471d8ee5472e526907d8aa92bec785d881ecf0c50835a045cb38c1583d770746cb09c658b2448ba2d5280ff35b0bcd"
    $a1="cc471d8ee5472e526907d8aa92bec785d881ecf0c50835a045cb38c1583d770746cb09c658b2448ba2d5280ff35b0bcd"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="beacd481df0fdd80e82571ff2e3b2ca8614295670cc809e052fdf0c4d0d301608b37578ce9b92e74c3f0c62833348a47c453be4a771aee860bfd16822f402d6e"
    $a1="beacd481df0fdd80e82571ff2e3b2ca8614295670cc809e052fdf0c4d0d301608b37578ce9b92e74c3f0c62833348a47c453be4a771aee860bfd16822f402d6e"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_applied_innovations
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for applied_innovations. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2NvdXQ="
    $a1="c2NvdXQ="
condition:
    ($a0 and $a1)
}

