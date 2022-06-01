/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9f4c9a5b8093e185dccb689aa0ee6fe0"
    $a1="3aa9dc55f225e35a57cd28d5795370a4"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="adfc6cdae8c6972b7f6cb38345a4a3b115db3e3c"
    $a1="d3496bacbfccf29ed15e82ee541ef76f2f5b5c23"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7c007479b667ab9a808550ee73ce9818541251ff9fb12540b867004ef659eabb1f12b4702e59f66d4e81f9bbc32e43c1"
    $a1="e315184486f32c9d7c3e0fb4c8235553db7c564c8a32a89c2181410df8e5535d3b207e8351ae8f733a1c128423572a58"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3f27742157314e793fc9daf55c2e7db7e4980b806acbc69b27ff372f"
    $a1="983a708e3df2c377e2b68595e74aa1f8fe699620e194f38530c032f0"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="880a2c02839be9d25ad8f43dfda082deccad74166f4c1407900650c316f2aeedda3718abcc23ea01a44c065a37b892ff9c6ab7cc5baa8e601167abaef7d6236b"
    $a1="4e8bb8235e4bddb3f0de834507d50bc731578547a5dc0b18320bd0becca2b3939d7f14db19066c6393b6328be9ccdc558223c23213887dbd0c8be76ba909915f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="479c139143a076ba9152751a266ee3817fd5ca70d46b143b25ee46504bd81928"
    $a1="75fcdc79c50111d864ba4b79fafc57e12938f22c679916d67a7a5825cfa5b63a"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="14a70e1680168058dab8e17a804182d1ce7ed4e58aaf0462b370c4db80bfab0d43ec07690f77f45e94a4bae11521c68a3551e2421541ff0928205bf419745012"
    $a1="f08602bc6c930eea3995af11a78fc4e6d5f90ebf6d8f7c982f0b06ab7c5a15fdb25ad67a92783e46d5bc3cedf32f6da05d867d12a65b398fd6b223fe0ce69f16"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="93571f9d80d24cdc326318ed1f1ed535201021119d5fd10ebcb5cfb99252a2b2"
    $a1="7e788f0611575df9c2802da9bc9353c9bedc108ca9f1bb683ea10928b8203479"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eba5eebcd9f4a69b235ae240a1e8bb2b0a24ded6d1cab4e8761c214b"
    $a1="a7c8fd1ea03160e668f85d92adf4f3783ffa0d4315c141f0ec449644"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d602706f945af50ba5b0a4669ab4bdcd11f65dcca072e8cad2bd64367c88c7bc"
    $a1="ce34707fa4039f51d576c654abdc0eeb01450307fcf238eed7a45251c3e75d31"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99d30ebf55582c8702df271b343564eee72cf6b63845c345dd3c14eea232a38dfa18c914b817a800d18ea41621b2350c"
    $a1="36dcaaced3983ec40e6e96dff0a2727094f20d7b86c3fcc77d36999d2fb11578a7bf81a34f57997e0ebc04fc55dfb468"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f4c61490c7b5a2c42d0774585174dce370c4f0139bcb0169d91a55980eb19dafe9dfea349440e5ec2b28f7793b141c95d36f9ec99171517b13e30f284144f11e"
    $a1="e58ad8d988825bd0074970c8248f7b9fc54ea44f7d6256ff50e41fd3aa5ac007eed9c1e8040d527f6bbee242b377e1d533406f1bd73c15c5799c8c8e4d3756ff"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_inova
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for inova. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aWNsb2Nr"
    $a1="dGltZWx5"
condition:
    ($a0 and $a1)
}

