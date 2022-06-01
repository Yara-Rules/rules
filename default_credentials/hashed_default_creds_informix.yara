/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01b630fe8d185bcb47005d162f7e0b4a"
    $a1="01b630fe8d185bcb47005d162f7e0b4a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0acdd939d26e9f3024dacd6a11d931644b7d0d13"
    $a1="0acdd939d26e9f3024dacd6a11d931644b7d0d13"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1c4e647f27cf854985247bd1e2ee0bfe76de492c3a1420efd7870b0d688c117f749708c80d5da6b2e0762817f5940785"
    $a1="1c4e647f27cf854985247bd1e2ee0bfe76de492c3a1420efd7870b0d688c117f749708c80d5da6b2e0762817f5940785"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4a7364a1afedafc3c9ff5eacb8f003b23d2b4db4e82b4a3dea5ffb0a"
    $a1="4a7364a1afedafc3c9ff5eacb8f003b23d2b4db4e82b4a3dea5ffb0a"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01389b520d126884faf146cb0c871a9879f75dc643c26c98fd2a32b33d8661cf4d230b56c00420ab82d87847946e387094505a3325da772e059e3b61e4a89830"
    $a1="01389b520d126884faf146cb0c871a9879f75dc643c26c98fd2a32b33d8661cf4d230b56c00420ab82d87847946e387094505a3325da772e059e3b61e4a89830"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a0b98d79f7b5116d36edc86c0452f131319a854b059dcd9256a8783bed16e517"
    $a1="a0b98d79f7b5116d36edc86c0452f131319a854b059dcd9256a8783bed16e517"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="60d311816dcf7f9218372d3d7742511380f53f1611c85666df0b309387618d65729213cc9155210a6de7ca221bcbdbe7a66676c8fd341378cf4494a336f85ddc"
    $a1="60d311816dcf7f9218372d3d7742511380f53f1611c85666df0b309387618d65729213cc9155210a6de7ca221bcbdbe7a66676c8fd341378cf4494a336f85ddc"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="984d99a8c2b8f3d776cfb869cd2a91c98e2d9ba158bc159c4e8b82d0492a3294"
    $a1="984d99a8c2b8f3d776cfb869cd2a91c98e2d9ba158bc159c4e8b82d0492a3294"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20109b2608f27cabfd15c663b572882fe09a950b85f97cf7f7a65cb4"
    $a1="20109b2608f27cabfd15c663b572882fe09a950b85f97cf7f7a65cb4"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="015988b9774e7f849c10b45df2a914a1d079828bea31292dcc8514b10508110a"
    $a1="015988b9774e7f849c10b45df2a914a1d079828bea31292dcc8514b10508110a"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9075e698b7643bc46fc8113dc316c5a837fc915fd4b46b5f362701be8f7745accf1d447c548845535f1646e46eda4778"
    $a1="9075e698b7643bc46fc8113dc316c5a837fc915fd4b46b5f362701be8f7745accf1d447c548845535f1646e46eda4778"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1f414a83225eda150b66441d061e8a0c5481846726c0d721620a3691572fc73dc759c405dcb78e47adaeb9f1fba9f378bde507a99dda232589712f35a19f095d"
    $a1="1f414a83225eda150b66441d061e8a0c5481846726c0d721620a3691572fc73dc759c405dcb78e47adaeb9f1fba9f378bde507a99dda232589712f35a19f095d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_informix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for informix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aW5mb3JtaXg="
    $a1="aW5mb3JtaXg="
condition:
    ($a0 and $a1)
}

