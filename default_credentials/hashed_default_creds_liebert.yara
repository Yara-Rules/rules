/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b7f93cb17ee3de8a948bc222ee207adc"
    $a1="b7f93cb17ee3de8a948bc222ee207adc"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dcc6c1d719425492778be1b0b81752146d2d65f2"
    $a1="dcc6c1d719425492778be1b0b81752146d2d65f2"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="24d472ef95b6482dc059621f2e0f0526300195932f99146a05bc7d3a5b981e1407d3598593ed8f67dc6af5ee98328d0d"
    $a1="24d472ef95b6482dc059621f2e0f0526300195932f99146a05bc7d3a5b981e1407d3598593ed8f67dc6af5ee98328d0d"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="25dc310bd8760c5a1b6bf8bf105fb6e87a477cebdce5c9be6150fb2f"
    $a1="25dc310bd8760c5a1b6bf8bf105fb6e87a477cebdce5c9be6150fb2f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1a1742fef019f9d520ce8eeb17d9eecb14735cf0e44518e2b8cc828760e8b8987139dcdb62783530ad4bee70057645539a6d7f366b123ebfd97c57f5f57cb24d"
    $a1="1a1742fef019f9d520ce8eeb17d9eecb14735cf0e44518e2b8cc828760e8b8987139dcdb62783530ad4bee70057645539a6d7f366b123ebfd97c57f5f57cb24d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e015982059c8bc8e42fb8739200091343e3218d1c80b53f087a21f0780bfe38f"
    $a1="e015982059c8bc8e42fb8739200091343e3218d1c80b53f087a21f0780bfe38f"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aefb7dbdda9ba4718c2cb6b0a795cdcbe8a2d77b3d58420e684c568815d03597f18d7012f5cbc356031d9eec0fb488c5da1a1ac6fcb50635c46202009dd1d229"
    $a1="aefb7dbdda9ba4718c2cb6b0a795cdcbe8a2d77b3d58420e684c568815d03597f18d7012f5cbc356031d9eec0fb488c5da1a1ac6fcb50635c46202009dd1d229"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="95d539301bfc53cced586ddcd21deacd7409afcb10d2fe2137407110b68f14b0"
    $a1="95d539301bfc53cced586ddcd21deacd7409afcb10d2fe2137407110b68f14b0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="35c85b10912bb4f466cedf877e63091c434812b66a0e6b34036aaffc"
    $a1="35c85b10912bb4f466cedf877e63091c434812b66a0e6b34036aaffc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="46d7f9545447fb8d501ad7d20ce12f219993cd99be6856836f6a0245df155360"
    $a1="46d7f9545447fb8d501ad7d20ce12f219993cd99be6856836f6a0245df155360"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7322badae51ef5cc2401b9ad02938bd77b14d13a6ee75cc7076c8104f83d64392ee5de9157839556dce80246fd7fb6b"
    $a1="e7322badae51ef5cc2401b9ad02938bd77b14d13a6ee75cc7076c8104f83d64392ee5de9157839556dce80246fd7fb6b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9d95c357580759ddd936324a52d9027763edaea366bf6bd2a2ed39708ca5fbbd52001c38ce4e8d5f86f44faade09a576775d02c3c0876edf998d5b5aee9069c4"
    $a1="9d95c357580759ddd936324a52d9027763edaea366bf6bd2a2ed39708ca5fbbd52001c38ce4e8d5f86f44faade09a576775d02c3c0876edf998d5b5aee9069c4"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_liebert
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for liebert. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TGllYmVydA=="
    $a1="TGllYmVydA=="
condition:
    ($a0 and $a1)
}

