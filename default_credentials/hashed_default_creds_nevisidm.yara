/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ca4c50b905dc21ea17a10549a6f5944f"
    $a1="44c8575cd10d543dc1da875941b7dee3"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3c71cc99d2fc1c12a3d3e1b27e448ca612a89a1d"
    $a1="67bd5810ec8162548419905bc9769ccf95fe3a1f"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e2b7c7854abdcc42df3436106f858f40174d421f69d38c633a539828975b0b5dbfc62d98ebb1f071501144c53d48c3dd"
    $a1="0219e403de8f8c0b3569f8bec9cf591524639506a4b9313a790fcab11c79e2fbda0317d6b136f67949126dbe11be62bf"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ffee25b15c7d573aa51968c9d481d923982cb48799d1c2a43ee08171"
    $a1="f610f10883a10416ac1a27e1bf055dd8d6f6a7d90e4071789a1acdb9"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e8b9a6d0c9f6e51c265b9274709b76c7811be2a35b4d9a203d9274068c36b77ecb8b16f11439187aa5283ee81ce1d735edeb8bc652337b6dec6e1a13f82183f"
    $a1="a6262e1fb0c0d1f960f160febdeb9c8db4c106b4162ddffeeb2335b924185ca8943a6de7266a7441f4ab1abe364066124987e5690ab8682eb649263041157208"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="333c04dd151a2a6831c039cb9a651df29198be8a04e16ce861d4b6a34a11c954"
    $a1="e0cb800a5ccda4cb1b2ad7990de082aaa1e40e771898c0bcb28fcb23c261e422"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="48aad0545e3700894ed120eeea958eddc92f0fb8dfe7938fb109da50bdbe7b410f5dcae87751b5d99c0bd0dc4a03a069d8db23ca6af5d7672d97cd7a51e321f0"
    $a1="6ae29f94f9655f299dce9964c467e9f08addcdcde24b951dd00f454c138eae9217ba58f53e3a3d53adf4186f41dceb66aa71c6ceeb41b86db3a9c2c2d4217b87"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6e7dd38bc01f2dd5d18f898b77d6c59384bd32ea129d4b356120393aa76a81c2"
    $a1="ba42ac77ef8c2dc1630fd26b5f9bfa52cd26037649460f0b709bf5005949b3df"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f331b466b582a8f60e6088c98e57b08ab64db01abf40cc90c34826e4"
    $a1="b20a271233d223a5a78f423751110a33b782c4e97a6455d31fb3acdf"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8eded94961d8dd40135e394074be0aada36bd83a6f1ceec30fe509cf6610c8d1"
    $a1="21bfa6e54ac71a0c1a553e5d323e4affba4afc288073e1ee4047c438749ba085"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="036d97795c39019b373dd89e9aead59640cce2158e39851b4080c2215117180924cf1b83ddcbd34b9189eb380809812c"
    $a1="81a85f11bf623a5812e633428bd5de3a97be512bf05711ae4838e14fb694d691200499ea5a87c9ef8dcbd109f805ecc7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="741e0da10325acae9106891bf28cfb0d80ea1ef9938b2660db9c8e63242f48bd3cead5b0e18aa48ded525ef8135071b5a4b1294c630c48f278cc20f60211bf2b"
    $a1="ff7d60eccc07fa23d33bbef9701d2d163fb822d6530e82280c8c05ae298a82cdbcb4bb3fce63340a3231b837bc42abb57200a8c0a4d51eb38e8865b5a47b8258"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_nevisidm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nevisidm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Ym9vdHN0cmFw"
    $a1="Z2VuZXJhdGVk"
condition:
    ($a0 and $a1)
}

