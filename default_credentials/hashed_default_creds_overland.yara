/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1c6e980e0eee73a9a9512439f56665c5"
    $a1="099ebea48ea9666a7da2177267983138"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e47b9b1021034a56b7d5f70d92d0481524e78f69"
    $a1="f2231d2871e690a2995704f7a297bd7bc64be720"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="73114c7a760f92362ccafc80b500ae704167906e9509d6997906df729b4f86e678dc8a9ae7a7f926874920b67b2621e6"
    $a1="f5889a6a118d1f3968a0216060e6d861eb3b2fa05fc5423674908d92a0c80c335750f12790fa95e03976ab94cdecca47"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9013712ed33598db5fd4ce9b8ed8709bc807fa71b361e9c7e2089a6"
    $a1="e0537f07091ae104db4a8b939b3c47b1b8c2f4f38c55ee45f871b22b"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5938d9afe029dfd7976b6a64a0535d4abd93801616424098b81ff72daa04cb1c24daeb6397ce04a542405513e4c35746756d328a7f21dd99d5fada7261a25441"
    $a1="8ea15870987d34972ee28de0e6b8ad0217970d473bb0414911753e8a1101cec81ba9f6b0db7fec16b2d0b9cd4c91337896ebdaa033b47955f620834761415c44"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c4b97afe643da8e91b649cfabdffe821d270de093e189e264b369c329aa3a82e"
    $a1="f76043a74ec33b6aefbb289050faf7aa8d482095477397e3e63345125d49f527"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ef3c14a1d14912c2dbc35856ee8d08de8b5cd143f8f2a1b8c236f7ef846756e630803fe34243cf58aafa705e03a99d688ea1985a116ad0d1ee2dacf364e3faf1"
    $a1="6554dad708a65bd7d3abee2d9c028e2e4c1319fb3ef8a752723b70afd572dfc408d3b1d0d19950f280d8772012d0a35209f5546345c3be1d3367fa34e9bb1e92"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5616213d19391447e21fd7a3119ebd9ebf17ef493d3760ef89a4a769b62729a4"
    $a1="b9bbb73c490b862e77461f5b12b60ae92c5460901991c39ce31b7da24f1d878f"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d3b41d589a345a9f032ec864eb83dcf994e92c42a7b7943e12d7a493"
    $a1="0f81b51cf2be501fff5405ce1426bab4fb53a8bc0089ad4e19fa38a6"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="afec5811ca4b60e82f6b4f88b484edd8420f01539205074dd897fe9003c11c8f"
    $a1="9e60db57b96a31d91a6e93b7f4416d257d0b22ab081e6b293e7d23301a9521fd"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="07bc09b5d98a45b3a068a1b342c86374b5a5be23a847e706ac5e7827e273fad1baff63eb5f68424efac7f596b5471f9a"
    $a1="420677fb158e8c3207566ddda5f7983239b89f99d2229fb03594b034cdc3d7f3a2253f202fe89931b7953bea6497ae5f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6884d4025cc74257c32e357331c3c876da1609b7009d612d0da5197881e101efceaba542ea7fe1d216d3886a972723ad3cda8865585c29bba6711ceaa23a9525"
    $a1="d887a0e79eb31a236584b5fbc521b86fb5fd317e9d5b381844d65da4e4f318bd354699208fd8f155f70e471e9a5048b815292fdc1f8b772d37410049a9cd1d89"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_overland
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for overland. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="RmFjdG9yeQ=="
    $a1="NTY3ODk="
condition:
    ($a0 and $a1)
}

