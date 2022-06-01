/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c11103d0027b062d759e79ed790ffa43"
    $a1="c11103d0027b062d759e79ed790ffa43"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6053fa8d58a9d1b674fc197fa9b12ab9e9c206b9"
    $a1="6053fa8d58a9d1b674fc197fa9b12ab9e9c206b9"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ead12ef786610814658fb8eff64a151bbde6a956e21e4302754a84dbb93dde46ca8952e17a0c93f61d40b6ac7211252c"
    $a1="ead12ef786610814658fb8eff64a151bbde6a956e21e4302754a84dbb93dde46ca8952e17a0c93f61d40b6ac7211252c"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dbb954ecb25f7f24f2e538004960fac8afa7cfb26926c918ea30af3f"
    $a1="dbb954ecb25f7f24f2e538004960fac8afa7cfb26926c918ea30af3f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cb4459fff9614cdfa35ea7300c2fd24132d71240efa5ead4b56581a4da3750472db10df848bd5b063e044d64c80316a63f679b491538b33767709b819640f59"
    $a1="0cb4459fff9614cdfa35ea7300c2fd24132d71240efa5ead4b56581a4da3750472db10df848bd5b063e044d64c80316a63f679b491538b33767709b819640f59"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="14408fcdc99674131790d7311784649636897036c340a2a15c82c8a60df95a0b"
    $a1="14408fcdc99674131790d7311784649636897036c340a2a15c82c8a60df95a0b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="67a5184da943e9fdd7353f98655a5ec12a8c1ea14ddfe0ceb74c70b9b1e992812bdb329a9aafac6b26ccd269b75921a56b14160ccb374604dfab3a81c35e4c7c"
    $a1="67a5184da943e9fdd7353f98655a5ec12a8c1ea14ddfe0ceb74c70b9b1e992812bdb329a9aafac6b26ccd269b75921a56b14160ccb374604dfab3a81c35e4c7c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d660f01b3c91789204fa16a9d6d281c52b7467524d0b577df194ede5829d30a4"
    $a1="d660f01b3c91789204fa16a9d6d281c52b7467524d0b577df194ede5829d30a4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2b92d529c5c32adaa80dd53668ead6642275cd1a6c390a64930a04f"
    $a1="c2b92d529c5c32adaa80dd53668ead6642275cd1a6c390a64930a04f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3f62fcd1a0266a63c61987cf35a4083aa9243a8d64c5772aa3caf0be1c61373b"
    $a1="3f62fcd1a0266a63c61987cf35a4083aa9243a8d64c5772aa3caf0be1c61373b"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1122a2e3f0d239d93ff35f517203de2b7c2d8b93d33596c8dd5ba283c1468e9c9adce1a8ad9abd7cfa0ffbf090fa407b"
    $a1="1122a2e3f0d239d93ff35f517203de2b7c2d8b93d33596c8dd5ba283c1468e9c9adce1a8ad9abd7cfa0ffbf090fa407b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="469182284c02cbfc6b34446a92ca5c9b5ee144eb494c3b04ae7f84c09762129f3b1dfb020a82b4a35fab49de4a1cd5ebccf6d2592ee8e53145e612d60a9f4f5a"
    $a1="469182284c02cbfc6b34446a92ca5c9b5ee144eb494c3b04ae7f84c09762129f3b1dfb020a82b4a35fab49de4a1cd5ebccf6d2592ee8e53145e612d60a9f4f5a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_quest_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for quest_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="VE9BRA=="
    $a1="VE9BRA=="
condition:
    ($a0 and $a1)
}

