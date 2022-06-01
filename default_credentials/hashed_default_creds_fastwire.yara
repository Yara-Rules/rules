/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="77aca988ed9d1d7f3ccae3eba8ce822e"
    $a1="8f51ef3b9040a527832bebba66e286ac"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eee4f011f1564dcdc28ee3ad1e6da6fded80d120"
    $a1="cef439e78636cdab99cd2923826c5065a0743e5b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="125ed130116c43fa22dc63ebd49b74cf79322af6c78f6f0b5b2f3bde9a0138617100a07bb08decac89d16330cd5605e2"
    $a1="52c20a6f7f43271e6489d0a1e243b576ac7ef37245f667bf66f0616409824bec4eeb3542c5e0799f242315b9c3df28fe"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da5a52db330368b70b9d417e31b08cf5a008f6ae0fb06e2ae5fbecfc"
    $a1="df406b93dec09623678e97829e11f9fdb0f6ce204da4c5880f6c42d5"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ce430ec96b8cc77d15429b6e49318d6c8c3084a7214227fa18a8a86f27a09ce2af081859c63892c9b72a034faa519387e1d9b4725d865e9a866120a2e5ff038e"
    $a1="b9f5306438d93f5ab53422ae35822449cad534355db57f47139841bef1d68c24190a68b0efb297bd4c36e8a1bb2ae302b24a35cb3d29657236a8b822e1c0c265"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ebb2df5d72722f2ac5809c0c4f006a25162d70bacea18a1a7d24fe6fb3f559c6"
    $a1="07f7ab476bc3a83fad639d34a012cb4a5f859441f0d24c11627ca96696839012"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="176cbb618d6875e597a7fa5e209b1d6ee4074ee899efc6abf3f797435e1067042e3c670016f3fcfe26232ef30dee6dfbd0765e4a162947d0c1a8de329b9a24ff"
    $a1="ffa8a10c6c548458f60e567eb13900ff18ef6471655ace0c325b391812210c5a21cec1ec3f3dea62163fcf82eefdfcc0f025ddf695f8c720eb423c495caf78b0"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dcaac5c8574a8a788d94c5ae3246f63bab016598f6e75f09563f146e994bb668"
    $a1="513dc4835af063d65b888b4af939a0fdf94f7908076b4cdaaffacee2c2e20abb"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a55bddffa65a6b6e581a822306c116b1c4c2c683736d1f93c7890eee"
    $a1="45f7d7ea8ed0aa7402864b27a4411e906b09d3ab302d2c8f0b0a1309"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9cbf5ac0a9a96b60a95a9f33773a2ac5fc11bbcdb76cb1e96452161cf61ea66a"
    $a1="adc51ed9923c6a9318a8e56cbfea00b4786cbedf36fefdd12ce660dbc105e504"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8b46697d023f1e379053b42ba6b30f9a38bfe50db731cbdf1539a9b52bb9faaa86e4b0a3d3b4a740ecec7babecfdbc36"
    $a1="1c331cc84ed6e9712c42ec5e710008c3af9a3112113a96e3939b1b83de5ffd62fb5f606cd14c0f26f0ec98d176a0bf53"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ab4661328aae5f4ce70daf98f71eedeea4d7f4bc5e1b4b122881471d57f40c7cb6ddc306ab2dee37ad2f290cd68b477937bd1b1661e1c56bc5dbe0d4b8b71754"
    $a1="3a6fca043737a884496c41aa3cde643952028376961f3e435867125356949ce0d4156eb83518e1f62ea15cccfff5b126f5e2accf23a45d4dbe5fcb5f93c44f1f"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_fastwire
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fastwire. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZmFzdHdpcmU="
    $a1="Znc="
condition:
    ($a0 and $a1)
}

