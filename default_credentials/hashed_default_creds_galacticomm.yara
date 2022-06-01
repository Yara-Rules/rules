/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f033f04be477a7337dc9ba2574d4743"
    $a1="6f033f04be477a7337dc9ba2574d4743"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="70b72a815151321507f1851ef5b44e22339cd49b"
    $a1="70b72a815151321507f1851ef5b44e22339cd49b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8d096c43043f44bb12e630ed368598f5386597c3f6292f78deacdbb1de3311efb3be6694c2ab6d5787ee8e5e455aee95"
    $a1="8d096c43043f44bb12e630ed368598f5386597c3f6292f78deacdbb1de3311efb3be6694c2ab6d5787ee8e5e455aee95"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="91e7c34a031434f5dc7e1fff0e8e175987899d54d8d7505ba26d3896"
    $a1="91e7c34a031434f5dc7e1fff0e8e175987899d54d8d7505ba26d3896"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ca70567b61825bdef15255ed5841c1960e584b6488c3183e0c82e10c02f2d342cbbdc5940b2554c1e6f47b4b2263d45094a20b4aa3136c2c46f65d524b2f42b3"
    $a1="ca70567b61825bdef15255ed5841c1960e584b6488c3183e0c82e10c02f2d342cbbdc5940b2554c1e6f47b4b2263d45094a20b4aa3136c2c46f65d524b2f42b3"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e60808574c8f8a4937627143a6972c785f4b537063d5b6e0c8ff4619de6fef63"
    $a1="e60808574c8f8a4937627143a6972c785f4b537063d5b6e0c8ff4619de6fef63"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d04114cf2db95aeea46ba3cc57cb1e0494f78355cf28b92ec02b1bb68cbcad8b7ca3640827f207754488ebcff8a63a9ffeabc22e2c61ce060b7e6538bf166a76"
    $a1="d04114cf2db95aeea46ba3cc57cb1e0494f78355cf28b92ec02b1bb68cbcad8b7ca3640827f207754488ebcff8a63a9ffeabc22e2c61ce060b7e6538bf166a76"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a081adbf29d497c40569e453fbd92bae951f59b35b2c8ae475b1d4e08238c6d4"
    $a1="a081adbf29d497c40569e453fbd92bae951f59b35b2c8ae475b1d4e08238c6d4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2279ccdbf917746c41cfb08324c225cd530ee5c7f2fb9a938b9218c"
    $a1="c2279ccdbf917746c41cfb08324c225cd530ee5c7f2fb9a938b9218c"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5f96c8935c9e4ff4bba826abda84e811701d674033c31efeff5fde1f9e5f297"
    $a1="e5f96c8935c9e4ff4bba826abda84e811701d674033c31efeff5fde1f9e5f297"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="167f8244658367ae1d587fdd792555edfbdbc38dc99e1802d835d55dccd33d8cc051817ce39d1907e60791adb21dff54"
    $a1="167f8244658367ae1d587fdd792555edfbdbc38dc99e1802d835d55dccd33d8cc051817ce39d1907e60791adb21dff54"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1b227174b406db0a4f07fd700d219af684c54d4ba7c9d9dd14b4c93d2186580366e42665d34666ff0314a813cfa6d03b21e8f591db2c212116a234c73d74361d"
    $a1="1b227174b406db0a4f07fd700d219af684c54d4ba7c9d9dd14b4c93d2186580366e42665d34666ff0314a813cfa6d03b21e8f591db2c212116a234c73d74361d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_galacticomm
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for galacticomm. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="U3lzb3A="
    $a1="U3lzb3A="
condition:
    ($a0 and $a1)
}

