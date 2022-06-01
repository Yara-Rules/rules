/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e33a9b0b06aa0a01ede70995674ee23"
    $a1="2e33a9b0b06aa0a01ede70995674ee23"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2ec10e4f7cd2159e7ea65d2454f68287ecf81251"
    $a1="2ec10e4f7cd2159e7ea65d2454f68287ecf81251"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e71fed31722985ecf8213ecaf2d63bb8c71e6f64bdde6c01c5914e9570cd813cc5023361b38b6504ff60d2b09b8e54cf"
    $a1="e71fed31722985ecf8213ecaf2d63bb8c71e6f64bdde6c01c5914e9570cd813cc5023361b38b6504ff60d2b09b8e54cf"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e3b7cf16b9d701dd4dd4536095731b1ccff0e9a5a00a68a7ec30f00"
    $a1="5e3b7cf16b9d701dd4dd4536095731b1ccff0e9a5a00a68a7ec30f00"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="43192475f95e3820fe441daaff7c84d9b73ca3a5afc7309ae03f783151b6b0976e4d68cd990f97ad0d65ca640d35a407199d6d7510f1dff5477b8cfce1531475"
    $a1="43192475f95e3820fe441daaff7c84d9b73ca3a5afc7309ae03f783151b6b0976e4d68cd990f97ad0d65ca640d35a407199d6d7510f1dff5477b8cfce1531475"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0afb00138d8e73348ec1fe41fd3d3a8fcbd90156b263bfa5791ba0e095f42cfc"
    $a1="0afb00138d8e73348ec1fe41fd3d3a8fcbd90156b263bfa5791ba0e095f42cfc"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1d21043cd59511c4762c11ea171e5d0595e65129efa7f997958976d4047a0824aba6505daeb5a480af2f133aeb8beff62775a96762319e28266e9a39e7999ede"
    $a1="1d21043cd59511c4762c11ea171e5d0595e65129efa7f997958976d4047a0824aba6505daeb5a480af2f133aeb8beff62775a96762319e28266e9a39e7999ede"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7722ab1ca9ff316ecd58c7accf5697aae367c4da184c0f783fe215b278ee85d"
    $a1="c7722ab1ca9ff316ecd58c7accf5697aae367c4da184c0f783fe215b278ee85d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1f3927c5f2a425ca4160903044fbb3a9a6b703a77a0071a4106dc0d5"
    $a1="1f3927c5f2a425ca4160903044fbb3a9a6b703a77a0071a4106dc0d5"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5985b182b2b67a822ecaad7ee44636333e2310b57533e7b9c95e6c08a7c7932"
    $a1="e5985b182b2b67a822ecaad7ee44636333e2310b57533e7b9c95e6c08a7c7932"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e492b64edc61513302f0289185580cc0328a19ab96ec876dc5592643b0ca0c2904eaa94b6dc3daaf19891862059b4c20"
    $a1="e492b64edc61513302f0289185580cc0328a19ab96ec876dc5592643b0ca0c2904eaa94b6dc3daaf19891862059b4c20"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5d69ed22fc52c139e82a80cc63208adbd2a31adeaa357f5e901beb63fccbc714adaf5df724f845ea783cb91baf574c146c85c13ee2d8ce40745f06a2a65441b9"
    $a1="5d69ed22fc52c139e82a80cc63208adbd2a31adeaa357f5e901beb63fccbc714adaf5df724f845ea783cb91baf574c146c85c13ee2d8ce40745f06a2a65441b9"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_adcompletecom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adcompletecom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWRtaW4x"
    $a1="QWRtaW4x"
condition:
    ($a0 and $a1)
}

