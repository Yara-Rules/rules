/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6979a1aae6629a465809ae5809c1aad5"
    $a1="6979a1aae6629a465809ae5809c1aad5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a5091ad3d591af7eff8ea3d73be5b068f229965"
    $a1="0a5091ad3d591af7eff8ea3d73be5b068f229965"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="78adb963118a6b884c705fe2d78804315dee8bc32e83863d6a7fb482da08722f0c83cda5c273b4113071627e841a1834"
    $a1="78adb963118a6b884c705fe2d78804315dee8bc32e83863d6a7fb482da08722f0c83cda5c273b4113071627e841a1834"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bf38708bbfd108f71d4e225ad124e7a8437ec83e7020ec92206d08ff"
    $a1="bf38708bbfd108f71d4e225ad124e7a8437ec83e7020ec92206d08ff"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4be8509a64cb9a7319309eda69d8ea7ac73b747309467c95bff4e0dc52892fe3c08e9abfaaab285d564519f5395d5b46a998134558ae54abff99547cb61d0c7f"
    $a1="4be8509a64cb9a7319309eda69d8ea7ac73b747309467c95bff4e0dc52892fe3c08e9abfaaab285d564519f5395d5b46a998134558ae54abff99547cb61d0c7f"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="61e06ee14cc6e7629a9e82a6d97eddf683d14f90c7e46f10d46981e437f7699b"
    $a1="61e06ee14cc6e7629a9e82a6d97eddf683d14f90c7e46f10d46981e437f7699b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f7048ee929f2ea8d4c3e02bbd872bad3d1ceb51fd4b2e9566d0b8c180a493c91b30a1d5fb9088c1153084217d27e6bc615079efe6147c53fff94a672765a57da"
    $a1="f7048ee929f2ea8d4c3e02bbd872bad3d1ceb51fd4b2e9566d0b8c180a493c91b30a1d5fb9088c1153084217d27e6bc615079efe6147c53fff94a672765a57da"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="895efb8f3cdbb394f6d70e95898dc01280b992f9a3589a8301d0b7122e1f6dfc"
    $a1="895efb8f3cdbb394f6d70e95898dc01280b992f9a3589a8301d0b7122e1f6dfc"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cfbe665e81e732f9992cd71dedfef5784cb5ccfa419816bc930c812a"
    $a1="cfbe665e81e732f9992cd71dedfef5784cb5ccfa419816bc930c812a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ce0dfdb152de7fdf187917d88b8f1530f6820b594d47a3d3e28100ed9d94db6b"
    $a1="ce0dfdb152de7fdf187917d88b8f1530f6820b594d47a3d3e28100ed9d94db6b"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="958810aed7c6dff7c26e425a9b2a346ea6fbd3dee4d7ebaf7642b959020ee1004d17d5a55a21c8ab392b3c5af97056f5"
    $a1="958810aed7c6dff7c26e425a9b2a346ea6fbd3dee4d7ebaf7642b959020ee1004d17d5a55a21c8ab392b3c5af97056f5"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="06ffdade2c104f07520bc3d8f2822d5f48410e77ed91bd10bd0ea914d0daec7023cd96bbfe338b88467922569b7a428006fdf3b1337c438456427e4531b01edc"
    $a1="06ffdade2c104f07520bc3d8f2822d5f48410e77ed91bd10bd0ea914d0daec7023cd96bbfe338b88467922569b7a428006fdf3b1337c438456427e4531b01edc"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_globespan_virata
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for globespan_virata. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="RFNM"
    $a1="RFNM"
condition:
    ($a0 and $a1)
}

