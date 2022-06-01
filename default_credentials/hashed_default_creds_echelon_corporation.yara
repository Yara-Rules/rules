/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d53d62056b878f168d5a560edd7b466b"
    $a1="d53d62056b878f168d5a560edd7b466b"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f6c2c83a731a9f1542a4afbb45ea0439c4f45ca"
    $a1="6f6c2c83a731a9f1542a4afbb45ea0439c4f45ca"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
    $a1="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a9dbfdebc83bb85be8204293e1ac7ab6aab8e6f07b2521f5ca608196"
    $a1="a9dbfdebc83bb85be8204293e1ac7ab6aab8e6f07b2521f5ca608196"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
    $a1="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
    $a1="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
    $a1="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5756d18256a7d25364cc470f20e1d507b17ed879fad7fe484b9140cd8f4034a6"
    $a1="5756d18256a7d25364cc470f20e1d507b17ed879fad7fe484b9140cd8f4034a6"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
    $a1="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
    $a1="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
    $a1="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
    $a1="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_echelon_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for echelon_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aWxvbg=="
    $a1="aWxvbg=="
condition:
    ($a0 and $a1)
}

