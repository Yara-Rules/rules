/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a1="cbdeaeb2cf5b812c628b2325bcc4c560"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a1="59b7bc438df4f2c39736f84add54036f2083ef60"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a1="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a1="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a1="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a1="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a1="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a1="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a1="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a1="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a1="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a1="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_apc_ups_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc_ups_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YXBj"
    $a1="YXBj"
condition:
    ($a0 and $a1)
}

