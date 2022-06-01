/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4600bb8b66b6a2af771fbb0566732196"
    $a1="398ef13bb16c89da50ff2d17ec2e9e2e"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c35bf6e2b2bc7397ff9f2321c39ecabd9043f671"
    $a1="6f66f1a36e08a70e25bb15f7c6d739ce83472dab"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e8744e7407cae08f9170caf620309cfa1ddb1807cc9f0d497e0b03098ad3a63f6633f9509b0a2ce5203c5218fb438382"
    $a1="6c9f709376bc7e12a85c675db5f0af675ddbac325021de19cc1cf7543ebfc7e4489ce3fcd075a52526f70a9c63b6d639"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f9944cbb94a0c0a2b2bf8a6b718ed2f4d9a8346b32c739c221a1718f"
    $a1="260bec252c0303fddecf39ad22afebd350e49a96300ddb9c280ebfb1"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="25fbbee6fcd8bf82005c2bd26de781c81060d780cfc4629639634e5ec647c71a7ed4094d51b387b1d82135aac539042b35a047ed0955d3ce4a59e262e9c0f3b2"
    $a1="98c2f891db63d6f2c0b925ec72d005b59ea25a8817da9387bd16890666180bd7dc9cf818374b949ea33ccbec2d51271fa9a6a8613d5a0b9652d139781f13b59b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="51b57fa2315ff3308a2fa19b79c6682e7449ddc241eecc900180d064c16a24f0"
    $a1="e8581b8e80abe1d9d8417292f0772a6515618ada70b6c8b7be3a130f9b273b3d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="afd1f93f57cabb1de66da1abd14628d2ae2bf9b2c5c5eb496dfa19c9ebf6153b0ffeb01b96aade0dc718d91307aec78a124ca450b66070ce146232d402843b9f"
    $a1="02eb805bb6f27654bd1ed7d9879e2736c8a759a71944db2081828472450bdd998187002ca1f1f8395365699204e3424158e648016a16484461fb97102c5f5e85"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01e9f1dd98151f82714350a2c4e5537b519e017cdb24b9d8ecf9c25d82b90792"
    $a1="7773143d6f688b61884dd6709de4a4e3d8ec6968b15dfcefa11c3d4cef113d2a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fbbab0892e4437ccc7d46d062ed777d2616802bf313480da4a2f6352"
    $a1="b6fc0ad96d39def6ffe8297153fcbfb5631c7a1d5b2de79eb16e66c7"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bdb4ac0899250d3b1e82ead3c77ab3103870d1ad81d551a0c4c6a440c850abc0"
    $a1="65cb8399e1b0c707af3d3309028e39317742c1bb123c4257c1d9019f9da1ea00"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e619b85b927015fe24086cb9b22540eef895d6b4b87179bfd9d4911d90a388ea6594cb13f811bc6e3b86d8e15d1046db"
    $a1="eac570c2e6e211425a60e32cb04ec6da7b626126dc7bf1b8aad33ce166d1b9f2ba83d6354a430d461ee0bbf78a6c3bc9"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eecc8c5c5c8268bd52440a00183fabec33ac6b2763214b19da54651f8017339d05c0f51dd02783bd4d3846147e192ae34062618c00ffc1a2c10248d43c6ee182"
    $a1="11f8ba115294bfddd613264d0842061bd124ba8442facf3fe7b0f75a59ad32ef0caa2fc50b653106afa4447baa0ce0078a55d7d6ca37ef96b2cabe79d56cc196"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tiara
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tiara. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dGlhcmE="
    $a1="dGlhcmFuZXQ="
condition:
    ($a0 and $a1)
}

