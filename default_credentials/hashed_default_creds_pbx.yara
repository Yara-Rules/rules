/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9f9133fb120cd6096870bc2b496805b"
    $a1="abab585edfb59d21ba713ff22be739ea"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c95ee47689a0aaec70c3eb950244657722c69b1f"
    $a1="db4ae75c98c49a313335f3ab3e634efe380540aa"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d7d4375a6045ae4b2dd32d6ccf53ee632c2d858cc5e67b2292f60e7e497f3f22efa1093e67ff66301ef64633437df096"
    $a1="d9007f3215dc7e388200e1a5c8c59f2481a7ff99735090964ac2c9ecd3a25dc2f54bc41079aff431ff09328ea4837b18"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="09fdbc623941c03d3cc3743c3f4923873e75ab6173375aca0500e2a0"
    $a1="eb90e1a292d4fe1f529dc54825471b629b53b96e2b533ddf9b317d8e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="03e27e1cb5c4dc29a516e09233b4ab6d6521eb98d2da9be0522e197798149f9be841dafc8833c431f295d6ce1d1fe6beadaaa1d31d726d227f0627c82757664b"
    $a1="ee8f488ab280448501a7522004cb8cd26f29a662519717986b043b812d6475c977c846bb04b03ae90e8182100862b5d6fea16833ea7c6c7f40cf6c16a7a640d7"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe9bbd400bb6cb314531e3462507661401959afc69aae96bc6aec2c213b83bc1"
    $a1="042f83bc95908fb79c847ca651ceefdab5be1274df956efa0a67b427f68d7d9d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e61e21ceb5bc71f78b38263da5b67fc43356d4496918503d44af171fc8b80fe19d144524370712c245f5a71a217ef04e65169dd934cf3685d9af46017962bba5"
    $a1="ed01ae8b43d770e67b5fc02e5944f8f95b234aa560d800e5514d54757e93b9de6a0032bb02b292e53c356481db06af63c9c14189c81169977ccace271c65a698"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cebe32cdfd4b0014d09ee07bdb2f8816518d0599798bb30b9a303bc1c663af70"
    $a1="f4ee5c4e0ee0bb814b56556defeb5844c00b57d788daef6c55b9be301f31f18d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2012e43628843a91e7188cdd08486c8b10768aca107aa7af995974c3"
    $a1="48594ff9a82c1790a20fda1632a672b5e82d8d3fc8f1966283987d4a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6bb4c8e14fe4dc77a7a27a5d75c181cffa632c0c2907086c0f67fb9a55016b96"
    $a1="7257ee9b283f8079536ac3d0eb2e966b127875124b5aa45c6fff5e54759e7a19"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a742726566f6d65b11330667491a565ca4f74afa94ff04ef0e13b98fec6b50ec9efe4f779d45f90ce883367841ee691"
    $a1="06f43f361da27725e96bdbfe0216a143dba6103a09d625140bbae64554a87495c7c6f67496e9e3abd1b676b7ae3da13f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="00ec7004fc7306dcdb8cda65db82cd35a68b6c9146a2afc84e112c97c71f8e016fbd113fed86326fb3787dcb13274b25e3f909c58fcfdcd13c18e82905f1f464"
    $a1="81c677288c3070c810025f7de9212f2089d9d23917c49cb791d368dc086d7ba348fc2f11a88855e6f6a48a6e6528f10d7476759c0a51a169cbe0ba167c9785ff"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_pbx
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pbx. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dGVjaA=="
    $a1="bmljaWFu"
condition:
    ($a0 and $a1)
}

