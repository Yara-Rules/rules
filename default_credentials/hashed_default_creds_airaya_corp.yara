/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="300cc7b38300332ce2abf2777e5f33c4"
    $a1="300cc7b38300332ce2abf2777e5f33c4"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="950e23b53f84c4dd9ec1234b08deb8f587ce4e05"
    $a1="950e23b53f84c4dd9ec1234b08deb8f587ce4e05"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f9e229947ad542524619c7c253c5e30f2735f2b62099d43dbd932abb78f32716d2f683afdc2ff3c817ba2246ae3a66cd"
    $a1="f9e229947ad542524619c7c253c5e30f2735f2b62099d43dbd932abb78f32716d2f683afdc2ff3c817ba2246ae3a66cd"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b5ad977a934216340e7af8b4353f5f92c5f96f74101e0098e753f978"
    $a1="b5ad977a934216340e7af8b4353f5f92c5f96f74101e0098e753f978"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="85b09c5aabb8e42383a1acbc7a7f468bf86f64f48790fd4f87f61efc9f54b91cadf5804d9be927cd87eacee265cdc0db46469ec3495da9cd71098b063cdf06d1"
    $a1="85b09c5aabb8e42383a1acbc7a7f468bf86f64f48790fd4f87f61efc9f54b91cadf5804d9be927cd87eacee265cdc0db46469ec3495da9cd71098b063cdf06d1"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e39ca4051f140bf6ef6e95f4d14eb39c34713bc6a8867463078a73abbebc1e12"
    $a1="e39ca4051f140bf6ef6e95f4d14eb39c34713bc6a8867463078a73abbebc1e12"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5f7a4b2115c9555498caa7e3dcb920db55ed55e7c7365c6309985a2bae2ab785682e32be6e5eaf31dcbacf9b3db09633e64af0c675897ff2494181d5c2744cec"
    $a1="5f7a4b2115c9555498caa7e3dcb920db55ed55e7c7365c6309985a2bae2ab785682e32be6e5eaf31dcbacf9b3db09633e64af0c675897ff2494181d5c2744cec"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b21e098b84e8f4b386c2fadb236ccd2e6b289aabe3b0d802fd16362e249994ae"
    $a1="b21e098b84e8f4b386c2fadb236ccd2e6b289aabe3b0d802fd16362e249994ae"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8cab0ddbbffbf83a4a183b44ec014429f525a356b70bdf6d5551966f"
    $a1="8cab0ddbbffbf83a4a183b44ec014429f525a356b70bdf6d5551966f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="665e2ae58fa172efdbf2596e00b069e4ec384d2baf41fda46fd90e331f61497c"
    $a1="665e2ae58fa172efdbf2596e00b069e4ec384d2baf41fda46fd90e331f61497c"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="edc3bb91ca5640c94ecb2e6b34664fe76706382d93d457d5b3a3415257881599f577181613cd8a9272550eb76893f377"
    $a1="edc3bb91ca5640c94ecb2e6b34664fe76706382d93d457d5b3a3415257881599f577181613cd8a9272550eb76893f377"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a773241ecd38f3fc34602c0a58d0d16dd40acba244545e2e93c4edd08b4aca47a2c658206809e04630519efbbceb9a8ffce979c9939f33717fae830431aeb78c"
    $a1="a773241ecd38f3fc34602c0a58d0d16dd40acba244545e2e93c4edd08b4aca47a2c658206809e04630519efbbceb9a8ffce979c9939f33717fae830431aeb78c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_airaya_corp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for airaya_corp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWlyYXlh"
    $a1="QWlyYXlh"
condition:
    ($a0 and $a1)
}

