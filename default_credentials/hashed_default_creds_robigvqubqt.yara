/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="64ec452c6f6a1c27b0448d4803a437c0"
    $a1="8dcaf3e92913132fba0322f848bbcb0a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5f1f510868828b36606e39981a5c4c3ff2539e5"
    $a1="eba1ed23548c78348931259fee8e8cb40883c872"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30538160cae262d9dc805adc9b740d01ded8eb6e1a0d5f0e854614b5f3fa156d984e94eaa41f42ce2702d480e5638332"
    $a1="6b246be666938724f021773a2457a83c89a88067d7c2648ea7d50d8725f254a52fe3a07364a31308288caa27aa26e1a8"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e63db6c475a1854dac58408c2a9e938c9dab5e31a9775c2b5f35b8d"
    $a1="a398030f8035b5f75aa7bf69abe3d39e4fef4c83890411d4389600f1"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="04005c3bd5db18346b7db0a7ff9f4005945c4334496efe87654645451ad395912617b29cb68e864af2ceb7719e08e330e919c2d3f5dd16fe08e9666c9b77562b"
    $a1="cb92ec62d0f3d2831dda19a17a3dcdd51b3be8e595ff960e99d424858183f474efa296de95562286abb1c7eb61e38e601bf8ee2d66202713259a68c24d572443"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3263d518158cfb498c27d83e3bad63ec79453a6bd006980dd27e7f32466a9d3a"
    $a1="da4fae854d1fed67f0d83624582933d87e727eae011bf12437b0f9efcba467f6"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d33e214aabda53dff8b60e60ce872cb8c1698a0122208db57ea182f23c24c241400c95aa587844a313aae0a28f92d106092237b052991acc17f86818cba20590"
    $a1="8d148ef11fc7e2043dfa1cf3817a0726cfef45a098f945586675bf08baec4c472d0eaa5ffda4c10bf17fa9883da8be8d2dcbdfb7da0d0a02070af102297e7b9e"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed1a92d93da90f5edb5e19f449e6661c0fc46b6a6fdb7cc86849f5400a827f3d"
    $a1="1733a34cd0cd3b8ebf20e01eb3eb6dd480652c6ff9fff28f4179e8470fcb9079"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5b72ea144aea07247febc395980a188d0882bdfba4d653f9d73b0dc5"
    $a1="eb99350898234d1020c1a8d2e12720feae72fbff781df21ae24f7aa8"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7093154cb7f2ca1c1f949120010b2b5d8ee79fd1f60bcc4f4753d1ffc4e8e8f"
    $a1="2340fc30f8e2806e84e6bd6ea5672791ed54969a58e3173922a13af16e922d45"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="213c3dbc308ef42a48cf27bde3b9e5347ca16acfcffef1af54f214125c312402a88e8c7a65617657ed86edccabb2828b"
    $a1="524741e7bd93bd7dc11cb53dbbe9b33270ab5872e5370fadef088d5a43d0094b0c3d9c789461e90300b0b9d71154b7d1"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2fa1455c1bc4b16b04055b0b59f0cd2d8cb61b30d0f94fcc8fcae2b387f5629cdea8e730ce944b585cfa5a9adaf137f6f698b6570618ae37fa7b3ad0cf441703"
    $a1="42f9d2be50b77df4abbbff945ab81540aefeb7da5ef278eb4aa0670e2334197f13b0604bd1e3a3f5d976dad30854c88028dd76668ec55d3ef73c0a33c121165d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_robigvqubqt
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for robigvqubqt. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d1ZReHlRZWM="
    $a1="ZW9tamJPQkxMd2JaZWlLVg=="
condition:
    ($a0 and $a1)
}

