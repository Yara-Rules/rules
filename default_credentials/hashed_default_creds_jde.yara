/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="748b51386fe18f10637d0284bd331f34"
    $a1="748b51386fe18f10637d0284bd331f34"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aa3289f6250ae34f67f1f237b633a8b6dad0bd50"
    $a1="aa3289f6250ae34f67f1f237b633a8b6dad0bd50"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df72a7cad7d53b30f02313ba73b4326f6bd27ca7a812d82d961d42d5be9fd0403f61fdf82aa9cd2f190a66cc800a05f9"
    $a1="df72a7cad7d53b30f02313ba73b4326f6bd27ca7a812d82d961d42d5be9fd0403f61fdf82aa9cd2f190a66cc800a05f9"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b1870b9f5c020b588a49ec93ae4bb143ea86e0802c831b02de51e47e"
    $a1="b1870b9f5c020b588a49ec93ae4bb143ea86e0802c831b02de51e47e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3ecc0e9f4b585ee6bdd9038fb3f282f783975c61be93ce1d450852d2af13888bf555550ba2f8d475cf7bd7123003d50a3d7f25a7da3d6dab1caa53a1e9ab5b74"
    $a1="3ecc0e9f4b585ee6bdd9038fb3f282f783975c61be93ce1d450852d2af13888bf555550ba2f8d475cf7bd7123003d50a3d7f25a7da3d6dab1caa53a1e9ab5b74"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37c0b2244593c32dbda695aacd552918c77bc63f0dc8b9513cf357fcc7b4ac6d"
    $a1="37c0b2244593c32dbda695aacd552918c77bc63f0dc8b9513cf357fcc7b4ac6d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="64e86c28ec6dfaf731effa4b87e55eec33a0b2c1d41ffa36809375c3e85ec4403961e5955555e01e5d7455d1d03d2e52bac5e80885fa1200961266a9992f440d"
    $a1="64e86c28ec6dfaf731effa4b87e55eec33a0b2c1d41ffa36809375c3e85ec4403961e5955555e01e5d7455d1d03d2e52bac5e80885fa1200961266a9992f440d"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e2620913f0fa7212d691f91d133988e9163b9887ec78155454a781d006f4055"
    $a1="5e2620913f0fa7212d691f91d133988e9163b9887ec78155454a781d006f4055"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="19a525867d7eef0256e7a70ca7481fc5e3560750ceae158e3ee690a7"
    $a1="19a525867d7eef0256e7a70ca7481fc5e3560750ceae158e3ee690a7"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="482af1dbde0c58dcc8a8712c34dbc85a39fb41dbff2cc237be518e2bc319f3bb"
    $a1="482af1dbde0c58dcc8a8712c34dbc85a39fb41dbff2cc237be518e2bc319f3bb"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e666d206603b2e11a291ca65490e0fe52016a752f5c217015908fac53779154e1555b5d6b9f54b43c1eb05c27f72e96"
    $a1="5e666d206603b2e11a291ca65490e0fe52016a752f5c217015908fac53779154e1555b5d6b9f54b43c1eb05c27f72e96"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6fb3e93f9a871989c9a91ab7b4c7c87abfad046463ba9d3aa1fcd01f38d96ffc266b11a8b6d59e41ef26931c82698a7c513dc60ecef489d888566aa17088fdf0"
    $a1="6fb3e93f9a871989c9a91ab7b4c7c87abfad046463ba9d3aa1fcd01f38d96ffc266b11a8b6d59e41ef26931c82698a7c513dc60ecef489d888566aa17088fdf0"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_jde
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jde. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="UFJPRERUQQ=="
    $a1="UFJPRERUQQ=="
condition:
    ($a0 and $a1)
}

