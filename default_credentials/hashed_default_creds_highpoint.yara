/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf91513c6fc63cebe4b63a6647238d6d"
    $a1="a1cf62324ea980ab05fee7b1d3147d7c"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ec78fc6e5f39ffda9be97974fa1cf6163f36f2af"
    $a1="96e8ec7ccd75dfd567ef37f7e32171e2d536a374"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f1a72ae40795fac6f63816d70241563f59041d64450e1ae3df824de7a4295ec4b2a0cc9dd29369c586ccd1d35480f61b"
    $a1="e8c9910f7849d5b1c25ef30db30482bd156954009738a4daff206fae810cc8a7bc1ffc7feba82a6a6d9ab036ce045117"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d406ebf66c1247a5ee6daec2f709182073ba165aa358dd194b0aa162"
    $a1="5f889ed39bf0d4ab51a1c44c6697910916bc7910b52b9cfa3b34805e"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="101b271ffca2c6d7d1394e5ccc45e7130b9f72541d048d66a5502bafd26c3a43c4ee38b1aca0f523b9c0760ef88c01a14f710da91d6946d8dbde520b0d291c57"
    $a1="8034aa85cb386cc24e948bd92148943cc56a7988d035b7a3e5b094f2a7ddbda85da8cb80ae9952e16018c8167da6641e792c3a2cb888ec45629dbc22d9ec75fd"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fc0459fef3893d2fc2d113ed43432ca4176c13e00fe14548a0ad9d5f4b16a6db"
    $a1="fa1ca992cbacde62e2ca7990d57243928433d66e789091767de15b390e170fdd"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2d130e17ac0a62f5b3f3235834dda84e8c81ea04ebf49025447375c767f033a288c9a56c1b04e4149fa7965200018bace11a42d66f4506cbdb13f9e8c962a2ad"
    $a1="6b7dceb516fb3ba35b7db1bcae92a23972790a8f392d1294c496031169c0892ab7ceed62ee3d8e0d2dbf4df84851d1d567544b410fb3fa988c2378e3dd0a5b21"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="652668a5992e8059aeb54f618c3ef4663dddace1e4243b92143ee261cf6ac1ef"
    $a1="0cd1b45ddbcb86bb8a889f7faec5091741d32f1394a0b4c7113e461c6d89366d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4a4211bc90556a7422e7202eae00bf723273d1a4f7edae532f9db609"
    $a1="0b1c8818463118a5e6f37c9d0257b04a9695dd65dc1057400cd555bf"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9666792e2c2a09933262ed637e0374ad3a0993d722c8526778f4c97bd33be958"
    $a1="2406ad1483e544e076bc0d43b7e07888c6cf765382694f040d657bd4a6579fec"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c84476727cb63767a3922a16f3e0123cf28778a8a541b686aee768aaaf613e0df2ac572960ca0d74a4a5627fde5110fb"
    $a1="55c3d7d0b301593640bd0c4028933ab5d4948d25f73b494185e1cc02c0122c01e9af682ca176fe4beeb7465c89698ec7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f9f55f91fc6e1dfbb28c6e4712fe5e8eb6e74d039e0219da3bde556ade11fe12bac1c22b1e6d0c6dcf45d7f0d07d85af0c13bf54144e64636a112d4ffbdc8925"
    $a1="54bdd012232ff158c1a070e2b3c15748a1a3f6b647a671d88f7ed09cddbd68bf857ea39c3e29d29242b98d79cd9816434be10f4bc79d118917d1c8d5b800455d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_highpoint
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for highpoint. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="UkFJRA=="
    $a1="aHB0"
condition:
    ($a0 and $a1)
}

