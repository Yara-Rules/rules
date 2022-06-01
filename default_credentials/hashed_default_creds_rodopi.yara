/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e531431e371fc921cbcbe3f719ff37a9"
    $a1="e531431e371fc921cbcbe3f719ff37a9"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f4e65f2059efaed6379332d7e901159babaede12"
    $a1="f4e65f2059efaed6379332d7e901159babaede12"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="56832afc7613871a0b470754727a57305d89917876f207d3b6c44a256522ce97c8fca892667bc40ff7c304536f946e44"
    $a1="56832afc7613871a0b470754727a57305d89917876f207d3b6c44a256522ce97c8fca892667bc40ff7c304536f946e44"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e2da4d2c46076de30800a2777d7d7ae6be36b64e39246c345ff93676"
    $a1="e2da4d2c46076de30800a2777d7d7ae6be36b64e39246c345ff93676"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="45b70e8b82b3db309e718914484c04eded60b99ea85bc1426c6184526cb9c2cd0246070620d6a618a476a624f9af7508ae94d132ecb16b6849cf875cfa6b5817"
    $a1="45b70e8b82b3db309e718914484c04eded60b99ea85bc1426c6184526cb9c2cd0246070620d6a618a476a624f9af7508ae94d132ecb16b6849cf875cfa6b5817"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="88269a83b8b78a92b2b67e624dc05891c00f00ac8a6c59eace99e760bde49c10"
    $a1="88269a83b8b78a92b2b67e624dc05891c00f00ac8a6c59eace99e760bde49c10"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c02ba7538d011c7d7e4479de0cf678147d6f68297ece415c6947e5a067eb627d6383b0ecc4868442999598b18088435c4a4a3b82fa3697287c0910fa796b9f6c"
    $a1="c02ba7538d011c7d7e4479de0cf678147d6f68297ece415c6947e5a067eb627d6383b0ecc4868442999598b18088435c4a4a3b82fa3697287c0910fa796b9f6c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f7b1c074cdb9ff3de37be03ab3e1777231d2a9fcf5898033446f067d431ec4d"
    $a1="6f7b1c074cdb9ff3de37be03ab3e1777231d2a9fcf5898033446f067d431ec4d"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ccc6df27da31287eb118c8af82dfd2020ad7c2fd4238abb5b2a15bc1"
    $a1="ccc6df27da31287eb118c8af82dfd2020ad7c2fd4238abb5b2a15bc1"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eef376bed892b16c8ee846e3cbee99856df0c1c68e5072405674ba82d259c5fe"
    $a1="eef376bed892b16c8ee846e3cbee99856df0c1c68e5072405674ba82d259c5fe"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c9c6d0620044eca7a8c12eb4054902606582b52b7e55990a65fe6944eef9a6a78b0cc9ef17084e927dc724310f422b8e"
    $a1="c9c6d0620044eca7a8c12eb4054902606582b52b7e55990a65fe6944eef9a6a78b0cc9ef17084e927dc724310f422b8e"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c4588c2083bf49a593c9d78ac02db0191fb9cefc9eee6ad2fbd5fd42456b8949b95968208069d9006e2f62d2957d51ac66e6b058172f652d0e86c70f50065872"
    $a1="c4588c2083bf49a593c9d78ac02db0191fb9cefc9eee6ad2fbd5fd42456b8949b95968208069d9006e2f62d2957d51ac66e6b058172f652d0e86c70f50065872"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_rodopi
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rodopi. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Um9kb3Bp"
    $a1="Um9kb3Bp"
condition:
    ($a0 and $a1)
}

