/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aaabf0d39951f3e6c3e8a7911df524c2"
    $a1="3ddaeb82fbba964fb3461d4e4f1342eb"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a1="26f580ae0efc69079ed9a6beea0e30288ad90119"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="66e17cee68b63148b492c1e60cc3b9c85161eac639df6ccc878f251b056eb1a1994c6e81f1f6971a3ada23434c9c5ef2"
    $a1="683efc8fb8cdedb8e52255891bdfb91afad01b7d31b746a0ecdb8760d9e334365338ab5943f35e22c424ec3c65fa4404"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a1="fb22dbd3dcf0b2ad8e74079e7db330b08b16a9cdca3a446bcc402a7c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
    $a1="8309dd7c52675caaf669868c10bb5616d28daec1e47001277118e7832a22fa7e624a497edcae4a8eb0c74b9f2f64882ce7978492b99cc4975fccece756c4712c"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280"
    $a1="fa1eadc4c6995667412681c69ce33adfc9302a2965f521c40908549e670e2e4e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
    $a1="b75c8c42a1c9216da01ffe3d1f1854706c5dc40a306a6bb76916e8bb93983d469542180373ca305ad5bbf8abc70bce61776f147eb2e041fd8e5367103d674e08"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a1="cef0603e0ff8eb1842c0822f0fc3974b996589f8c15d8b82e95561054c29d159"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a1="fd9dc48ed52245c81385c2a50f69254ef2318efd51650adb441113cc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a1="ed9e36fa06a282d0572283f9332e1008e159ec1d234e55fc4316c7fa0f3f30d2"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
    $a1="f3e35699f5b5c65615b9b77e56cf9a027927da2779f7e249a2971408801ee28c739c2de9b95a8bfc94647e1033239a71"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cbab59d74fea767f62a9cac3851b832e01570b54280cbffa7bfe6f0f57352199adff8fe9530a129101047560f0992cc6990116bf8d38bcfb44f8ebd2bdf517fa"
    $a1="aa0f96477a753c367edb9be48f0f5561d5ba9136c6cdcd9b59415966301d6c88b3df8eb446fafe1979321d7b81677c22bec39485bb2056a0e76de73d5f32286a"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_meridian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for meridian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2VydmljZQ=="
    $a1="c21pbGU="
condition:
    ($a0 and $a1)
}

