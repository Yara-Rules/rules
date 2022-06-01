/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f11903d870bd5136fdf72d2265ef7952"
    $a1="f11903d870bd5136fdf72d2265ef7952"
    $a2="f11903d870bd5136fdf72d2265ef7952"
    $a3="7694f4a66316e53c8cdd9d9954bd611d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a1="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a2="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a3="22ea1c649c82946aa6e479e1ffd321e4a318b1b0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a1="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a2="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a3="081de7624429ffbb0cd03c81da55df6fc8e36d09406bc581aa78c84742fdf45f58d999adb87f89740d2a4f88aaf38209"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a1="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a2="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a3="8acd70840f1928a2a80c548d7599a07e752a6804612469d1dabac68a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a1="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a2="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a3="2e96772232487fb3a058d58f2c310023e07e4017c94d56cc5fae4b54b44605f42a75b0b1f358991f8c6cbe9b68b64e5b2a09d0ad23fcac07ee9a9198a745e1d5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a1="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a2="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a3="8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a1="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a2="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a3="d6764cd7f36006d17c9c0de176f578d8ac764c5381daf01d2f8bf23527bcf12d3efb2431f65589f3493ccdd31b4b1467b50559293e2f27d9f0974abd793bee71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a1="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a2="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a3="ae3b60e36575f4b166ba8737078140a43a64e58905d9a502ec2f2587a7079307"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a1="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a2="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a3="774057ce10e1b255cfa747982782e969231ef434a057622021ff5b9c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a1="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a2="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a3="8a5e1d339fafc39350fd8cf1d7ca7982091c27f6b77f75bd4ddab3df425b4f8c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a1="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a2="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a3="a73cf129eac67f6b9e2f3818b3b845572914c3c6821fafdc71d834f7852ba1c1d894c1a1d71669b9090d1a08418d34d9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a1="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a2="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a3="f435ba3ef2bf43e694c8940fa315641c67f152c2ee2021f121af5e03f9860607f74e61e1451f9489c2ff59f87dc0e1c501566e2324355de32770ec52cc3bce47"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_redhat
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cGlyYW5oYQ=="
    $a1="cGlyYW5oYQ=="
    $a2="cGlyYW5oYQ=="
    $a3="cQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

