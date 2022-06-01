/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="55ad8eed989159c9f6c505f65dfa8d18"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="9ddd65fb665642eda7c9e8cd03f70f5a"
    $a6="f11903d870bd5136fdf72d2265ef7952"
    $a7="f11903d870bd5136fdf72d2265ef7952"
    $a8="f11903d870bd5136fdf72d2265ef7952"
    $a9="7694f4a66316e53c8cdd9d9954bd611d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="dad12c9fffabb65b85d947e3bc7a34a606f17474"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="e16647473cf3644be6a4dab4e590acd2b21eb344"
    $a6="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a7="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a8="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a9="22ea1c649c82946aa6e479e1ffd321e4a318b1b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="38c43d59a9f92c5407f70e2244a1aca4ac35285dc852f27502c1023daba398fc235778c5f3fc87b0e07a93ca8f77437f"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="a74941273a74fe14e7bf79b533397b17f1f192f339dc14f9773a962cd1810bc43b75ecf0904919adf723cedb80a907a6"
    $a6="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a7="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a8="05274ce7e39f606e4607f9538c8c07eb66a6f4cab902df07e427d04d9f977105dd9ed68b51f35e826107dd5c6f3c7dce"
    $a9="081de7624429ffbb0cd03c81da55df6fc8e36d09406bc581aa78c84742fdf45f58d999adb87f89740d2a4f88aaf38209"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="048a223cf9974ce4fcecf05c8170bfbc8967a5118e95867d02b44e46"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="4679a792035ded5bd33dc573bec205baf54e8a65e081216efdeeb5fe"
    $a6="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a7="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a8="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a9="8acd70840f1928a2a80c548d7599a07e752a6804612469d1dabac68a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="adea8acaaccee2c05566fb7b3e25494c053e2a43b84ace8c3a6855140ce6bb2c98f1f95b6a499d3575b013b02e28d9f88a09287fb3ee9e7875bfc67b8421d619"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="44570ddf9c57e0fe0bb9dc3fc3c9977a8e581818a26c52f090b2be047567ba1b16639ed5a6e145acb23c8c82a321328cad70e6b347e456fd874e5ced30e1b6c9"
    $a6="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a7="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a8="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a9="2e96772232487fb3a058d58f2c310023e07e4017c94d56cc5fae4b54b44605f42a75b0b1f358991f8c6cbe9b68b64e5b2a09d0ad23fcac07ee9a9198a745e1d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="1998ee261dcf8d3104ccc4fbd8370e4d3b52200adeaf7c62ed14e8aa96c5011a"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="90e6b40305f9a228c6216327a00a6d32530dae06e4de4545f0194e1ddfafe427"
    $a6="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a7="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a8="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a9="8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="7e7035a00863a7f0d5a4ab4b5aebbc84f93c34181ebbd778a7869e9aaba96058bf4b77635732ddb6c4f4fb3de706dda95ebab7ca4c6e1991fc89dc213e6e9c94"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="3a50fe54ba734035647de098176a643e79b9ab51683114f8a25266c53862820024f364b7a3536ec0df45f409169619726d29aa36703ce9e7745224fe18f9a041"
    $a6="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a7="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a8="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a9="d6764cd7f36006d17c9c0de176f578d8ac764c5381daf01d2f8bf23527bcf12d3efb2431f65589f3493ccdd31b4b1467b50559293e2f27d9f0974abd793bee71"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="a200afc90a817f3909d2fd2e9515c8b9deb3791a7d3a6b7d162cc3129cbfe38c"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="fec1180b883c424907c1caf037f3ad7b1c1decca40f39ebcb70a986cb99bbb71"
    $a6="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a7="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a8="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a9="ae3b60e36575f4b166ba8737078140a43a64e58905d9a502ec2f2587a7079307"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="fe5f63c35260f17c2072e56333316ed8c3bc034aeab3c0a752084163"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="8531e75bae15111c474bfbff251056c3b94a091c531550e22e7b019c"
    $a6="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a7="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a8="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a9="774057ce10e1b255cfa747982782e969231ef434a057622021ff5b9c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="96ff51df5db9a34787f0ca6ccc585aa745dc56078e21fa133c14846621916af4"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="6eda6ff6bb4e7ffdb15c162cabc10175361f9df195c48eef57c53ae1882553a0"
    $a6="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a7="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a8="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a9="8a5e1d339fafc39350fd8cf1d7ca7982091c27f6b77f75bd4ddab3df425b4f8c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="a96eb591cef91e7138f716e84a8d948192fae1efaa46802e18f7948fe694a4cc0baf676dfd61927b487b977797290b35"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="ba24015ec19784d6401820d8a538ee22019a0f11ff7e9a568e8c4f7f3f602fb096f3f170b480b2b32e4fe3464f6f30f8"
    $a6="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a7="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a8="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a9="a73cf129eac67f6b9e2f3818b3b845572914c3c6821fafdc71d834f7852ba1c1d894c1a1d71669b9090d1a08418d34d9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="b5ad4ae11850ab5632c390de51f06048f4eb32c63f6664c69829b7e05ec00e7f7dc82c42a8c1c26ab736d73874213d5f88e7932191fba8326bebba9604baed53"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="f035870c349b14da91f9aa5fc05d512acedcf28e2bbeddb826cc0f99836e9fb5244de561e9bed89fc68fe313354fe6be82496aa93289c09ca6651207b2e0a6dc"
    $a6="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a7="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a8="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a9="f435ba3ef2bf43e694c8940fa315641c67f152c2ee2021f121af5e03f9860607f74e61e1451f9489c2ff59f87dc0e1c501566e2324355de32770ec52cc3bce47"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_redhat_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for redhat_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="===="
    $a3="QU1JQU1J"
    $a4="===="
    $a5="QU1JREVDT0Q="
    $a6="cGlyYW5oYQ=="
    $a7="cGlyYW5oYQ=="
    $a8="cGlyYW5oYQ=="
    $a9="cQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

