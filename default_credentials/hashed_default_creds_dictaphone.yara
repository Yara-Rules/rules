/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="35d991f227d8f56f63ebf6cac2bf0770"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="25835188a2355e9530d3a10fcbe4c65b"
    $a3="25835188a2355e9530d3a10fcbe4c65b"
    $a4="71740ec34cabbd03f03fb27be8aec352"
    $a5="71740ec34cabbd03f03fb27be8aec352"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4a9ff2446fd91b708e232c797b224cec0cd032a8"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="6845c6d90585c24d63de266c9a6da04090ed2dc2"
    $a3="6845c6d90585c24d63de266c9a6da04090ed2dc2"
    $a4="6a60619c25939a45374937d08ce674389e3d7765"
    $a5="6a60619c25939a45374937d08ce674389e3d7765"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b9f69886de1c58336b06878c60c11733c36859b8c5d21ef49e121aba55d61e7a7d25503a9983b1a842e5548edc130233"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="1dc4fce6e46b62d31fe29f5a5ca51c2b4f3db5ef8d58cec9d7bba4a4a99978959f4637730df6287852eac2243495aa39"
    $a3="1dc4fce6e46b62d31fe29f5a5ca51c2b4f3db5ef8d58cec9d7bba4a4a99978959f4637730df6287852eac2243495aa39"
    $a4="bc682477e61c4a8a71a1777b0151a1842c02e474220975fdec86c2fd8cf932e9caacf552eb2a999117b26172b8edd4e5"
    $a5="bc682477e61c4a8a71a1777b0151a1842c02e474220975fdec86c2fd8cf932e9caacf552eb2a999117b26172b8edd4e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c26df81ba4260e10d58acb4b42e3f7bfd4feb264435757d1e3d372a3"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="ab88a05dabbdd79168edc1d36d7e1f026c7144cb85792701611576f7"
    $a3="ab88a05dabbdd79168edc1d36d7e1f026c7144cb85792701611576f7"
    $a4="5e982cc7a14b30196bc347ee60b91fd0b4a1647814dfd8894cc5f9e8"
    $a5="5e982cc7a14b30196bc347ee60b91fd0b4a1647814dfd8894cc5f9e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="712ff61b36e220dbbd9be554345617eb76f71fc899aad39313b9539240773b4ac08f42e624c3a1181e0bf798c602fdefe5cd5f6b38fe79e0b43ce2401115fb83"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="d57c797c20fa47182c80d1e4ff32f2dd292ccb686d294072ab050ea4cfd6f4b26d089c642fd6cf1b1710891f343f0a686a52100ed67ebf2fbdfc0e27c08a4cbe"
    $a3="d57c797c20fa47182c80d1e4ff32f2dd292ccb686d294072ab050ea4cfd6f4b26d089c642fd6cf1b1710891f343f0a686a52100ed67ebf2fbdfc0e27c08a4cbe"
    $a4="4280f3eebeb1ca3f6b401d448d1963372b5ccc66b69b645347cbed493b982e0ba238a780be72bd3d9fd79be3bdc899e5fd5e8ee11e2a2a1e64158cafbb18213a"
    $a5="4280f3eebeb1ca3f6b401d448d1963372b5ccc66b69b645347cbed493b982e0ba238a780be72bd3d9fd79be3bdc899e5fd5e8ee11e2a2a1e64158cafbb18213a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dbfbe3357c08bf56da1fc1ecca32a97f46b67e9c985ed09c90481f99be954507"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="b5a9716fcd63f4a279e2f6df8f6de89dce75ff38fad8c7e04ebb2d8e2227e2eb"
    $a3="b5a9716fcd63f4a279e2f6df8f6de89dce75ff38fad8c7e04ebb2d8e2227e2eb"
    $a4="737f62617487a729b41b1f8b53f432f1551d3f2bd5124b016c7c0ecc69c46a80"
    $a5="737f62617487a729b41b1f8b53f432f1551d3f2bd5124b016c7c0ecc69c46a80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ba9bbb4c90a14e1aefc8cb741164f1668ce10394cddd8fb3fb35cd71c9702ac9a40154890508ae56337f829b6467fef881d8f144d91c83ae238ca1eaecfb3885"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="d230428f78de6b4d82df4a3cf4ffa430b5f7ee3485107cb37cda32c5807e6a4ccd72f533b739b907fb9d410e1318f6b3e2cb0c4b39a571fce2478020cd364fa3"
    $a3="d230428f78de6b4d82df4a3cf4ffa430b5f7ee3485107cb37cda32c5807e6a4ccd72f533b739b907fb9d410e1318f6b3e2cb0c4b39a571fce2478020cd364fa3"
    $a4="f036b90815db103238fe933fe748a7ae48aa271516d127ab0962d97b403d53aecf30d3374ca2537629e767753fb6d3b421b3921838c3bd2da6ccd0043a254d3a"
    $a5="f036b90815db103238fe933fe748a7ae48aa271516d127ab0962d97b403d53aecf30d3374ca2537629e767753fb6d3b421b3921838c3bd2da6ccd0043a254d3a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="042a1d8f2f834ee4ce229abb3620e69ce26edb4381844f1ed2dc2a9acb194df8"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="bcd4b1c877da47b20b5fe711e0e5a47532bd57aca7fbe4e4782a2216df6a0f30"
    $a3="bcd4b1c877da47b20b5fe711e0e5a47532bd57aca7fbe4e4782a2216df6a0f30"
    $a4="6e901b6b30bea1f0c3e2afd93f5c720f15c7145b1e6ec0f89ddedb3b8d4767c0"
    $a5="6e901b6b30bea1f0c3e2afd93f5c720f15c7145b1e6ec0f89ddedb3b8d4767c0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8bb6e987fd805b403db36ba529cc1aba0d86677e044e9083cdff9c1c"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="f4f9645c6ecf231432820a3334b276c11b746bd96b9b0e2932ef9a39"
    $a3="f4f9645c6ecf231432820a3334b276c11b746bd96b9b0e2932ef9a39"
    $a4="0e4729a46e76021dc02a90f365b845c17440a14f8d39e3a380eae46c"
    $a5="0e4729a46e76021dc02a90f365b845c17440a14f8d39e3a380eae46c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="65f2312cd40727cee7789227cf6837af52a26f0a774e78f76f38ce5391b24f6b"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="2a6a93d8fbdb169f05a0270ae9040e5a68a420f7d8902828031676487665ffac"
    $a3="2a6a93d8fbdb169f05a0270ae9040e5a68a420f7d8902828031676487665ffac"
    $a4="b41c4dacb6eea63d2ddcdae18a2bca25429a837c1bafa5037baad8283c1ae514"
    $a5="b41c4dacb6eea63d2ddcdae18a2bca25429a837c1bafa5037baad8283c1ae514"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e699043cfc729ddadc667cb47ec6ff43c9190bb17a3d10fffa541ef3ae0d0261dd25e19438632424506a490a601a4cc8"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="c805854f8913a1dfd3ab24126f5babd95262447ff267fc9c97e21313165e6da535d9a37527757b6f80f522bc956d1d02"
    $a3="c805854f8913a1dfd3ab24126f5babd95262447ff267fc9c97e21313165e6da535d9a37527757b6f80f522bc956d1d02"
    $a4="1c33fb8b518f6d550863616cb2937ddc13c2b4a87f87db404b1507dea258cc5a1867f65c5ab27ec5b35cc29c016637e0"
    $a5="1c33fb8b518f6d550863616cb2937ddc13c2b4a87f87db404b1507dea258cc5a1867f65c5ab27ec5b35cc29c016637e0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ae2c3b7e998e11da229fa91debcda483025b24e7b0b5eb75672a3c8aa83bb0538bee8ee8850160d904e233abc5920bde22b231d12bded20c50bf4288b3a09e22"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="e31c51bdd66677ebe710ebb5c0f216d4a8a8210c501ac97fe54beb1b93bac89c9d40ae2da98ccf94c81881721c0d09999ee2d4c0afcb5c5bbbc6e77506f48d10"
    $a3="e31c51bdd66677ebe710ebb5c0f216d4a8a8210c501ac97fe54beb1b93bac89c9d40ae2da98ccf94c81881721c0d09999ee2d4c0afcb5c5bbbc6e77506f48d10"
    $a4="dfbd646332d1b53596068288f6b284fcced07fef20395cc50dcc1461c1e47c76dad59955048267edadc353656298508a4b8f48cac28ca2049368141f38c4a7f4"
    $a5="dfbd646332d1b53596068288f6b284fcced07fef20395cc50dcc1461c1e47c76dad59955048267edadc353656298508a4b8f48cac28ca2049368141f38c4a7f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_dictaphone
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dictaphone. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TkVUT1A="
    $a1="===="
    $a2="TkVUV09SSw=="
    $a3="TkVUV09SSw=="
    $a4="UEJY"
    $a5="UEJY"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

