/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a1="2d2b96462d029cfb96c3bd185634f96d"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="f5b2bfd7c890ff6d8cddb4f1e4e9a43b"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="d41d8cd98f00b204e9800998ecf8427e"
    $a9="53c4a5660187e1a9779f4136e73dc3ec"
    $a10="834622a413e3c42c2dd8080c226bee85"
    $a11="250cf8b51c773f3f8dc8b4be867a9a02"
    $a12="834622a413e3c42c2dd8080c226bee85"
    $a13="1d11d5c3d9f74519486d29845433d29f"
    $a14="21232f297a57a5a743894a0e4a801fc3"
    $a15="042e4af7dca5cd093dd1e71775e451e0"
    $a16="834622a413e3c42c2dd8080c226bee85"
    $a17="efb13c5d92b641a10423401c0745061f"
    $a18="21232f297a57a5a743894a0e4a801fc3"
    $a19="250cf8b51c773f3f8dc8b4be867a9a02"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha1_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a1="5436b8cd6b2498de3d1986a71b0c759005258859"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="316afa7be820d6ef82c8a94716e74b2b710b87c9"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a9="2b72297ab921dd933cc66350398d8c5941692f86"
    $a10="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a11="51eac6b471a284d3341d8c0c63d0f1a286262a18"
    $a12="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a13="264cdbe779c23de98fb932498d2a6222524ac6a8"
    $a14="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a15="fec4af4d9874274f99450a11028613ef8b3a8a69"
    $a16="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a17="f7ec3371c582972b154770dce9d85e2fc60fa4ab"
    $a18="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a19="51eac6b471a284d3341d8c0c63d0f1a286262a18"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha384_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a1="db0a91119745c6bcdcf60558d29bce5594891bf7da3ebc8b59f02f1cef2a4598adbea5345be0cec7f4934163df2616ed"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="6d50e6136d02d8e6cbbece289f2cd3676ce38fe6415665a78b65c744e137d7dc236befde79f63202483c56d313853529"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a9="be8401f80f90d514ba6f280e787f2b38286d4f932606c4a86d0f41f96822736db741ccfccf151d1a079ca608bed05d5e"
    $a10="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a11="714b7ac92749929c1902ae7a8497bf8da3fb421a3ec4311332053cc43f0994be9b6844f5b34ebd10d6801a1ea2482918"
    $a12="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a13="1896d30c608e95c321b2cffd60ac2b71b0662b94e55a70b3d0c53f0a62cdb9698969a372311ce51f0d278607261d2e52"
    $a14="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a15="f6dbb4d5687a9ea5fe44f4c88ff5e0447805006b48b8ac6c52dad8e24c7617299e4a46551039841132c3e8ffb8862287"
    $a16="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a17="0d9a6a03211e1f150d971917fc04c1e98343222c245cdf23543983bf5abfc2c8f5e75174a0bfa85606076cea2ceeb4eb"
    $a18="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a19="714b7ac92749929c1902ae7a8497bf8da3fb421a3ec4311332053cc43f0994be9b6844f5b34ebd10d6801a1ea2482918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha224_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a1="664d8f3cb0b98e5ed4204a2490993720a40dd297c859bbabb05ed987"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="0c91a5e2342a6d1ef9eb33fd240848d762c86138b2230f7e9435e1a7"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a9="920ac7824a6848b43e560a17bd2a63221543e2756cc1cb661da8f725"
    $a10="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a11="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
    $a12="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a13="11882960fbd93ad1606c66d9021f6281515a7d3a2c766881c597e33d"
    $a14="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a15="3cc27ba47fd4d99add33ea2fc6b94b1ddcd92598df48568e70c35ee4"
    $a16="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a17="09e8afd1a285e7f260f65e8de0e97fc01637360157b411cca9516f73"
    $a18="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a19="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha512_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a1="46534abbc7b4d4f4a348f43324f861e8e583e9f4c5a4bef73ac7eb9c476df48ef65a8a16fec5031e9eb8f8f5b4e6a8f0ae30f31eec1c6669d5be0d04888605ce"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="b915be0f7a735f376db80239cced6c932f026f280b57ef7c1af553d99ba59ddf504b030a28edea6a6476ef7dc376a9c59b90b72920036487937519dcbef84ec4"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a9="5cde00a5bc4e756b47c4736b5cd6640a51fe4cebb92f7c8805369e1bfd4fb94e7fbdc002100943bea8ca93d01ec30496f03395234ccbdd4263faa455b233bc0e"
    $a10="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a11="f6b07b6c1340e947b861def5f8b092d8ee710826dc56bd175bdc8f3a16b0b8acf853c64786a710dedf9d1524d61e32504e27d60de159af110bc3941490731578"
    $a12="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a13="8c10144fb8485e7056365df293ac9bbb2ac01bed7c7656e2e0315b7beaa878f1c394beedcd9baea3f5bc0544e7a4c3bd60bcd2d418f2ae1a12cccc5d1fe976c5"
    $a14="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a15="056a04f5dff1be846d7edeb527d1debd104663e0fddbe1f1d28abda6f4d0869c75284126492617980be9f7aec391937e416833fb8c1e1e7b8a56f2015cd1bd3c"
    $a16="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a17="c03acaa86255c2ed52831dac7d04546ed150c370f873d624252b81b80ade3b3a85552100cab4771c938217cdb4715655cacfd25628394f54f059fd4669b61196"
    $a18="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a19="f6b07b6c1340e947b861def5f8b092d8ee710826dc56bd175bdc8f3a16b0b8acf853c64786a710dedf9d1524d61e32504e27d60de159af110bc3941490731578"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha256_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a1="3b2bcbe6081b7deaccbe0b42f2269a0910e8f2c47ee4e61ccfaa13b3a0de0f9c"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="460f315f7b5ee50c1997f464fad2bf426b5762ebbe4a5d4d9c813adb25c7a141"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a9="5eb76e4f5dbe7a5b82d29bc1addbe6c7f632a94ccc6a8a5564e31d228fd426f7"
    $a10="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a11="b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
    $a12="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a13="84da65567426a771c18b2e2294ffa4485eb209e392174bf6737af060414eb7ea"
    $a14="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a15="8d3c7a78b824e5a1d6b902d0b63c418c358a4194501882810f4e003a775914d6"
    $a16="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a17="f0c8303d46ebe569e445b6f65ce43e7f8ba14efef67b36bd2cd6fe97c85e08c2"
    $a18="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a19="b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule blake2b_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a1="f1020c2452a3847b7c9a82a054800c7a26e6d79ef9c380d9b3d5f0b2f47aac3a0d2bd7c2ed4d19677de9c25bdf25329078420cf12ae3f1656d76c7c4cf9f5a2c"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="69ea1c17d4fe7ea98a1f4ab488af79cb152b954ec44087c91be40ecc05984220f8bc74e7e64be4de0c99236f58b356f878f39977d4b1b4f6e4df13484f609665"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a9="eece26021ddda21521dbf7d3681937b80dd8b53644449473b7c761e5da8b70fe0929950d8872d5d3716626e049909d281201c36d014d5594547662a7b37b2145"
    $a10="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a11="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
    $a12="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a13="e0c680e19cc0d6a3661209a56431c23d0144f1add2d9f815e6065ac1b54ff56822fe2af3b649f1fdcb631977466497abac925deb21b09aca0bdd321f68bd6d41"
    $a14="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a15="87498478322b2dd634b587e2b88688fbbfaa412d26177d0708cd1190101320abc21025baa14aaee3640bc073cca1b83bb0a4bf0c9d6409c31e85a5feb7cc9662"
    $a16="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a17="a20657473838a54d50b5b6ffd6610d84dd8389b988723ffdd516e6f5472cbb4705b90abb5be970bc061f2bb89048de00b1978681967de86a1c7c612c7762362d"
    $a18="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a19="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule blake2s_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a1="bda6e6fceb2a94ff97a0720b0202b3f1d31a7e241ec767afc18464da14c7edce"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="b8e0a8bbee44c0062eb034608dee731a910a6d8cb93bebb9198c9cd75cf1a1b3"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a9="67b0118ed5fbd2749f2b5a9daf480cfd973138c0f019d54bfa20be646ae04bc2"
    $a10="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a11="1d9d8b9a458754c6f38ef1659a4b869ffd939dd25474b0c1677b36ace49dd37a"
    $a12="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a13="0894548f2f7123ad7209d8bcbb1fc4b3bd06b394ad0f1f8285baf4b978d63f30"
    $a14="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a15="5e328fa3b17ebb32cf0382d3012b005263eb26333ea6fe9c7cbf83e3558df98e"
    $a16="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a17="3f6be9d5ff390796fdf62e19e43cc62cc8d00458d3887098b40f413f56b87fbf"
    $a18="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a19="1d9d8b9a458754c6f38ef1659a4b869ffd939dd25474b0c1677b36ace49dd37a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_224_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a1="3195faf8dac1265a29b31a6ca528f343b8209cf36b065e031b75b652"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="687b75730612a8ac8e1a9a75c0ceec5bdb0584b30257e55b6f1549c1"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a9="996506b265077d9f1d9e61658186eba3e3882425310a214c09b82c65"
    $a10="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a11="a6908462fb4e2ce1d26de530bf014805f3f08d109f390066c635e4d0"
    $a12="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a13="89e5ca9d7cb2b3597642cd2be279676935d45af50c26dac5340930e3"
    $a14="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a15="ba6134b813bf09cf0479742c3113f52fee1e6824feb200122c6aae95"
    $a16="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a17="cf963f34f33cf23074fa3a37d94c2455cf7b0d49be88d26d93280539"
    $a18="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a19="a6908462fb4e2ce1d26de530bf014805f3f08d109f390066c635e4d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_256_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a1="fc1cccc1b9f433a6095e1b515300161ced511ee8880692f9fece2f7b9db81de4"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="3366145d66749709bbdcfc0d39c61d22263995acd05d2a390f50d11f594e6ead"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a9="2b61760c9fcebafc9d393c05687c8aeb9c49d107bae4e25c0a7c8e787572fae2"
    $a10="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a11="fe2c6648c75468d6f4cc5fa16ce33e43f7aefe8754f92a09eee2362b71851b85"
    $a12="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a13="01d84a0e148f75e15230702ed415ffbbf9f0e05dd65c708683e4e9ed3c6fbe59"
    $a14="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a15="a65290535b8f2e82433a5b23f67b8087b135b38473a4a541ad5bf36bf0dd1804"
    $a16="c62ac717afa32b3362505f0cc2a1391838ecbb84a67b6b62be8bdca46195decc"
    $a17="2ed55ef7eead2dd7377ded21e7a3928ac7be2995b3e804ec86e2fd4c84bfc7f6"
    $a18="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a19="fe2c6648c75468d6f4cc5fa16ce33e43f7aefe8754f92a09eee2362b71851b85"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_384_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a1="e9c39d4b15f14239a96991d9628368bfb7fab6ba2a9506574ce22070fc12ab814952fd239e7abf522777460acdc1a8ef"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="b60fc6b8872c39e87378b9333e9431e7b3a0f83a238f2b9aada5209798eb673622626a7a6e9b68131752c0042c39ebe9"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a9="5e6f534dac4962282d1830daff5eb09f88980d30424ba968460b9448b61af92d5c3100cc1c7ff0d41ab5389801d23455"
    $a10="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a11="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
    $a12="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a13="d1506f7938bae235ae44b42b10718f3039e9f2f0a2e11df31455fa85ded512c792c5ad66bbf7cc40512f35c336199954"
    $a14="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a15="14e14ff32e7fa536d894bc4926bbcabca700d98b0c743c1ff845dc5e1cd700698b6d559a5895145628bb7bcb95eacf56"
    $a16="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a17="d5d3a83a2710dfda618f51e0ea1b486218c37ba994054a2297d5b1e31f1d271a42a4238e2dc54c2b20c087ee32599067"
    $a18="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a19="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_512_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a1="ce997a8d374571ab2f8c2ac59af15841a1518dbbecb473dd04a73c3a2ba3631aa5274026b136362e694ee211ea27dec883cd2610638127cb7ca5f77e2fab2c29"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="aa52e97b670d2811a33905d53da3c60d4901890ba22f5e652643e12b762c6144ce123201c3695760f8f620e42cb1992d1f3952d738ca7140ac455e3116c60bc6"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a9="27cd708900bc5d28d3545d8d3f5ea8426796ac18951bebf508adb361e6b89e48ac133e3c9e863fabb5ff105fc43aa96d3be2059a288f9ceae7f8b33571bd2cd5"
    $a10="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a11="0fe220a126aeb06ab687b5cf73175abbd6194f57b593059f33186d72066a283af765cbbea04cae0bce0ce793116a4ac99424c28ea7fded4e88a18cfc51513cd4"
    $a12="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a13="8b60ce07a45624f930298d133aacb304924320cd4829c352a1dc38514299d633e37ecc5ecb90987d01273ac9709e4fe9bd496577dd2337f37526f1c5ad872591"
    $a14="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a15="a1c449c96bd5a44824f19a7131ee2545b218541a49f10a5708addab3f6adbe66569a7741f310da4161997edfb1c7314bd2f2b81f5eff0ebd8c57faade572943d"
    $a16="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a17="a04c522832688f86f66bb9811bc69084dc7c918044c72bbdf6b87953d0cddc2952948b46c6aadce9ef8bcb62f250a837e7a7825f3468fc9415f22896dd42d6d0"
    $a18="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a19="0fe220a126aeb06ab687b5cf73175abbd6194f57b593059f33186d72066a283af765cbbea04cae0bce0ce793116a4ac99424c28ea7fded4e88a18cfc51513cd4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule base64_hashed_default_creds_polycom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for polycom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW5pc3RyYXRvcg=="
    $a1="KiAqICM="
    $a2="===="
    $a3="QUNDT1JE"
    $a4="===="
    $a5="YWRtaW4="
    $a6="===="
    $a7="===="
    $a8="===="
    $a9="eDZ6eW5kNTY="
    $a10="UG9seWNvbQ=="
    $a11="NDU2"
    $a12="UG9seWNvbQ=="
    $a13="U3BJcA=="
    $a14="YWRtaW4="
    $a15="YWRtaW4J"
    $a16="UG9seWNvbQ=="
    $a17="NDU2CQ=="
    $a18="YWRtaW4="
    $a19="NDU2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

