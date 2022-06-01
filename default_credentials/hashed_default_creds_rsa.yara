/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="c93ccd78b2076528346216b3b2f701e6"
    $a2="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a3="7e27f238e794d145f1450749d47ee1eb"
    $a4="eb0a191797624dd3a48fa681d3061212"
    $a5="cdd1c82491d1228637c228f1d79133f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="7b902e6ff1db9f560443f2048974fd7d386975b0"
    $a2="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a3="73dd342b9c693012efc970cb8cdd8cf7509d00e7"
    $a4="4f26aeafdb2367620a393c973eddbe8f8b846ebd"
    $a5="f45940808e0868d1dc8f98c5e4a1dad2dc215705"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="a9c814a170b0bdb551e56977d25d4c41150dd02da15089fd514ba4a58761bc49c02c91808f9a009a4660e456f1b103f2"
    $a2="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a3="9eeb6518b1a04f055c79e4deee94ad7bdb24eefc068f836961f3b98bfcac51ff1af93af6d86fa2d115f14b13c241974f"
    $a4="233a0c3b653358b1b07cf093e7b2e36a54bf4c66d5736db17ed145b18520c9108bbd9ed53bc74de041e15f1476013b10"
    $a5="8ea2e856001afab1ecf0c5afe051f10d1280709567e24ac0f156a58294d6bfd6b549077f6f89ced812ea04cdfce0c578"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="65335da024e1e7b60ec0e63c69807e0043d5562a942e9da5ddbf3dba"
    $a2="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a3="b08eae280a1059344bad6e8c498cfbc928abf4fb005a3d704f63ec39"
    $a4="79f95ce631a460dc2e3d220a5dffbb5616074375648e4a2212127ecf"
    $a5="45ebe56040d36c09aa907a6946213289dec195d146e2033092607056"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="92f39f7f2a869838cd5085e6f17fc82109bcf98cd62a47cbc379e38de80bbc0213a23cee6e4a13de6caae0add8a390272d6f0883c274320b1ff60dbcfc6dd750"
    $a2="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a3="f2cead0c3c9e96fab4b6bb221baac8c403af192129b209f256a18c6c05e3dda71580288febc38e52f359517432f0a273a1471b8a169e03b6da24505181d27789"
    $a4="353ba90f8c0b3e0f355a3d6c960b7caed5f2c1412992277c0669a04a62e7dfd35fba9f4631a7dc6d00fb44d93d305cc0b749c7501d9ce86f26148d05101b8324"
    $a5="fc623e91c091714d1bd3253607c41b3e99a925919c1439e21dc06590402db08a6dcca55a27e4071e40ca17f7d36fe016f9ca523e97e819100e351a56dc662b16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="ac9689e2272427085e35b9d3e3e8bed88cb3434828b43b86fc0596cad4c6e270"
    $a2="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a3="f9f9327b117123ad004e22276442a8ba793f0db4c6266223d31f213c603d9ed2"
    $a4="fc613b4dfd6736a7bd268c8a0e74ed0d1c04a959f59dd74ef2874983fd443fc9"
    $a5="fcfb1c875774fa6c23a3a701b78952c153857efe8ef5514706582defbc218e03"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="c4717d406b24c889867a4216e46c6cb553d9fb1daa43180b306813ef5d552677554953f92e2711668757433fc1976ba9c8e66b0c6d375b40fb605e72edd835b0"
    $a2="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a3="6900131c6ab65f150a110925593c6ef5e27bea2d2f7c5ab20ec61b84fbe06aef54173c0041c5cd9e9dc611498d84b6f989ba352785fd0683f0b9c2dd95712ec4"
    $a4="33ace3eb11c517be804f516ab407838b51c6eb5baff3203ce3a320b6750bd1bcbf7091092555a332abc4d467ef3c13fcd9ff5312aa0036b98ff1b29774d55f4a"
    $a5="d1c53092b65f84d48a68097a674b548b6bb67ac4144b3e1e459a6506e721a52b6fba53cd6908564bb56dec4e7349e6d1c3c6cb781201257d23796ba5551c9d7e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="7d140aed39f1c5aac91290d17ff10a1994cba21340a92d741a9c0286be14013a"
    $a2="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a3="d26182faed3a47e14868d1c22aff1cc5e22ff4b1fbe8962f3b334e3b35ce185f"
    $a4="2f185fbcef16ddfab9451925d69b0af28181a7a5efcfa9c6b47f76a2aa430e9f"
    $a5="8318cffddcc7b9dfc9b1a4686f607e265516940ceb8368ee3d35fa3d80395693"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="3bc5e50481c727313fa7a4aaf7fd28a4d9572d828a1345ba103d9df4"
    $a2="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a3="12db234edbcdc0820bb0fc91d05d2ddab42eae0386abc6ac77c45f05"
    $a4="03370c307219d3d33781c917e10df30471407b8097cf71487eb63c69"
    $a5="44d674cbbca9652ee41799901d7c22526054a4a6e0e15d83747c89f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="9fc68b83499793838b29c32aa0661f4ef2cc03f49446de9499bb5d17994c850a"
    $a2="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a3="6c1399bd25719b90b17bb05a4170ac1c9ecf6c95511402873ddadc77b3f05bec"
    $a4="8e5d79468855b0aa30152460f869669ebece49a748839c70f19d17bb2a2239e2"
    $a5="40e78fc0cde06cd0126ea72c7080364433068fcff61a73d1236d8e802fc5fae6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="6e435bc01e97a55221c5077fdc20035a50d0df4c496c2a2366be9be382b5307499b17ead047b3d49c2622cc0fbac9679"
    $a2="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a3="a9d6dff71f0b196db07620445af4141f5a622dbfc7a2b81ac14f2bca505e7a7966cd04e4b1f822775f945063b3f7eaba"
    $a4="06ff6516b10e34580acbb5f2b05ae2628cc1c661fbb3e50b31dac0d0fc5be94784163e820aed296a54555a0d4ecd0190"
    $a5="8b70e863e504e52c07cd07d5996de3bb6c1d04c9d1121543271b89354c594e1f931c27ab8ba1d48ebe20541ccb515b97"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5db0b6d6a145a4d2648a18f5c24feae7d2e82fe9197122f353a145e4d75346b6977ce57b9b404144641856350e09cb53f706ec1fbc9b637f2a4fe8c1933d1dbb"
    $a2="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a3="a30add93befd90ffed288e4d443ed7823a8c72415eae79c481ca84bae2db8daac507dc10d77d6e28da4d168a1ce338ab9f7699b81e51ec4be6cfb50c2ffabf67"
    $a4="c56f59716f146eba7b862cf6a1443e68a3cee348bd8a6d51dcaa1ea5c52b41692ebca2e96063db57158e82f789a429d2723b0d84c3a308e198827399448c9090"
    $a5="d5ac09c53e096a047b6d66036218444e75b0d7462abcf774736dee7cd77ff46ff2539c13bda454da24e0614a51074a99c7cb9f7d4f6a27a790bd63d208fab34d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_rsa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for rsa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4xMjM0"
    $a2="YWRtaW5pc3RyYXRvcg=="
    $a3="UlNBQXBwbGlhbmNl"
    $a4="bWFzdGVy"
    $a5="dGhlbWFzdGVyMDE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

