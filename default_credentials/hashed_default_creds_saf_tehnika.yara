/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a1="f4a437999d6a7ab8dff90cdb70c7c156"
    $a2="946922b258d486fa96254d7886e27b32"
    $a3="9c7212a48ec6eeff96a3bf973eaba6e1"
    $a4="08b5411f848a2581a41672a759c87380"
    $a5="08b5411f848a2581a41672a759c87380"
    $a6="4b583376b2767b923c3e1da60d10de59"
    $a7="a2a69ba2bd9b5494d3ae482b82e8565f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a1="82057a39718ef5802f9e203600d69903a596e6a7"
    $a2="e068514ab6ec7f27907eda03824943109b68d98b"
    $a3="e0c594e66a94853423e5c83e70a0d0fb09d9cb51"
    $a4="9796809f7dae482d3123c16585f2b60f97407796"
    $a5="9796809f7dae482d3123c16585f2b60f97407796"
    $a6="fe96dd39756ac41b74283a9292652d366d73931f"
    $a7="13eaf6c11377de40d60e2bdb851f3c3b60c1c571"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a1="cec6d8db288f655e818e6642c913d4f6182fb1a2ec4dcdbbf3baeeaae6814074a5f5b2e7841a2136226be78ec7d39f81"
    $a2="287b08215a74112b4f95497b2b5e3eeb5e1dbf3450fc2734512f69072ff0e4122672fd93edcf71abb68eb2c058a1d97d"
    $a3="fe3bf047812714179c282fe1ab57b674dd3c6fdf53b21e98fda3e3fb80d82f1bf0c9afe68f709c9995a9e963ee222dfa"
    $a4="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a5="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a6="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a7="ec5320f37098993e1881aa925836966302ae51c5f3bc44544371567f5c7650b59f700e2da36e69760cd9a3dd0af6f543"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a1="52f4d3c7715abdba48b86d9d7d506c17137e68b65ad7ec2915aa70af"
    $a2="dde324f09efd3b7450ae469f283947826ab09469ffbf19dc43e7f996"
    $a3="63432c2683187cbfb17ff090d336b78ec31194b5b1a82de9d4048d0a"
    $a4="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a5="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a6="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a7="98f311a1909f9b2998431a3a599c4d2725a9f7c8458c917df8f1a64f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a1="ad8239a8e8161e83fc937d43aa1a7bfe7a3e2a25350005cc550aab0a422c62ce0fe69dd956d0543cab51571bb94782bcc1ec44a99351d309da5e6837703859aa"
    $a2="c0f50edcf23a4297560dd2bfdd967f31a7b39c5ac60ed6e543f360bcd24188694346ba95e5ed1a8dfbcbce64c693f7998252f8cfe0f5190a2af511a63cf60532"
    $a3="324425ea095bbbe73409c1d2f696d122cf53d0005236806c190af038d4723dda08f456dce264946c94da2633e88edb2139c65512ae27d70f4259db2d618a8ea9"
    $a4="d1a29ffc0c004008f8a6b5baf04a220e902876bf03758bde949c995c8c7fe9bf1db7c4e9d30d42761675d6815022138eccef2a54fc24d586aaa00939f261cc2e"
    $a5="d1a29ffc0c004008f8a6b5baf04a220e902876bf03758bde949c995c8c7fe9bf1db7c4e9d30d42761675d6815022138eccef2a54fc24d586aaa00939f261cc2e"
    $a6="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a7="81bba172c1379b4012cee70cce0151517a041591ff726fcddbbecc22c41e4bb49b1b8165bb9b6a23b05e76c0bc3149dd6f129f33d9089195de1e0a42a0487271"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a1="389e10a474636c2abdd57563c280e18ed45d3c945efe3b43496b209a7c0cc2e6"
    $a2="168196d133817ed25c3fe0bf9a5254309ab899daa622e81d3ead0daf0eb33def"
    $a3="41be026a4d4176681f15565f9f9f7bf8d41bd187795fedd8535f36630ff39aed"
    $a4="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a5="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a6="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a7="2ff21e440ac5f885fe8a43b80bf2fdf88af461730ce3afef950f8efa840af993"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a1="b2192112f9ead44efa931eb44022a832d9da272a961913b1199d6727a28f505ee4264f4fad018f55e7bb5fd94945bc75e9253e6339eaa566abb6bf16c6fe7636"
    $a2="1cf06fe11fd11b8c2d217218eb54d0f8139a8a42aa9b2a39f075f483e0d4973cd3ce6a16ea6482280dcdeae6041192a97ceef6e50a7f01e90f81d4df4efcad11"
    $a3="bd3e2b37a678e8fc512bbaf5a948830a0fd1b379b96d652aee301965d049e84030bd90810a27da066086f5ee79828dc7e351a371ea70a662a22478d5eaf345d6"
    $a4="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a5="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a6="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a7="662bd758e37a238307d407df11f2807d2c0634f1c007cfb1d6a4925b4d05fe34946cf7ebdb5c029bbc7b061ea198e51a4ad890e0ee95aab398b3ac13e7ec6695"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a1="f11623c53c2151d2c3ecc2291f32a93aa363c101ebed6fdc0b4821e5c0538d5c"
    $a2="6681c74838cb645934d7e8a8c8a510e714e10cff422f28f9e6b1aa712be98f02"
    $a3="4fd1fbff45321b03a04f4be3da6f0c8705e62d43dbb3cd75a94f3d6122e4c717"
    $a4="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a5="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a6="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a7="fafb96c8f2dacb1eb883d9fd7ffce1ca512d0a2f964e2a5674fdcbea01a29a98"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a1="50f790af2acff4bf64b7358d7d178cad3808f2d84414bb9bbdcfe79e"
    $a2="015992deb8b7e19faa1bac5a81ef83e4a2d9684aee956eae318281be"
    $a3="cf97cd55d38df3f5b2f18cf06ca8dcbebae08282c64c58088f80a591"
    $a4="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a5="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a6="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a7="da894a523ecfa6f6b52a8e9d8872608174d2be3952fc6bd76184db72"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a1="7823ddc39cf0edafe9b75fd43d026530fd370a94e9a1d6a7bf3620a8020af9e4"
    $a2="130b7c6c9040885eb45c54641120182aa82f6d562f777c320cac42bea954c34b"
    $a3="09e5aed71673f3e3c29c4821dbab77c91f5b641f1213cb5866c3a6c487bd17ce"
    $a4="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a5="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a6="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a7="29f1138ca2ea0780312f640305c1aa9116ce32c3774d3fa5370efc29953d3400"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a1="a46f29a6cb8cf6ece21d71e1e888c4ced518c25efc0f262efd62ab248a4baf3139e7854082f9af0b5ebc1bb02a4e5457"
    $a2="3efdf8d53a6e0b2833efe8caec234b3630ba633bf9288201f8a33b4fb0b47a253e0023deb921380ecfc1929fdf688816"
    $a3="64dfb65e747323846aae58781fd8db6f6b811bd99caf4c1dad293b101042f12336f3035d7cd44e333f308a35aa8c25cc"
    $a4="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
    $a5="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
    $a6="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a7="de7dfcfc3ca6ee8d4f4944e89853e4f47d2325178761f052c482d9f31db0e1bb88837b0fc197a240283c7f89ec292370"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a1="f9139780241176e5b4893e5d4d21b7441a0cf73e8d37d66c12050d7df79e9ce5c6aaa46d245d7c06dc991d0e2b20f2ce92509c0ff8c96f54dedbb37d66181c19"
    $a2="a2810f0382736604523e984c8d807de8df281e86703bde676ccb103867ecbe75e47241ef02eb3d5159eeca9508f1284d2ee9c55c96d1e07e04bb0ec0c1cc282f"
    $a3="3bc35cf93f11647d01b47ba9e90b757e7a816d84cc499cb59933e8853cd677673c309d7f45063fadd26c576e1e6385899d53edbd293fcfb0fb68b3e61250c541"
    $a4="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a5="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a6="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a7="87e5fb944e7225c1bb2a13accae75fde5fa9b257f81bbbfd13d2e314c4549aafd1a2122a512bba1482b5805ed9e8425969c31d995078cfe1f7dc397253c43005"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_saf_tehnika
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for saf_tehnika. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW5pc3RyYXRvcg=="
    $a1="ZDFzY292ZXJ5"
    $a2="aW50ZWdyYXRvcg=="
    $a3="cDFuYWNhdGU="
    $a4="bW9uaXRvcg=="
    $a5="bW9uaXRvcg=="
    $a6="b3BlcmF0b3I="
    $a7="Y29sMW1h"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

