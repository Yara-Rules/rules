/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="d6253984f6416246a10e31efaf7ce0f0"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="5f4dcc3b5aa765d61d8327deb882cf99"
    $a4="9549dd6065d019211460c59a86dd6536"
    $a5="944a4dc4ab890a7bae55a7c55d400960"
    $a6="63a9f0ea7bb98050796b649e85481845"
    $a7="d2d47ac5be4bb0127ac168d839c6e62a"
    $a8="63a9f0ea7bb98050796b649e85481845"
    $a9="c33e0186aeb031ccc645e31fc5233066"
    $a10="63a9f0ea7bb98050796b649e85481845"
    $a11="5b3aeeefdfafcd5dd385a21d48642d78"
    $a12="ee11cbb19052e40b07aac0ca060c23ee"
    $a13="5f4dcc3b5aa765d61d8327deb882cf99"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="27e3e6ea392307f86af9d0a1404b15ae27d7070e"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a4="7b202d57f214af016fe2923be40110740dd5bb91"
    $a5="9e16a685bc96e1717ffa25713c3defd141d24fef"
    $a6="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a7="a7b7d074bad56483bbc9c8c84d8137f206fcae2a"
    $a8="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a9="a681b1a529b97fa4b4bd2214fb9a8ac6b2297fe7"
    $a10="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a11="fc7032fb8a794c9f1a68907cd8c1d74fa7e5dc38"
    $a12="12dea96fec20593566ab75692c9949596833adc9"
    $a13="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="166bf8db77282ff4163af685cc2c36fccff42d2af7d83dfa0edbb900a87c3685b8c77fcf3320ed608e51a9e42f6a2e2f"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a4="a35e580c5e221b1031137ad24f272e05cceb72d5f7f6821320e7ba0a883154491948600073e063ef9d89a91887775aa2"
    $a5="102e13d0ec054aafc760a18e5b91637b4ae9706e40e64c4a1b1bd98b1b1bdcc14a48c8410d22f264367b41575f7c1cb3"
    $a6="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a7="2e4e826575449d44d6ff35573dc6567d87b3e9eae808ddab07ec439c23d54558955a9dc5c720a010e7292681a002066b"
    $a8="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a9="46776ca3f232df01dc5bb25abb9ca0e63e1f2253e38ae2d3b07a8389f26e8db0fa526faebb9d7c9d920e13a9f788559c"
    $a10="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a11="0a3d955645752ddf0caa5651b8003c646948f054b99f54d8f107615145d34e798094da981d057814a5c841b6163af0ca"
    $a12="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a13="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="88a89826f5cf17caee53b8f054fb5cb7e54809f8de3aeaecc7a6de16"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a4="aaa4bcff925fb93b9014e8d9f80453e7f9eed710d986541b176677c0"
    $a5="678da59480e324c87dc0a08479b25ad36a56746966ec0db347eb1700"
    $a6="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a7="4bb4ad5f08f86191dfe22bc534613c50096825d9b8500fb3e32a5f55"
    $a8="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a9="208464db6cc2b9f7d14779c6640b9abde4cd210726afe280926cfcfd"
    $a10="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a11="bddf1d3f6f46a4ca2abf6e1e1174a6905d7e632a94fcfafd30205997"
    $a12="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a13="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="44d3cf6a7598dddd40df331a2e1581faa7dd3b6e70eb5124b99e4012eed6b4977e34e7bb522f4ffbc6d4bf3f627f31e740f1ca3692a80b384e0b6bf94eeaacc4"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a4="b9d3bbccda0a4d0637df4e086a9f2e73f7a8e0eda030f75cc7d499b2907b1da15220b2a5784daec741c37ab5e3f97eab3ae5e091427f68d272060a8479278423"
    $a5="00972afc59ce76796d2622a1d88458ccb7ab2a9d919530da858120f957f7bb04583eb4f153801d2f3f11f0e7f4a9d00d153677bc5c5865b003a6c2b5b420fc58"
    $a6="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a7="e5141d9df152d8c4c74c0aeb22daad0e5ffa0670aa73c6ffc9e387c71f9b9cddb94bf5f9544275474f30a60f0ec7caa1fc20f898c68518993eea117c38766c40"
    $a8="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a9="690c8c6f049d5113d83ff4ff996780bf2db62c1cc4cd93c3e10824d703c2a3636757c1d284bd5da2e00e605543406817b51c19bb2ad6782120b3c96ecdec87ac"
    $a10="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a11="5f08037f9bb7550d408373dea93c0bf2be42b6b63f40e6c11f07f209757f48eceed04124b74b43d6aa52a760073e71cfecc6b4942f35d4b2e7b6650c2f4ba235"
    $a12="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a13="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="36b2411d09c038ab4968e54aa1ed723acc6cfe3fecd46e7e889b0529c0d4af02"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a4="06c8aaa93d80a768829b6005973fa92e34612849b79910c8be8e3b006cf91c61"
    $a5="656cf178e57bff129cb143d4761ad71cbc750e0316da61a1df4f1fe83ee49082"
    $a6="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a7="874973fa6baff5c4741c19d3b66137062bf7359e035491de626bdd293e172118"
    $a8="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a9="e88e51d746df3d2c0bdd91d42c235998a20a4c3df950462486343a647b174d76"
    $a10="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a11="b75d30e0078353d1e8394273a44bd52c884a9b2e780b3b5976b7f522d333aa3c"
    $a12="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a13="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="e27e79426a01b903f005c3ebf81406d026d7dd9d4d557cbd9037af3689fd18ca44bca6f0cea2781938a502b3cc345aa9e8bf040c493665a468b94d5d1880d1f9"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a4="22261d10bcffd6738bf1bd49af3e89c5735657430117fe58280df017b2c4b1970f52c94fbb44ca02d82c95c92f26e54cd8e7be5b6051ca491db604a2c9f31135"
    $a5="5fb225a4323029697683fa51a5afe1bb91e39be0e0a7f5263a2ffdb11fdd589caed3417414ee4bafcc17703197928d4494ddc4fdd51407b4564a474c3f2db041"
    $a6="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a7="ffd4a948a085123044f9de5207ae6f27a055604a83ae11caee4c79974695fe4d861e00de53c70fde8b40c5b09863fb7118b3c95318d7d4d430e5522c8d4c9fdd"
    $a8="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a9="4bc5289d1eb9c2896cf79c70affb0f661de338513e8c41f844f27856fc522d1739bb75a8084874b1fd07b1feaee5e635065f57d945e9b9e477189e94a5640b03"
    $a10="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a11="70123a3d05a3df56a32cb28213acbee215b8caf3bd25d0026d0f73280d692e0937f59e308b7d1a6c9f2ca245027e07528771344a79f13e4bd6b452de9fe5e9bd"
    $a12="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a13="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="31ed63e13f7f312c056846e740546d098be526fce08ac44e0e7bb373d0cd6d4f"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a4="e5509bb5cc9c58b36ac26478cdb1bd131ecffaad0e05aa871518f6d249161d90"
    $a5="9ab4c9a0549a6248beeaaf8ae5e4422ba50bba1fd754f5d91f71500022bbaa99"
    $a6="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a7="ae6d2546dddbaa8187393927065fb5f631c0c7033c18fbf1a98bc0b7979415ee"
    $a8="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a9="844f998d5e8ee426330b6106694dcde5e1f1c2dd39160271ff75396dd75309ea"
    $a10="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a11="5a759c6bc0f2b3cd12829dd7095254f4c0e4dd4b518b865cb003fb3312c5f212"
    $a12="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a13="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="cc2b9547d268c03f7f3ced4129df0c2322618d815753e62aff3e838f"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a4="09dce0ca05c368202e5478365e75ab15c529903416808e8a61bbb542"
    $a5="f90f2c99d36972d59353b28fb98154d2619b681dbc481a1fc88616c6"
    $a6="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a7="e6cc960a467d958a458008e3b63832a450d6e83f8dc213d7fe088450"
    $a8="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a9="bc9c2a8b440f42b11a6a557208153c5435d994fd4ad4dd45cb70a773"
    $a10="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a11="9de87879c673cac94dc6828ec80ce39914fd4680a986391aa5559885"
    $a12="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a13="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="7560a7f3f0cf0e66b1923d4f45e89d526af2b32907f5fca081b23c5f064572ee"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a4="d46b2ac485394ab8ef0a0f0fd4fe1cf11188dac9fc6fb4672f79cf9ca3f6385e"
    $a5="deca0f27c3ed4d9de7e471f4b18c97b2b022dc152f281066c9f7325eae9dc0d0"
    $a6="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a7="7661da70cefe6c7c07b429f7f482004eb90aee28b08835ed0c0ae18fd341e064"
    $a8="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a9="695ea791eab813ea9523c2d3d800f447146366ce0d2e0aa8fbdecab6fe74654a"
    $a10="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a11="20e96233e6a11d6ffd57bfbe41c79d90670057253d905ae1cd2e54c18aa70cdf"
    $a12="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a13="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="d98456f7b20aae747248f8751df51a1c4ed9ec3ee010ae92abbfb55562e34b479248e4d20e72a99bc2cfc04bd049f3c6"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a4="713c7fcf2680a4f564d9a03a7f0d7ba60f16c9e9012ffc1bd1e5ed4ef6b6d4bb32e38edafaf0b7d315766b3a971ba18a"
    $a5="67d399badf2943c0508c022bf9aeb8cd57ebd6e51826ba18e5527f9fab5ac325a1a9a0f6bdfa4ab7c81d1bef4a1d80bc"
    $a6="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a7="6618939d8b777092fd3c53cb9ad91bd4fd018c700d609ff610801a5267136538e4d2d856bb9d4d217fa705d85bcbe7fc"
    $a8="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a9="bb313411dfe2019fa21fdc4c88834c16a6959f079995e27e6f5b11f25b6aff255eca6fa2e27757186fdf33f5b0f4974f"
    $a10="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a11="f14543ad498291c14c51ace3e0cab7f3bfcff5dbfd9e107632088b2b8870d5b8628f0c434be1a652570dc52abb8182ad"
    $a12="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a13="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5da9b88d9fce0f291bb02e5c0cf1ddce000483486a1c609bb1a004907c9e4a8518e327cd9686c92e59d02b1dfe1ca315474f7fc218c95d66d6d7f00a979e48e3"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a4="ad0c9f9157129a815aa678c8464c440984c1ff2751ad4fe751af01b647e4213e75e8f1a9bc1a3b04bb5b97ba20617754131ff8accac33ff822a7fb05e92410df"
    $a5="1dd4032a2e92f759da53faa09dd47997e146557dbd973b66ffae88d2c579768afb2027fdae1b1cf158a77931104f95098cc92febc544c4aa2ef9253262b8d541"
    $a6="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a7="d0321f34513743e2a1a61be5298c2e3775c1d12fba3ed5fff8109e131b534f84e28b14b38a5123fa1026b91ba5e5ab4fc4719f1db4267db302e76f1999de8aee"
    $a8="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a9="23051c691d244f4355f15b68b586fbc4b7db676b3e545a779181511f515173e3393a17bb1768871291e450bb82a8c7bcf236b485999e5f5168cd96bfd1a014be"
    $a10="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a11="c1eb5876a443af248e9c003ecd7004daf84a41dc11e1a0dcbaa6639f053d27432464771a853e856c20aae5bc04aeb66dabc5872897c1ffb1a17e6d895c529ff7"
    $a12="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a13="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_brocade
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for brocade. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YnJvY2FkZTE="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="ZmFjdG9yeQ=="
    $a5="RmFjdDRFTUM="
    $a6="cm9vdA=="
    $a7="ZmlicmFubmU="
    $a8="cm9vdA=="
    $a9="Zml2cmFubmU="
    $a10="cm9vdA=="
    $a11="U2VydjRFTUM="
    $a12="dXNlcg=="
    $a13="cGFzc3dvcmQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

