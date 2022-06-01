/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="a1117d0ea5902113aacced93179f5b04"
    $a4="e3afed0047b08059d0fada10f400c1e5"
    $a5="8b263081d8170d67ef0f9e567508cef5"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a9="b3eaf71561d6b92546e8cf29a296873f"
    $a10="21232f297a57a5a743894a0e4a801fc3"
    $a11="b3eaf71561d6b92546e8cf29a296873f"
    $a12="d41d8cd98f00b204e9800998ecf8427e"
    $a13="4a7d1ed414474e4033ac29ccb8653d9b"
    $a14="d41d8cd98f00b204e9800998ecf8427e"
    $a15="d41d8cd98f00b204e9800998ecf8427e"
    $a16="d41d8cd98f00b204e9800998ecf8427e"
    $a17="b3eaf71561d6b92546e8cf29a296873f"
    $a18="257c2d1a0423a6a7c108632a8f963932"
    $a19="947f01331ab0db1b086a4fc91e7bda93"
    $a20="c21f969b5f03d33d43e04f8f136e7682"
    $a21="9b343ab63586ac023b7d8d2a75498e06"
    $a22="9fd977dad8b0e2231b7a2112faa889df"
    $a23="3f77ca96fb71e9443ba4034fac80fc25"
    $a24="52c6aaca28a6b621abae2db20e887dd7"
    $a25="b3eaf71561d6b92546e8cf29a296873f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha1_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="4ffdd4db4eb1bd5865a8d3b7a9cdbfb587465df7"
    $a4="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a5="f58f1c9bbbced2419818a0a2151e340adcc0cc8b"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a9="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a10="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a11="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a12="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a13="39dfa55283318d31afe5a3ff4a0e3253e2045e43"
    $a14="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a15="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a16="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a17="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a18="8f198fad85c1ade2c1fa575158726672d789eeea"
    $a19="ece362775003aa2cc452ed00d3c1fa5e0f7bf77a"
    $a20="7505d64a54e061b7acd54ccd58b49dc43500b635"
    $a21="5f5020d67d0b633e59f81c0a9353fc67f328b0de"
    $a22="0287e6f69b8d608a1e4e4582519f4154d1a04408"
    $a23="bd71c71b4ea02571c9fe058b7e9b2aa2ea2ccca9"
    $a24="b86c9d332f80d68ae3c274c984219fbb999ab5ef"
    $a25="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha384_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="4bd8d4ae7789627ae3cee9192ea7e13b26db483040f47d1c8fe094d66cb09b6807fe72cc700507afaea10f5fcd60ffdb"
    $a4="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a5="ad2649a34d1b07919a1c5886c89aa74809274c3c54cc44b0a18cdbf433e04172f953bd243da3bb6965681404f40b59b5"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a9="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a10="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a11="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a12="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a13="b034e6d9b4da9ec8962957bdce03b507b67dd5d40f821ab7f732d3591283253342d136c55c8eece0e1a50e1f724c2dde"
    $a14="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a15="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a16="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a17="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a18="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
    $a19="f87c1ebc04f901041f18dfb7d24bebc6d45e1cbbb2d9f005605e47afbc6d5d56356e3ee5f7762c5373219eb2ffd6554f"
    $a20="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
    $a21="3e333bdcd4a8e043ca4d1266960829915639577294c9cec1743e0430234a8a779516642c12dc94adc4051e5f594dac6a"
    $a22="4b616013976cdc35c752303ac396019ea3e5b50a3c3cf8ead6efdff067e0c4f19fcec3fb37ed5298a51d644c968feac2"
    $a23="2340e5007830436d3e20f2b682ce17a72e6a4fa429e1c7004bd9ae9ebea5c43cf9ebd01f10397b6baebdd8b3410ae926"
    $a24="6e802f47b8d123f24b93f8d5cfcc091b76ae2c87411a75e6be23a2394f06944658bb9b300086ecdeb63d34db974846ce"
    $a25="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha224_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="d02105ca0dbbd0cc327b9e08133f58c8a8f0cde6f53ed0ed71d2e6de"
    $a4="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a5="82d9c3ee2ca2513164aa2e8fa3c0d25e07f2d7393e816b4bedaf9415"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a9="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a10="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a11="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a12="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a13="adc91e03060b42e7836bdfba7ce19b3bc1297d234fec44585472529d"
    $a14="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a15="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a16="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a17="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a18="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
    $a19="cd67b76f75f4577b8c0f9541bb4658e24a34ee90a9fbe4f3a46bed80"
    $a20="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
    $a21="d7fa4220dbdba075c082e72b446d4c022ecef55474fdf085de543015"
    $a22="6e9642705c45d7b717574d3fa6ac9e0db4f5fb59253b3485d7881872"
    $a23="464a4808d15d53e3a9ef3f3351a2dc9b59bf2ef819823f35c2948322"
    $a24="5fde807d89bc98fa829ab5c847c25c93c96faba025cd2e5a7f0d1ff5"
    $a25="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha512_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="234916c8a5cd620971052069ba73927b79c45485bd31054a1b32209aa905a783e45d692f779c8526c32b0cf84b5bc69a2ceae2b2520598714c37ab0ab9484a84"
    $a4="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a5="10ae165956e0cf9f3159c052bd39f781f39a123c150ccd82bb0dad7a9e038b42a9ba432e62fcbdf9caa1e3e73a149a91ecbfb965f7dab3b45c90fca653f4f4eb"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a9="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
    $a10="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a11="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
    $a12="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a13="c6001d5b2ac3df314204a8f9d7a00e1503c9aba0fd4538645de4bf4cc7e2555cfe9ff9d0236bf327ed3e907849a98df4d330c4bea551017d465b4c1d9b80bcb0"
    $a14="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a15="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a16="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a17="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
    $a18="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
    $a19="dc3283f0dcc070a4434448ab2bf8caaa3b546bb32ea44a1173c7f7fb896d21c087786050eef69ad3e7541b546ee7a8f61e163a5749de0089502a401e51f19b9e"
    $a20="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
    $a21="7486d08905d6a2342bcc9535add0a70e783cd9a566d492bc538f2f444ff78f7b9971ce5bbe6e82009777da78003cbbff1aae5aa4cb36a288d2e0114dda5121d4"
    $a22="d06c22252cd3bfd3f487da8f33ff50c7ed5e537e71bb34006b7aefaa7d641ad8f52c7530887c3ac7303c54cad419398df124e02c29c56d60f4c71963ab295a51"
    $a23="523fac79ac1dca3f3aceb5524e57a61c4af19c59a448f16a7ec1ce3d20f23b3893e3703f202cc83a2bb59269e786cd09faa8950986b24bf4a8db50c559bf28ae"
    $a24="c50b2a559d87967ed9b83ffac046e58e4079b17a18e60e74324760b9452d7bb0ec91f2de20131aee28a31234a760714493717abeb494e7818dd5665a156ca0aa"
    $a25="a7da90cc415307e664a142d87a2de14c02a08fa0c8a2b90b4135cfa026715f89095bf711e65fb4485725f0d0d72b58a4d0108ca2e9ae2f38ab5efbd57728f889"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha256_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8189746886056ee6d6fd972305266512644d5160ebf412fe049157d4458a2a36"
    $a4="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a5="3a5364b82c10fd33a3676e2e99ef5b46d8c93c9ecf115ebbeb09d5adde45fe47"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a9="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a10="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a11="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a12="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a13="9af15b336e6a9619928537df30b2e6a2376569fcf9d7e773eccede65606529a0"
    $a14="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a15="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a16="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a17="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a18="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
    $a19="92563d2553584ef62ef475e3600bb4acb6c40ebd3ba5262e764272a05074a7f2"
    $a20="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
    $a21="89292d1b3103ac3cd6a0dec5c9168e9b636e8e0346c940bcea67d1c343a97585"
    $a22="f73c1c8e2facc4b6f4cacc8ec891c55c2f7363bb9f84ebd007e7c947d63381f3"
    $a23="324dc0fc79e6ed2f5ba548e90d23e7600e5a7d0cf072dc2dbe17013d66534551"
    $a24="6f166e778d3e08c067dfe733f47e38f74c59817c268e7ec633c74d34e6deb56f"
    $a25="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2b_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="84fad0f12fb8bc5196e490dfaeb95caab93c5d37e81f1191085cf5c4a3203f9c73ffe7234c9577f69a37ef87512c556c9ee417c3334add4de91a8516639af1a2"
    $a4="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a5="8ac62a73ded609592ea02477c9c318855e29d60b1bbf836e154d0d5f354568739ed3ecb3638292800054f619efbd6d9c938a529868c42299c1ed2eba5713f25a"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a9="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
    $a10="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a11="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
    $a12="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a13="3b8565b7d15b7cf1cb681d5bfb0fff2326212746772d6676d9daed2eb9422c0b1fdd6446c4c18127e2a791d431994935a69d6ff468916167af1db23d95eea8cd"
    $a14="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a15="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a16="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a17="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
    $a18="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
    $a19="69baf6e415c26242d39904368c39f644eeb36eab71912c8aff38911aabab0ddc03317e9c93d209a8306a8789a51a6b90abd5e04a4454de5afdedc95314ff45c9"
    $a20="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
    $a21="6baf6ae31000c0b078d6aee708e5aaf13cf2c86801a0e983309db234d00d09ddfd0475463f4bfa87c86a873a17bd17a3fcbaa8119c78e37ac3c291927b790552"
    $a22="329dd7e6add3a733b61f11c8058eb9feb8576d283e4d96935b6a18e7fd86b64e32bca47758ed11c54421841464fd19047712b06e61682b810790d7487104a7f3"
    $a23="15971acb6dc55aa1f23e3ac4ac09b17016fbb0e98f396609c7fe22ffd41500d7d54d1e62ee4fd4a49e7ab8136f3e45a3233414029fba5dd7f44defa9ea42600d"
    $a24="a2efb8e42ae1cf400bfb9bb0504a0db1a5e15e6887ed502bd0c9159299dbe1e09f39adfd7981681e7284b7294bb08f716e2c88cc3aa77529d0555b45a925e5a5"
    $a25="d370e850128bf8e0e7ced28d2168009877e8ba4e3f34d060ba376911e63dfe0b56a05094d70a02e220a4d8a6c051eeae612609c50fc50b2921447ce484d0aa03"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2s_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="4ffc5bdfd33a24fbe95c11c318697b883b15c93ef72d06b45e2660d1d75179fc"
    $a4="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a5="9b47cc1fbf17788ec8a5fdc86e2ee8d92068623df36eae7217468620a17f639c"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a9="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a10="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a11="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a12="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a13="1b23aa0241350289fc70cf9372437d9a021b875b8baa558b15b0b7687952ec73"
    $a14="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a15="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a16="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a17="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a18="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
    $a19="a3866d06cdac0a0e9d7286439fa10193cc2f8a9991444dff01a5c1b8955ee428"
    $a20="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
    $a21="40fde414b5d75d32c01f34d9f05bd86752a4c3ff4244ae1c4071856eed0b19ea"
    $a22="0d0ab17836ecbf9bb500e19a403333b23639558fd32ed3d95d2f6b9b8a52259f"
    $a23="231a00cd8d05fda295e915f2c45410d3b529a0dbed95bdb181a7f1dea5e68a93"
    $a24="551ef0607965136474e543d944d5392e1bf3ea65224f77f90f7e524b7b88be25"
    $a25="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_224_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="c40c0066051109e6be0e187914098b30e226d67555b5ada283a95def"
    $a4="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a5="cb728babc0fad99e8568d29b85f963fe824744f5fdefbfa2e6645f94"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a9="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a10="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a11="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a12="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a13="70afec1674af6485ab6713729de000542e1b43d45ba368f55c271c41"
    $a14="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a15="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a16="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a17="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a18="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
    $a19="9976702f28a05a97104c42c54485cc5ba9934c2678cfb760019f2b3b"
    $a20="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
    $a21="ef104e45e2248bda1fc499d3b77ebd7e857a3aef8a8bdfcdad077bde"
    $a22="cd2a95bf34c36874110599b4da7e44326c8bc8e17e91753dba17228e"
    $a23="798853769d763e8c45a872e54953992c405f029f93dc99a342887a88"
    $a24="60d14e19989ed5a1b03b31934f189be69766c5692ae815bebceb4390"
    $a25="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_256_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="0c251f4f9fb5fa97f7950461c2d2fcbf8c2aa4cd1d86319053f72e90a4a56af1"
    $a4="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a5="8b20283aa7cba959cdd356f03d0db09434fa9140a72caeac7677eac37992bcc5"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a9="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a10="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a11="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a12="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a13="a6af70b7af3f42352d783e8b07515e433c3d45669d4efee670516727193b291b"
    $a14="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a15="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a16="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a17="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a18="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
    $a19="24af0329dd22bcdf3805f1fdd579b30681ebe2c4c0b89eceb528158b64cced67"
    $a20="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
    $a21="82c3099b1c7c22250266ca625b7b6294387d3e1b462bdd0b51937032dce79c5a"
    $a22="81197174dc203f5440ff4e2abc106556e591648ac6fc30f50803d69e31911633"
    $a23="8763b9749ecb7a87a023d92dd04a60cb7e3443f1cbb040a21145713ce9c70b24"
    $a24="06930fbdce4d7fba6cc4c3bdc7f5c2d20bdfcfe9ee51364be81e119e70e6248b"
    $a25="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_384_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="c488bc88d9a5f41f36fa285cc2b44f8e6f9b171f33be64daf3a74adac3d555b241ff898ba8043f86c17acdefb359c1d0"
    $a4="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a5="0429da6051634207233ce1e7a6f5dbd59e56b606138bf1c8b0dba1729129fbf482d3f0ae2804ccdc1ab485dd073a060d"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a9="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a10="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a11="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a12="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a13="adff06f440f7f2ec74a4141631d1cf89a142a28a58b252516e09027846a40f35608029e5b46af8cb15d1cd552262eaad"
    $a14="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a15="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a16="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a17="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a18="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
    $a19="1d243ea48da2020cde4f09bd8d38a01876f099d53bacb37cffed21309dd399c9cd57a4dfa671c06ab2627c6eb5e23f99"
    $a20="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
    $a21="99c6b10c4aed4f0d55b9ba3a13ee2bc67207fd3bfb3969cf04449b4630d87885844fa701f0eb6aff43b84242182e632b"
    $a22="8297ad20b40298518832407380132303d05a61a28c2009d16839b0b461188c3bf81df28c0082f0830049ce4a439ae7e0"
    $a23="e40da1fc6ecbaaed8050379007e33d86bb116367495b90bf7bdd1dc93c3b5578a42f883e1ea9061ab8ce45e895f08c52"
    $a24="597796fc80368aa98896760b7a2c66de525e5472ffdea59875a4eed2c9b28d8e3840003feb7e3f5124c964fc7632a08e"
    $a25="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_512_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="d42ad07b936dd598d8aa24b2f35007c7219f70c6d0b730d0b8d22cd6125d20836b7db2a2ced7cfa22c911d7650ebf9741b05c593788b33b61087473e981b1207"
    $a4="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a5="5e51bd73ff2054acfa90787a02bc083cc163511de9e4df84a51159a22dfd331b38a030a9794705e0e1adffbfbf83dd21501903e964673453ab317025f6d268e2"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a9="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
    $a10="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a11="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
    $a12="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a13="b678ce98622f627b5b35ca1e8f656f1bd33545d242b59f015a31de938afa3afbe685385b8e3cc9ff37d8c2af86eebfd319eed65abdb4be4181cd42ee4f370f61"
    $a14="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a15="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a16="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a17="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
    $a18="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
    $a19="92412f3f01247436f1201394d18e7ad4ed5d4e378f50e01a0604051924a9470882b53f8cd3818e0d736a2a013d7dd4099c3ee8bcd8b38c3f9c796fe4a915589f"
    $a20="fbaf1d3516e4849991e8eaa16e401a9d0cebad944297cd80022f9424c8d9d172f7cc94844f529cca51005498f56ca90672ca918cbbfc06c0071b9c12b98f89b6"
    $a21="5c736114834138dc922314c1f993b6765a8d3ce96ad902a40c294dee828f3bc223e96a3d4c3653a33c3af1133d0db4698f3f9fa64210c0f61d0f557bf63b56ea"
    $a22="b6060e997af54b34d3f32ea50618ad3aac9dccda5a57e90dc7d78f0209371e32cd6c7acda5d2f8090a4410053b3ca67fecc52765035450f05c3dcd61f6b0d2a9"
    $a23="c62bf0987ce54d22a9e3e9d0951e282776777e281cabf4e1266694c6715f7de7e3204938148442a570fce689bd7b59135aa804954097544ee167f0d6e37d41be"
    $a24="6fd00eb3bc5a865466378bb825d765ccd649b467acdf00761c503d703ce2024a183ac6dcaf40bd6e15adef030826d6bdfb1c4c587da53e10e415b691b7bfbcd1"
    $a25="c3b1b3e2ece320eccb83e1967d31832cda664a0b1aef72abe8c1b3ea2c46c38d5b631edc3573792c84006d245587b19a6e2d94bc36531f7e52b0669874ede7bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule base64_hashed_default_creds_smc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for smc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="YmFycmljYWRl"
    $a4="QWRtaW4="
    $a5="QmFycmljYWRl"
    $a6="YWRtaW4="
    $a7="===="
    $a8="QWRtaW5pc3RyYXRvcg=="
    $a9="c21jYWRtaW4="
    $a10="YWRtaW4="
    $a11="c21jYWRtaW4="
    $a12="===="
    $a13="MDAwMA=="
    $a14="===="
    $a15="===="
    $a16="===="
    $a17="c21jYWRtaW4="
    $a18="Y3VzYWRtaW4="
    $a19="aGlnaHNwZWVk"
    $a20="ZGVmYXVsdA=="
    $a21="V0xBTl9BUA=="
    $a22="bXNv"
    $a23="dzBya3BsYWMzcnVsM3M="
    $a24="c21j"
    $a25="c21jYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

