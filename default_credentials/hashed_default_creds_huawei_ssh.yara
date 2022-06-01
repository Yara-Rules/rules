/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="e3afed0047b08059d0fada10f400c1e5"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
    $a6="62b9603582c02b025d479e91b00ed397"
    $a7="62b9603582c02b025d479e91b00ed397"
    $a8="2cc43538e62cc90345e155922056a1b3"
    $a9="a016b28a2669f876cc24e9b3dac1bd73"
    $a10="ee11cbb19052e40b07aac0ca060c23ee"
    $a11="1d20a3f049ad11f799bd5cf2f6a2b541"
    $a12="ee11cbb19052e40b07aac0ca060c23ee"
    $a13="ee11cbb19052e40b07aac0ca060c23ee"
    $a14="84bc7eaa45ea2645f030a98e7866f34c"
    $a15="84bc7eaa45ea2645f030a98e7866f34c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a6="71741899f22a00c72ee4f74c613470664b6e241c"
    $a7="71741899f22a00c72ee4f74c613470664b6e241c"
    $a8="10ffe60d53e7703286eaab421f05c946ffa19a37"
    $a9="62fdbe21cf61f637191d971ab9a5caba51094aa7"
    $a10="12dea96fec20593566ab75692c9949596833adc9"
    $a11="b6497a0ad71538443248bde3420cbbda395fde00"
    $a12="12dea96fec20593566ab75692c9949596833adc9"
    $a13="12dea96fec20593566ab75692c9949596833adc9"
    $a14="59836eac64195796688a11780df5c4e2ce668b95"
    $a15="59836eac64195796688a11780df5c4e2ce668b95"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a6="793c090417a2cf388f3b608a3850b0d2a8089cb1c1e41bb7095b529867320b16ea72a1075ad5ee8b080b42470611646b"
    $a7="793c090417a2cf388f3b608a3850b0d2a8089cb1c1e41bb7095b529867320b16ea72a1075ad5ee8b080b42470611646b"
    $a8="a9636155bf36782c5afe93dba56bba5771148f9762dc0df829362edc53867f6518ed909f869f26ba0e994d2d53b2c6ee"
    $a9="89c276949ec33c3ceb06b06406606a8e72ccd0afd44be6fa167982445a31918ffbf223683ea695d1e8385f3e2766af14"
    $a10="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a11="c880b582c3edc04bc80703653a3f6ce71ba0836adea4d3b70632049b76a887b0b7df5a35fa6285e921821035b24ced15"
    $a12="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a13="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a14="b746cb73991dfd086fd2ced503a08cfda2154e9a30c1a0f28932abf7e9c48efe27d1a6aca4e6c585c4b06d65f79bdb30"
    $a15="b746cb73991dfd086fd2ced503a08cfda2154e9a30c1a0f28932abf7e9c48efe27d1a6aca4e6c585c4b06d65f79bdb30"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a6="838fc8b0cb7ebe2832d05dc3e7b373572b6f5381d19073650b5f30fc"
    $a7="838fc8b0cb7ebe2832d05dc3e7b373572b6f5381d19073650b5f30fc"
    $a8="7493a7051f66564aa3d1345443b4b5dc1e6c4ba5545171949025b714"
    $a9="535f266f3254bd5c3dc1c5d0a8ea5e5a3c113a6048f473fc86d6a178"
    $a10="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a11="007ec7afc4f088819773b83c16ca3cce7bc680a8019b9545223e0aa5"
    $a12="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a13="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a14="cdef3e7447abf28dcac458f6118fd8f5d9266e871e8c9861a7b45ec6"
    $a15="cdef3e7447abf28dcac458f6118fd8f5d9266e871e8c9861a7b45ec6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a6="8e8a26e46d810aa1206c7d87f62432f6fbbb5d0a7cc7521e8e33650cf3ac336908c6176d7d2c4769231547f8623ddf265932a42d80d4fa2cb20e5ea5c3c84c90"
    $a7="8e8a26e46d810aa1206c7d87f62432f6fbbb5d0a7cc7521e8e33650cf3ac336908c6176d7d2c4769231547f8623ddf265932a42d80d4fa2cb20e5ea5c3c84c90"
    $a8="47d1dac5aa905cf79ba459698cbbb442e7d2f9cd2a012720f1c83fd87457e05b4a4f0794547e673dc0b69c6ba5e7d5958d0c6de304d83a58c142dc11393457c8"
    $a9="868ff9386e3dea32436089cad85f840e26a0c41865b7bba2230c5acab4c01e791f8c606d33cfccd18d44714e147d6df33146a3f706f2cce669276f011219ea17"
    $a10="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a11="b588ab063a67925162377e16a86dd33ced8130b75facd77bf02a8c9bc34ed6c18917ac492107cb38345ecc35a432c5fad4d31c413fca75c2bedd55e46663089f"
    $a12="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a13="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a14="d27b9b86be2c1ee43c50dcae09b3c18e155748dd5a3624098c87bc933110c57d940b1b81c833c233a35036d9a1f065a0e519976a220ee31f7da2a93b78513edd"
    $a15="d27b9b86be2c1ee43c50dcae09b3c18e155748dd5a3624098c87bc933110c57d940b1b81c833c233a35036d9a1f065a0e519976a220ee31f7da2a93b78513edd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a6="94f6682f71fc007700c2190785710092ec7d0c59cec689e67bd77a20f6ac418b"
    $a7="94f6682f71fc007700c2190785710092ec7d0c59cec689e67bd77a20f6ac418b"
    $a8="bc979c4710136670e77b88916412901b7926e454626910433ba52db89e287f82"
    $a9="22358b6af3977915e7d095ee76a8a572e952adda4fab9e8e8841042d806afa27"
    $a10="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a11="5213f4cb8a72d3908b4ac8b665e09f23bcd8dd01c41395de403106ae3cbf7c9b"
    $a12="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a13="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a14="c09dee99967309b12c066143a662efd5fc01f4b628d337037dcdf3931c0661bc"
    $a15="c09dee99967309b12c066143a662efd5fc01f4b628d337037dcdf3931c0661bc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a6="e899f7dd47030fb9d0fd800dfde63b23d51ab9e2bd84c8e6535f855a88845d0ca6fb85bdaf12c2aae97befe0cd7a4583660bc55e37c666093d4b84e54e1dad07"
    $a7="e899f7dd47030fb9d0fd800dfde63b23d51ab9e2bd84c8e6535f855a88845d0ca6fb85bdaf12c2aae97befe0cd7a4583660bc55e37c666093d4b84e54e1dad07"
    $a8="b8c778edba5a254f1a4ca2640d33ffb002db146b6f6898972f61afd134b272496c6bbfbb7781192897ee56aedb5f03fb196c384a2bc35fb7c5513adc26fcbc43"
    $a9="9c5dc81d240786e8a743cddc26e3b9e84fa7ad817e2171ec64a9515c789c97220637a2a418428c7c2d19dc47366541c272a04346433d92ec4e72e6c5a0e60ddb"
    $a10="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a11="2cfaed14f9fb8fb035262d7b34401f9bea9e865ab47bdef94d1fff4ffaa3abf715ad29fa1cb54730d8326e850169b1977a03711e4481b8e4a0597762d5157a8e"
    $a12="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a13="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a14="56d4572ef63cfacd97c46028466ef485da6432a81831915c8222f3a55260f06827678d4bfdda1fd3747ba6f782ba9ce9a746de7c223be0a98757fa3e24fea62f"
    $a15="56d4572ef63cfacd97c46028466ef485da6432a81831915c8222f3a55260f06827678d4bfdda1fd3747ba6f782ba9ce9a746de7c223be0a98757fa3e24fea62f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a6="bbb4fe984d23a35edea1c68c6cbb56c7ec8bd2e34a82a04951ac8e4b62bb5609"
    $a7="bbb4fe984d23a35edea1c68c6cbb56c7ec8bd2e34a82a04951ac8e4b62bb5609"
    $a8="61192aff78cb38a71858a3a9adf0deda1aa3bc771dde2ebad68bf1183b95daef"
    $a9="ecf90201f780a7e31410e79720125d4f0e7732f021614a51abc2dc9d68e277ab"
    $a10="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a11="98c7eb8f78c0b8786e16cb50f57ad7230d9316dfed040a70c4dff0d97b426fc6"
    $a12="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a13="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a14="80688a4089ed8ece69d6710dfadd097f1decae2248cb4b6ab9b73b1206b0c820"
    $a15="80688a4089ed8ece69d6710dfadd097f1decae2248cb4b6ab9b73b1206b0c820"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a6="65ec07d421a61b431fa1f4dfe8447644927823ffc9e5ed15743fcae1"
    $a7="65ec07d421a61b431fa1f4dfe8447644927823ffc9e5ed15743fcae1"
    $a8="fae58965751ca3b5f7490c7ff429ff3c92b5f1ebb06edcbe8a102ba3"
    $a9="add94bc310841f2297286a9b76d4a652f6a230f8899126f588afef59"
    $a10="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a11="a9ebf1937a742d3c21b0794419cd477017ce3728b1702a7728f17bae"
    $a12="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a13="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a14="50e7f91e037877cd8a809c4f7a2812f9ace7bda5f895896c4e2eea1c"
    $a15="50e7f91e037877cd8a809c4f7a2812f9ace7bda5f895896c4e2eea1c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a6="756a2f17b28ae108e6239416736a5471735481b366ca9eda3caf9ae382a5e682"
    $a7="756a2f17b28ae108e6239416736a5471735481b366ca9eda3caf9ae382a5e682"
    $a8="753018e757e13828f825cd2ad313ab06a567ab60babae2725c5c8951a95e65f6"
    $a9="6aea42640fb12d8ba340110ed1ae8616cbb08cf0d5bf4aab3a28a47089f6ff8f"
    $a10="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a11="d7018b6fa16cb915bc0383ffebb50f8e49cd9ea4ff0e99801edbc6c0932beaf4"
    $a12="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a13="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a14="fb2a49185ff85e19b80a5046bca671f1c2f39a41eb2b94de092724f5e90d7a40"
    $a15="fb2a49185ff85e19b80a5046bca671f1c2f39a41eb2b94de092724f5e90d7a40"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a6="7abbd600252d0146f83b25df998af94b5a0e52ebc02f5354dbd46c5093b1d9f2616772dc826a081bdd5138d784e34296"
    $a7="7abbd600252d0146f83b25df998af94b5a0e52ebc02f5354dbd46c5093b1d9f2616772dc826a081bdd5138d784e34296"
    $a8="d4f7d21ee9a9f6c05bf277caf770f449f6cdd90cd78ed6f7438d6cfdfb3168d209b31d055350d2de7fbd29b9fd5d2d11"
    $a9="6ad53a5d9f18d6ceefb6ba49ce5ec13c48b90a41acfc3385dcb1a953be2f5e464ae535ca2e822a44e71eb3344981ab63"
    $a10="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a11="d960f28a178c05dbecab4339af88391ef996fbf19ae20c76d9b42c9606db91798edb6f29f8c91fb78a9ff7e079d63c75"
    $a12="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a13="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a14="f00ddbc4a4fae61d2c4216a2231b6941f9ef04715c899c86e5271a1604f97e2455aa11d7994cc4e9b2402413d9997276"
    $a15="f00ddbc4a4fae61d2c4216a2231b6941f9ef04715c899c86e5271a1604f97e2455aa11d7994cc4e9b2402413d9997276"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a6="88fb5aac8c14c70d3ec6c5f8f942f1abd2ac3450288f9ce235c5b3a1caa8059fa9731d9e8e17db2fed38cc23eec24c2fddbb307234e951b9a906a76c0473b783"
    $a7="88fb5aac8c14c70d3ec6c5f8f942f1abd2ac3450288f9ce235c5b3a1caa8059fa9731d9e8e17db2fed38cc23eec24c2fddbb307234e951b9a906a76c0473b783"
    $a8="4bf56c5f5668d38a0a556e447ef89b015908367bde6b2961ea1bdb013bde8158a50842cad00152be5c926aaa8c8cc8e83dbd05c44085e797318a4b5a6a5be55f"
    $a9="0e34e699dd1503414c8ad8f2779d761c2d6839d21b307301a2c7d7f5c025d39dd49878d778d3f0c55b212364941082a10616918779282f28915a3a1731850f34"
    $a10="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a11="a1722b1c88ea54cc3e561a9b1565b6e57163446bdccbdaaf974280648909d3c046d4d489afb4aef1266449c50db19e8e47b6ecf2365f45e04b19606572adc89f"
    $a12="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a13="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a14="fd1e71eeca9068e85b237cf5d2a5068762c77c66e69ddaf3662b9292898a5ee8767cf0ce9d7f7b7c5cda5942c8e1611b04a2f2ea074d97a2c19c342a6527d27f"
    $a15="fd1e71eeca9068e85b237cf5d2a5068762c77c66e69ddaf3662b9292898a5ee8767cf0ce9d7f7b7c5cda5942c8e1611b04a2f2ea074d97a2c19c342a6527d27f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_huawei_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for huawei_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="QWRtaW4="
    $a3="YWRtaW4="
    $a4="YWRtaW4="
    $a5="===="
    $a6="ZGlnaWNlbA=="
    $a7="ZGlnaWNlbA=="
    $a8="dGVsZWNvbWFkbWlu"
    $a9="YWRtaW50ZWxlY29t"
    $a10="dXNlcg=="
    $a11="SHVhd2VpVXNlcg=="
    $a12="dXNlcg=="
    $a13="dXNlcg=="
    $a14="dm9kYWZvbmU="
    $a15="dm9kYWZvbmU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

