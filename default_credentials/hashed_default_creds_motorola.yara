/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="750379b5926e9f728aa6c253d37e3792"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="5f4dcc3b5aa765d61d8327deb882cf99"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="4a7d1ed414474e4033ac29ccb8653d9b"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="8fb04719a494ab06d32d66deab3c0a56"
    $a9="f3395cd54cf857ddf8f2056768ff49ae"
    $a10="aaabf0d39951f3e6c3e8a7911df524c2"
    $a11="3ddaeb82fbba964fb3461d4e4f1342eb"
    $a12="a0f848942ce863cf53c0fa6cc684007d"
    $a13="d41d8cd98f00b204e9800998ecf8427e"
    $a14="eb919176ebac2099dd026ec41524b707"
    $a15="99cc2f5f84d520057c50a0eb4da15beb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="51e822c50cc62cdbdb850a439ea75b6d45ac487b"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="39dfa55283318d31afe5a3ff4a0e3253e2045e43"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="ad594f17d657ef21d59f2012f4388d8b65352d5e"
    $a9="77eb1db6cb81b3cb088d36ab7aae8f230dcfaa28"
    $a10="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a11="26f580ae0efc69079ed9a6beea0e30288ad90119"
    $a12="80437a44a661d141174209119d54125a59a64b2a"
    $a13="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a14="55d25800fb82ba29a267c932300aaa8a19767b75"
    $a15="72944a17c06eedbdd83d6bfd8d9999e8a2236637"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="f90af180966a30a4bb42c9a2e5390e12279336d0355d26c5746219a2d5d2cc60793fecdd3ee224cc0041678d2238159f"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="b034e6d9b4da9ec8962957bdce03b507b67dd5d40f821ab7f732d3591283253342d136c55c8eece0e1a50e1f724c2dde"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="0b0920075996b936192ff5550f153b2c845184834abf13fb67ba8dc07ff728d7c1a809919d044de3974d14a18c1d6e67"
    $a9="2a055b36f9947efb7fbe1817e20e14d5f4c4815a0d51b089f1fafa2e7cc8909b840b8e455dd740ce6313fa56419ad86f"
    $a10="66e17cee68b63148b492c1e60cc3b9c85161eac639df6ccc878f251b056eb1a1994c6e81f1f6971a3ada23434c9c5ef2"
    $a11="683efc8fb8cdedb8e52255891bdfb91afad01b7d31b746a0ecdb8760d9e334365338ab5943f35e22c424ec3c65fa4404"
    $a12="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a13="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a14="f507f1638f8d1ed7fd34b4f6ebac79309f2ed1bfa785ae3d6558a701c8af466af6ef1a9ae260bb0196039ce2c7d6b514"
    $a15="0d2542695647320ec0bedbd6a467fa94320835293536b8d12903950e6d0df65c6861f98eedb45f48fcc71496fb2f9a80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="e7c6add1676a3f5508b4f9833c5a6deb83848b18d0f82b425365ab1c"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="adc91e03060b42e7836bdfba7ce19b3bc1297d234fec44585472529d"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="b6ebf0805e8f23a423ccdb6824195fff219f53040e41870933a03b57"
    $a9="7902f17d6164ee01ca4f8ca79c3e39618b64e93160311f2e8e9d402c"
    $a10="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a11="fb22dbd3dcf0b2ad8e74079e7db330b08b16a9cdca3a446bcc402a7c"
    $a12="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a13="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a14="60a3e7db49689e427d323d69d8a9ef86af02a3b4668bbd9d17e22e50"
    $a15="98e6eae7336c91abb2949ddfb5f1c0499cd36d9c3c7b83997703ec53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="2aa271963bb68c9bf0b44736814a288bfccc0a5d1802e1ee2c2b653158faef9e6d66e9f805c8fca303d4d82d97e2b5d613f792410b2ed50c044a0768398b991f"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="c6001d5b2ac3df314204a8f9d7a00e1503c9aba0fd4538645de4bf4cc7e2555cfe9ff9d0236bf327ed3e907849a98df4d330c4bea551017d465b4c1d9b80bcb0"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="baaa60c571adfc75b00432283b6fc4293dbd366f4b1f031e85f32251b4298b25fc49c74791014b158193b3c2f5de52077d5fe94e5a0820165b2330e63cd9ce15"
    $a9="8391976da1e82092fa39893979d25f9714e39ef9367ecd90b15eefb8b7b80540e7efc91ad74abe135d0e7eaaeebdec1e126e840471b2ba692e04447ee85366da"
    $a10="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
    $a11="8309dd7c52675caaf669868c10bb5616d28daec1e47001277118e7832a22fa7e624a497edcae4a8eb0c74b9f2f64882ce7978492b99cc4975fccece756c4712c"
    $a12="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a13="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a14="1008aee4cee1463834b3eaf369b8e6788f456bf39d1cebf505697ec8701b685e95b37d2e05d8ee2742bef77debc7af52111b339f926871ff33bd3ec2c314d9bc"
    $a15="be460ecd19614bd7d5a1e127a0d9e717128c5472b4555017f8f053a9c1856d5c1816d69b3e061e25d7045e7c00b2473b75418cfdd4e919253d3c7a37721f6984"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="0c44be9f7948957db073a1f24c266b07508b127ec030b328269ad052d7213aa7"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="9af15b336e6a9619928537df30b2e6a2376569fcf9d7e773eccede65606529a0"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="5fd27b27dd78566133180b3e86d5ac88439099188593a375302bcef9f846eb3b"
    $a9="74c95604043427f0bee1d0e16bfa53afd537f736ad0073c4cc4e1ccb3a82b5dc"
    $a10="9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280"
    $a11="fa1eadc4c6995667412681c69ce33adfc9302a2965f521c40908549e670e2e4e"
    $a12="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a13="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a14="29ba9d9cef5a66461116a24938bb9307e005c35aa1bb909f16aa5e85bd767480"
    $a15="24319cb915275f937eefa4e8fad430ac0a971177756850b7f0e49426b69c744b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="f1e49137c65993da285d960add379c5b1f63d9fbcee77026e3e191a5da7db10d5eedca3b4a5df348aa95bb75b5b914d3b0c3fdb10a3a9b99de8f118269c66ae0"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="3b8565b7d15b7cf1cb681d5bfb0fff2326212746772d6676d9daed2eb9422c0b1fdd6446c4c18127e2a791d431994935a69d6ff468916167af1db23d95eea8cd"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="8da5525d49c047c516f2d19e05247aae07dc54e5d94ce1af5f4c099846113fca3f34950635d4d08aa057126009bcdd67a3a21a79186d4c7c5f50ea6738018aba"
    $a9="04134ddd131165ad52bcbe11800875556c75245a7dde83d127a2e83bba0fc9cd5097b1c04c743a75b224c28d9326471da47991869f2e05686e9c1da69eab192c"
    $a10="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
    $a11="b75c8c42a1c9216da01ffe3d1f1854706c5dc40a306a6bb76916e8bb93983d469542180373ca305ad5bbf8abc70bce61776f147eb2e041fd8e5367103d674e08"
    $a12="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a13="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a14="5860893bfed0ceb5b3f4f874bc3e6256eabd1b3091f0cec26132ff8591b290a2647dcf236c153ac3895291cf2074dfa5ca1a5e0ea159cede8d84857cba17b5b5"
    $a15="7465b053b832bcb98d162be89dbc054eb945b3e2ca42f99b2c20189b9e3dffaaf872a4b077d46026a4451305221fa6c94dc934d7a544f9295ce7bcc23aec31a8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="e922f7b90d222ccd09d1114614152e9b533f300da2c3c9eb6124af77dff2a528"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="1b23aa0241350289fc70cf9372437d9a021b875b8baa558b15b0b7687952ec73"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="4305c8368fb76b838cb16a4334a34499323bef73919dc970d8f13ccdfb42ef9e"
    $a9="f45b3f0eb0c77db94cd9e089c91e4af34cebbf60034df9a3bf0642239af32f8b"
    $a10="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a11="cef0603e0ff8eb1842c0822f0fc3974b996589f8c15d8b82e95561054c29d159"
    $a12="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a13="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a14="27621d65151802229728aad129e062d4b30a3bd77a960bb67d412dfb9d818522"
    $a15="06b07472610e2f84d641236081940a65d124e8f814c54fe4536b834d70d411f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="0f0a9fef8fcc761fcfee0e6757bfbe09741361f7b7df68ca20eea036"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="70afec1674af6485ab6713729de000542e1b43d45ba368f55c271c41"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="3d485d081fd9f8aeab0a900813700d2ffffad79267748f753b6438c1"
    $a9="283b91b42fe837604b6c486310061312bc2887abdc821416b858521c"
    $a10="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a11="fd9dc48ed52245c81385c2a50f69254ef2318efd51650adb441113cc"
    $a12="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a13="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a14="3ee9a89c78349023a55c7e7b2f67e2c8de518495961090c74b91356f"
    $a15="fda7b94b1afd7d51ea37c37632bb79b0f19499cd05cb47d58b7bab2c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="34f06ccb589e19284e83e1669bae6358d6a4c6b23698dc3114b94adfd53faac9"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="a6af70b7af3f42352d783e8b07515e433c3d45669d4efee670516727193b291b"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="edac5c28b92c7d127bd2b5557d6ee6a2491cc147103ee5fb16bd39100ff30c58"
    $a9="ae48964325684403f4239ebf3de09bea8dce035f40ffc0c03959300538f476bd"
    $a10="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a11="ed9e36fa06a282d0572283f9332e1008e159ec1d234e55fc4316c7fa0f3f30d2"
    $a12="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a13="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a14="92a2396ac62ab41d712a66589901cb680160f38cfe0359b0f0d35f6b5d35251a"
    $a15="a7797efa8ce0417f3f0242d74182c431c6a6b5c739348afb3b01d8c11cce36b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9e67fc27dc82a040f4d69afb4f21404ddc2939a6596f898eb849afdff339bf4021424076a0c9abedde240ec9c9f743c1"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="adff06f440f7f2ec74a4141631d1cf89a142a28a58b252516e09027846a40f35608029e5b46af8cb15d1cd552262eaad"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="d1ef2e826150dddff72c5b643142f61c25b0e529961693fdea0c2f3f7e9fe3d422bf5713d43d632acbc44dc7c7724495"
    $a9="09115bb74c0f96f7e0afc093d1343c10e8f97a5ade755b5e3add1dd2ea4c5c11f6c0d8040aedc090e86ff68eee98da1f"
    $a10="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
    $a11="f3e35699f5b5c65615b9b77e56cf9a027927da2779f7e249a2971408801ee28c739c2de9b95a8bfc94647e1033239a71"
    $a12="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a13="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a14="9f2d4fa5d014018b928656b25ba1bb19c8c30c99608f41f03ce47d63ae09cd9a87efaf5fb4b93fa21db220ef57c412c2"
    $a15="31b5e246ef3f10c8f47695ae15579dfbafded3cd41cdc02a2610c519e9adfa34352a60db6e6caaab5cb6430c52e2e478"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="afa4f4598504512a701d121a0102edbaef2723e764399535d30b7f1976d204de734a67d495cb36c4707c042b4b7b90ab8dd0c8ee2120f42a21df06777fa9992a"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="b678ce98622f627b5b35ca1e8f656f1bd33545d242b59f015a31de938afa3afbe685385b8e3cc9ff37d8c2af86eebfd319eed65abdb4be4181cd42ee4f370f61"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="b494d71e9282ce0e4abd722aea47bb98179de1bb997655da07a9e3d4e29eaa169dec383ebe573b59c36741f70a517d513dbec037fe13b451c01d88a9eb3023a5"
    $a9="3fd49aaf123262c9488283fe59596fd271b6e9da0978e5d9cee0168c078996d9705fb03528f2a49a2136b81bb9008092265fe7fc2d082279296f83f37bec538f"
    $a10="cbab59d74fea767f62a9cac3851b832e01570b54280cbffa7bfe6f0f57352199adff8fe9530a129101047560f0992cc6990116bf8d38bcfb44f8ebd2bdf517fa"
    $a11="aa0f96477a753c367edb9be48f0f5561d5ba9136c6cdcd9b59415966301d6c88b3df8eb446fafe1979321d7b81677c22bec39485bb2056a0e76de73d5f32286a"
    $a12="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a13="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a14="09aeb34e3c243c9d5365b896bd62588df6bde484db7c7dae0c6f3a828bff09c1a1b853eaf2c422349101a7301efeb2e23a80c8bc91f747f661c7af54697ea125"
    $a15="0c757889a9243541ad16cae83b4d1aaa03b4206691d9999de0846c21839677b5c56bf79ffe3ebff27b2fd914b95167053c1f2fed76468a79af1e1fc78021b579"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_motorola
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for motorola. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="bW90b3JvbGE="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="===="
    $a5="MDAwMA=="
    $a6="===="
    $a7="===="
    $a8="Y2FibGVjb20="
    $a9="cm91dGVy"
    $a10="c2VydmljZQ=="
    $a11="c21pbGU="
    $a12="c2V0dXA="
    $a13="===="
    $a14="dGVjaG5pY2lhbg=="
    $a15="eVpnTzhCdmo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

