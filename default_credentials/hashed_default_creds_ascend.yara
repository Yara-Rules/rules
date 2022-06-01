/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="ed45840f6a6415ca5eb50ae607e9449f"
    $a2="336ebbb2179beaa7340a4f1620f3af40"
    $a3="62f45890cd48195be8e9318aa383456b"
    $a4="2ea7fe2bd051ec076a226b7dab76aaa3"
    $a5="333d3e2dd98f46786c6716cb59995fc1"
    $a6="63a9f0ea7bb98050796b649e85481845"
    $a7="ed45840f6a6415ca5eb50ae607e9449f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="b8fad891d4314ddc31d382ce6a48bd3e3ff135b7"
    $a2="9a27718297218c3757c365d357d13f49d0fa3065"
    $a3="b611ae96194d3c2de7ae260de5149b906c1ba762"
    $a4="accf881e821ed62ca842d34164426a7d9215a948"
    $a5="a9dd351bee26150accfccd3701c7b0db26379896"
    $a6="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a7="b8fad891d4314ddc31d382ce6a48bd3e3ff135b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="3fe35e481a78c49434a85ead9d705ed62919749d5e766cd2d6ef060127181ca83cd4087b6e11644b2f09a3957fb78c7c"
    $a2="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
    $a3="d12fdf2e3f04f870d878b475689c612b02e3214bbe9446904dd412a3d2e9801d0b1b1850f7307807d086dd100257092f"
    $a4="07118c8912d6527cd58200ac894bf3abf0aa38c27d0db9fb866e0016f348cf3b59b7a96e14e000217d01d00e0734c76c"
    $a5="f4d6fe6f62934bf34a452ce6184e42a4892a40a70371eb2e883c8573b93349afc606c710db090584dbe31ef4c22b1078"
    $a6="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a7="3fe35e481a78c49434a85ead9d705ed62919749d5e766cd2d6ef060127181ca83cd4087b6e11644b2f09a3957fb78c7c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="9ccb03ee072bc1417365a249f925ddff6bf050841749e0ed0e141fe4"
    $a2="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a3="aab31839eda6ae30c9e04b073a6c840b3da972c72ecd46f020c599f1"
    $a4="7525d4343f66352bf3e51528c809fd8473f7969996aa6b9fe9ab39aa"
    $a5="931cb2c2657631363b8a216b6ae51002af953a5dac26fa43f60abca2"
    $a6="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a7="9ccb03ee072bc1417365a249f925ddff6bf050841749e0ed0e141fe4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="90009d12415ac46a2c7e4492c12bbbb22d7888011ca9aca98ac14837f210e110fc63b991f24f0d51dc4c18245e08cfd2d93380569ca3a00701dda743e9a08a69"
    $a2="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
    $a3="bd41baa75fe7647f1d27c31a72b4e2dfc537db475e089a139f67a82d7f555aa1c902aab6ed849b376ff5fd0f2d37ea9f3421ec2ba2c82312c65806da7d45c648"
    $a4="837b64c137ec2633242b1363ab465707b6a26fecbd5c47e17a0ba457369afaaa9f04dda78a72d64607959a2a002586fdc77f87d943c95c42e7a9eca4ee2f41c6"
    $a5="7bfb8ed4f69d24f6300c57f6bf8ec89f76e6d7158f09eaa4a1dad5128a153ab83e6e7248ca0bbc875494ba510e29fbc339cda3698a0ea414eea7eeb80f2bd283"
    $a6="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a7="90009d12415ac46a2c7e4492c12bbbb22d7888011ca9aca98ac14837f210e110fc63b991f24f0d51dc4c18245e08cfd2d93380569ca3a00701dda743e9a08a69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="2ea802eeb4485cf32398e8fa1c85d0be431cfa53e21c8cae1e413c628eef2c0c"
    $a2="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
    $a3="79214a67320d0255297ff8f4107aea70e3d674cfa601a81eaa0fe72c93716993"
    $a4="dbed7fe3ca011c3d1fb0fec3bdced5031d4ef17dfce2fa867717f7beeff23d8e"
    $a5="2a54483d03dadc8ab9e4f69e68f4340018c3dcb9e63546d55f5e5d88737b81c5"
    $a6="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a7="2ea802eeb4485cf32398e8fa1c85d0be431cfa53e21c8cae1e413c628eef2c0c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="31a330e8c8e72bbafd399ac5f50823c0682a5d830acbbe8df65bda0e7a93178e71604d50a9698af12175a35ba66e74dc5749d7991bdbaa638fc9518d3f3f4b12"
    $a2="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a3="dfa9daa408bc2317afad1086df4f602fff9a34309c2202dc6ebff703d85fedfb9ac0f1a35da6c3589dcc9730145934675694f66aa7a42f3714d78860c908275c"
    $a4="ef2fd09f1a0711ffb157269b5f22c433a85a2f3396d8d9348ad9564ea7a6bd425026558c84725e288b9eea12002305558cd95e61fe7a198d1bb69df986c1b3d3"
    $a5="b540ea01ced69e6e6159f992e3ed9c30b7a65f08f2f031ee6147c2b6395762004f79c137503167324ce307f412f483348f6273c1c33a8b42f4fbbd856d355d67"
    $a6="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a7="31a330e8c8e72bbafd399ac5f50823c0682a5d830acbbe8df65bda0e7a93178e71604d50a9698af12175a35ba66e74dc5749d7991bdbaa638fc9518d3f3f4b12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="d65713daf4bfd4cec7b745476c42fcdb7f34045f314f4842f6e47dcc25d27ab9"
    $a2="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
    $a3="e9906881fc284dae8238878c1a409311519713023291779b53d8636234c9a735"
    $a4="deccbbaa43384c8f3618af30729423bce158c9e716a394cdb960da011c4390d8"
    $a5="c396f26e2507ca2b9d5723d5e649f705767beb0d4326572f45afb469faa21151"
    $a6="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a7="d65713daf4bfd4cec7b745476c42fcdb7f34045f314f4842f6e47dcc25d27ab9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="def073a2b31ce23ee32457ab705a51f1abbce8e25c327dfb36c98873"
    $a2="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a3="78b3f0c8476104cf533ef1a8f77b7f941e9278c0e889a72d9b986454"
    $a4="ef7288e18476c5b2efb6d043e4bd7f5d955df401618360641761f6dd"
    $a5="9e7fb7d8aeae258f2cfa631463fc989f13ba0f90f852bac101f2d0e7"
    $a6="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a7="def073a2b31ce23ee32457ab705a51f1abbce8e25c327dfb36c98873"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="a214f7312073b63bf1c183534e979b18533771ab290e105043b898942702a995"
    $a2="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
    $a3="9f9b41032ecfcb70a6060c45f72cfe28c7a982a75e1dcca4f02d82bdf58bfd3b"
    $a4="ecadc4b42ff468b63d113a1ff868aa2d8c4566bfc8e41c6c0b1197f0cc86cf0f"
    $a5="ca177780df436f74a06ea281c897a680fb5c59033451d73faa0e65ec25da4ad9"
    $a6="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a7="a214f7312073b63bf1c183534e979b18533771ab290e105043b898942702a995"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="a741e81d56af5d8d8989246b020b6511ca94eab702c084079afd8a0493d6231f66c3a7ea7a86c37bb61597d4956bb8aa"
    $a2="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a3="59a8a0053065fe4eaa6942c9eea9ba79846a14e747a11c9039779239e63b346f7bd3439514164f573ed9c4c0ec37b89e"
    $a4="efd9e5ef02a9405c6da4dd3b8451f61834c6c444d2ff6654a29a2c4709e69d98815377874349b9d9189f72527b2216df"
    $a5="a53f652c63106cc8e536222155fb49f98e6071e10f0a523b81ec1359d1d2ab8351fcf141a3442ccad71de87fa1f18efd"
    $a6="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a7="a741e81d56af5d8d8989246b020b6511ca94eab702c084079afd8a0493d6231f66c3a7ea7a86c37bb61597d4956bb8aa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="830da7fdae27f65e0604953d955bdc20f007c6cbbb2a807cae31d88cef2403516d6c5f7a656f47eafc376cf37127fa824e115f7b34db333904354490edea6292"
    $a2="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
    $a3="77e103fa4098a3ee23c73bec9df9561b0396fca97097342fbf7fe7dc1c489b401baa6153933443b204fbc19a5c8154b1e1ff2014242ff9a181f92926d49fe4b4"
    $a4="0932668b8444d7cc4c45425e8a81d3e4b857045672c7dfd99aa0937aaf86f4ceeb80af7e6845120b7ff6ff482d5ba4513f4b65b76c5ee2f2e2f037ac874ad4cc"
    $a5="a74fa0d922a306eb09a5cefed65b4165387ea013cdcc19ed7ca7a5d32a4bf9e594f18d28e3127e715593e3b9cd57bce95be5592ca580455878daa1cdceefbcb5"
    $a6="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a7="830da7fdae27f65e0604953d955bdc20f007c6cbbb2a807cae31d88cef2403516d6c5f7a656f47eafc376cf37127fa824e115f7b34db333904354490edea6292"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_ascend
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ascend. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="YXNjZW5k"
    $a2="cmVhZG9ubHk="
    $a3="bHVjZW50dGVjaDI="
    $a4="cmVhZHdyaXRl"
    $a5="bHVjZW50dGVjaDE="
    $a6="cm9vdA=="
    $a7="YXNjZW5k"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

