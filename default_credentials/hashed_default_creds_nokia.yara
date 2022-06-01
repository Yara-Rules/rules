/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="fa246d0262c3925617b0c72bb20eeb1d"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="dbb4cea57d0d718cd70ec16fbdae01cc"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="0c23a8bf29a191f18aee814737e2a6ec"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="ea9bb3aa950723face73423802625074"
    $a8="62608e08adc29a8d6dbc9754e659f125"
    $a9="62608e08adc29a8d6dbc9754e659f125"
    $a10="dd268bd826d9947ca1feb5e9851a963d"
    $a11="dd268bd826d9947ca1feb5e9851a963d"
    $a12="a571d969c8661fb0342afd08e571dfa0"
    $a13="827ccb0eea8a706c4c34a16891f84e7b"
    $a14="a571d969c8661fb0342afd08e571dfa0"
    $a15="268e27056a3e52cf3755d193cbeb0594"
    $a16="63a9f0ea7bb98050796b649e85481845"
    $a17="0c23a8bf29a191f18aee814737e2a6ec"
    $a18="63a9f0ea7bb98050796b649e85481845"
    $a19="96ca9d2f94b871e6933b51800e24e917"
    $a20="1316379096c85e48ae3c8426e1536ed4"
    $a21="827ccb0eea8a706c4c34a16891f84e7b"
    $a22="29e7396b6b7e8b8ab20daabcde1c7732"
    $a23="29e7396b6b7e8b8ab20daabcde1c7732"
    $a24="ea9bb3aa950723face73423802625074"
    $a25="ea9bb3aa950723face73423802625074"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha1_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="4170ac2a2782a1516fe9e13d7322ae482c1bd594"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="e474d8b62a7545d09349e2d474fb4aeed562efa3"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="d61db83635e5f720433ef78a30f3cb269df0c0da"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="f9ba98a0694ade0740017ef26f79efb102609c7c"
    $a8="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a9="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a10="db70a20f403dad43acbcdc0290862079d7300f7e"
    $a11="db70a20f403dad43acbcdc0290862079d7300f7e"
    $a12="e3272363f7e59ddee3c6be2811f61d4e8fb3f002"
    $a13="8cb2237d0679ca88db6464eac60da96345513964"
    $a14="e3272363f7e59ddee3c6be2811f61d4e8fb3f002"
    $a15="01eb84f052ba857d610a26815628d5339386c8e9"
    $a16="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a17="d61db83635e5f720433ef78a30f3cb269df0c0da"
    $a18="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a19="c1f46c805200d800a0c0185b33334b263d34c7ed"
    $a20="fd3cfc02834858b6847a18bcd6e8e8c145fad487"
    $a21="8cb2237d0679ca88db6464eac60da96345513964"
    $a22="bbf0e00dce424049433f5aec1d93013db3698303"
    $a23="bbf0e00dce424049433f5aec1d93013db3698303"
    $a24="f9ba98a0694ade0740017ef26f79efb102609c7c"
    $a25="f9ba98a0694ade0740017ef26f79efb102609c7c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha384_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="1c07aa1d69da31feaa90536162bf9a9999a4ab1ba058220d10c7a9bafc415e3d461f78b92d4e16b0f8804fffd92bdb25"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="854eb3b7e21f9000a7e8aadc171e33ea26a255222a83c7a4effa6fc5759220b3f1470675f5d05f6761003c6754a1619a"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="82cd45637b6e37ef02482a4d769c1bc1caabc0201a9236f739c285053549ca80d0ef2d554abf072558330627d36b44b4"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
    $a8="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a9="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a10="fde45e7a0492240962f1c83ac2e27af3023758079177620e47d83669c955aa4a1b535b7128f810b46eb7fc2cead3e6c6"
    $a11="fde45e7a0492240962f1c83ac2e27af3023758079177620e47d83669c955aa4a1b535b7128f810b46eb7fc2cead3e6c6"
    $a12="ff05f65a7ba581f9cc95d243128fa47f3fa3c34c8d4efe6761c62a8a4f083e90081722a2fab656b335887a24535b1550"
    $a13="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a14="ff05f65a7ba581f9cc95d243128fa47f3fa3c34c8d4efe6761c62a8a4f083e90081722a2fab656b335887a24535b1550"
    $a15="2bc130303bb7c1ed0c32351d922e0759add2cb648f7e25ea0b1fb3aa48403117f7f5e1d8faa5c7fd1aae93b56038b647"
    $a16="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a17="82cd45637b6e37ef02482a4d769c1bc1caabc0201a9236f739c285053549ca80d0ef2d554abf072558330627d36b44b4"
    $a18="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a19="e1df526616174e93218657e00cf11841173920b8bb984ab531b2a0c5ec111e342e1bce34a95a905b80c93916f9fc0da2"
    $a20="873574cfb5ba53f2cad1e4673f59b6764d52bf83a2b3a4f81a7aabbc5c3a2671640731ae078d1aad2c3838b055b23ab5"
    $a21="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a22="defd7b8c342efc74c397228ba9c2090c7565453d472cad2434cd4ac29e16d28655015c65f1e224e378e5887f71a8ddbb"
    $a23="defd7b8c342efc74c397228ba9c2090c7565453d472cad2434cd4ac29e16d28655015c65f1e224e378e5887f71a8ddbb"
    $a24="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
    $a25="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha224_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="5a22b396fb44bcd3c3b7e71f738ab1f956e73eee1e565c5b124da76b"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="82060e6cc5254f818fbccf71459e7dbef3453d71c9aa1acb6d3fff24"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="557f89c384f7385be18c3d14c893f72029f8abab7ccd0663f4b49474"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
    $a8="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a9="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a10="704878b930e6c0a1bf9c2534c9271d6d09c85956f5532aa21b23ac30"
    $a11="704878b930e6c0a1bf9c2534c9271d6d09c85956f5532aa21b23ac30"
    $a12="a976fa8a05671043deadbfc0d50a15e9adf48d47361991e7b0452a0b"
    $a13="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a14="a976fa8a05671043deadbfc0d50a15e9adf48d47361991e7b0452a0b"
    $a15="bc4c7b249289acdc09f7cd84537311182f71a4c4b8a391a870d55929"
    $a16="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a17="557f89c384f7385be18c3d14c893f72029f8abab7ccd0663f4b49474"
    $a18="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a19="0af5f61619a226b4a59dbab983fb0027d12dbe9fb438e89835539982"
    $a20="9b32cc942b73c884c90a739a20aa5c379c6fa6a7832ea521d5ffeaa7"
    $a21="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a22="c573581f23014a220ce810c6eed001ce74cf7b82c76f37a7a6bbb855"
    $a23="c573581f23014a220ce810c6eed001ce74cf7b82c76f37a7a6bbb855"
    $a24="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
    $a25="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha512_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="b61265c6a561e90476ef78be3d2cea768306afa55a2e510c591008f8dc3e6f8a9520687e5fd3805e2da67cf5c58aa1603f960e027b0d5307fd7f98b673dd172f"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="db0d9ec1504444cd8da1d9140c3a0e586a1eeda716daa10710ba8bb7900fe6b9cef4db6ba05c74bee29a7e201ca0d8df9ea9a2eff9e873db26d48c47c83baefd"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="3f83728a555227c63232e874177bfe70616e8879472b016bebcdd776f6c2ecfd5621db4717faea02c1e5875ba90c2b2160b93efea4918df05ac1992631359bee"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="8ef2e7406d35e5d72f34a9fe3e33fdd37cf3c49747f3b6bf9fb179c1234b5bc73a1095e47f718115bdb044469670a64066c5b65fc043f408098d1d3492d39d54"
    $a8="85d7741af27f18cbefc7fdc96d4465f63d4e8da2126a196f87c4f7e1f65298855a0e4a4a8986936eae95e2b899e837c48ae39d8048f907ebd0095c87c49fb0af"
    $a9="85d7741af27f18cbefc7fdc96d4465f63d4e8da2126a196f87c4f7e1f65298855a0e4a4a8986936eae95e2b899e837c48ae39d8048f907ebd0095c87c49fb0af"
    $a10="fd7760f88605a4e3ec091c627d8210c8eb78756585aaf10125b55f8f5ed0b8707a32388777919145d0094859c62617f34285c8f6ceb858b32521ab49c77e42ce"
    $a11="fd7760f88605a4e3ec091c627d8210c8eb78756585aaf10125b55f8f5ed0b8707a32388777919145d0094859c62617f34285c8f6ceb858b32521ab49c77e42ce"
    $a12="acced7d843aa1133b618794a27ade5254e53a6b682cad5edb249494d5f0d76b9262b179dc125af2cf5ddd6bd570cd5513146139d61f46ee7fa3efa1b06a82a92"
    $a13="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a14="acced7d843aa1133b618794a27ade5254e53a6b682cad5edb249494d5f0d76b9262b179dc125af2cf5ddd6bd570cd5513146139d61f46ee7fa3efa1b06a82a92"
    $a15="2637e59347980f0bae0e2817fe650c05be6faf161f957a32feec1d6b2d460a678d0a12c603e459abb43a36ddbe47b38f34841959c426c3d835e18b1b2d2939fb"
    $a16="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a17="3f83728a555227c63232e874177bfe70616e8879472b016bebcdd776f6c2ecfd5621db4717faea02c1e5875ba90c2b2160b93efea4918df05ac1992631359bee"
    $a18="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a19="4b96c64ca2ddac7d50fd33bc75028c9462dfbea446f51e192b39011d984bc8809218e3907d48ffc2ddd2cce2a90a877a0e446f028926a828a5d47d72510eebc0"
    $a20="7f412151c47f07236c426eaa9a5e9510f006b421f7330527f4a42845b7a3f4927c742e812cbfec9f6e62a5dca586a0aeacb553190f53ff7ceb39245eb001dbb2"
    $a21="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a22="b7ab73d40be6cec19c6d4e3fdd5a61be97fda1d9322578462bf0cd7c921877f9178f3c8df0d0491763ff2b78baf3ca7ce2b48b29e895632332ab54b4ae71223d"
    $a23="b7ab73d40be6cec19c6d4e3fdd5a61be97fda1d9322578462bf0cd7c921877f9178f3c8df0d0491763ff2b78baf3ca7ce2b48b29e895632332ab54b4ae71223d"
    $a24="8ef2e7406d35e5d72f34a9fe3e33fdd37cf3c49747f3b6bf9fb179c1234b5bc73a1095e47f718115bdb044469670a64066c5b65fc043f408098d1d3492d39d54"
    $a25="8ef2e7406d35e5d72f34a9fe3e33fdd37cf3c49747f3b6bf9fb179c1234b5bc73a1095e47f718115bdb044469670a64066c5b65fc043f408098d1d3492d39d54"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha256_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="888df25ae35772424a560c7152a1de794440e0ea5cfee62828333a456a506e05"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="6f909b4daf6cc87925d48a1c20feb8925198cb356dee38bc40790d0e3a9d6576"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="2ab6d53e717a0e0d773ccfdb8b0e84ac494729c6b567c72d256b883a9db17ea8"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
    $a8="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a9="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a10="29a0ae2eec6a90eb8100d0bcbf063c7081e60277dfba2a9db821074776bc44bb"
    $a11="29a0ae2eec6a90eb8100d0bcbf063c7081e60277dfba2a9db821074776bc44bb"
    $a12="2b8fbda969a8aaa908e763c57e6b22a1697b7c0c5f95fc35b95d492fcc54d082"
    $a13="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a14="2b8fbda969a8aaa908e763c57e6b22a1697b7c0c5f95fc35b95d492fcc54d082"
    $a15="12d27e106af46b4b9ca8772d97f1855329a420d873ca738b7b11c68d285ca71d"
    $a16="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a17="2ab6d53e717a0e0d773ccfdb8b0e84ac494729c6b567c72d256b883a9db17ea8"
    $a18="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a19="746ff992cd97391b15891f93dd1ce02908c33947c60f1a95fc134d40874e5ac0"
    $a20="73170a99e6da9a0d8b381209436bacd8cfef30ade921a2ca1276880611000138"
    $a21="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a22="c06f6073897e5e857e12be420e89d62163e5b0e73317d0a6c34dd34dec57c1d7"
    $a23="c06f6073897e5e857e12be420e89d62163e5b0e73317d0a6c34dd34dec57c1d7"
    $a24="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
    $a25="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2b_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="75ef577043d0a81f70eb2ccabfdc555b8f2c13ca8870a79c7922e08345d56836a9009f66b8548f92e8f51896241aa857368478c50075710e314b47f7f143eda9"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="b91f4c5b79254e6d8ba9f1a2118dc932b90882df9c6d2c1c881cb6e1aaf5b8a3116df95f3ca843eced03df6c8b51de44e517473ba2f06b7fe18c165aea26f525"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="5a49aa49a7751ae9c0f3044663a776313a2c47130a948ea3fc038549dac4482559f6ec51fccd57987c765b2f79dbb88216df4103772432fba8d150e449e88d6f"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="7b817910a46064762097c3a6119ca5584bd0822e1d3821c2daab55135b2732ea2f9976fbc75aee3923b5ebf18338cf206386559ec611c39ee6c8072c28543e24"
    $a8="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
    $a9="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
    $a10="5781eab2a830933f68c9925214cd498e51ec9ab5f292f831aacb9bcc1e75e22a8d709f812529b075baa7bd1559bc4cb38785e6367b092f169c596209fee88dcb"
    $a11="5781eab2a830933f68c9925214cd498e51ec9ab5f292f831aacb9bcc1e75e22a8d709f812529b075baa7bd1559bc4cb38785e6367b092f169c596209fee88dcb"
    $a12="d3e9afd16eda3c4629fd94e48e5bab9dc9da5dbd3b07cf9ea5663ad9d154c91c5390f6997a3ce46cd7fd56c612d9de0831263a017576baf7069d3cee30633cd1"
    $a13="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a14="d3e9afd16eda3c4629fd94e48e5bab9dc9da5dbd3b07cf9ea5663ad9d154c91c5390f6997a3ce46cd7fd56c612d9de0831263a017576baf7069d3cee30633cd1"
    $a15="342d752a9dc0dfffe297aeafeac198365be1d50f3b21cbca820743e86f2dac2adf0c28e44106ab95575610ddd16ab149d681e63c1df2bd926635ccecfa259e4d"
    $a16="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a17="5a49aa49a7751ae9c0f3044663a776313a2c47130a948ea3fc038549dac4482559f6ec51fccd57987c765b2f79dbb88216df4103772432fba8d150e449e88d6f"
    $a18="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a19="046fe9d2fac4b0c0376da117d98abbc0f5cfe3acc91ff6085908b3f13d10bd4e6c0151d4fb0ab312c322380f5dc3258bbbb6ab27fe8c51f659d33a32ffd146a1"
    $a20="0df3481e3baf81644af9a215dbc64af11b61a08bc42ab45fc72d93147ac02eaf32c076defe258658710a2a7742d58ebdbca1feb04ae5ebd8b938604d18544132"
    $a21="8b28f613fa1ccdb1d303704839a0bb196424f425badfa4e4f43808f6812b6bcc0ae43374383bb6e46294d08155a64acbad92084387c73f696f00368ea106ebb4"
    $a22="52e9f4483b441699b16276094af78f1cea6670bc9e359ca4fb984d69a0dd767a5acc9290515ea597639f629f76b25e198a3d121c1c7e82b553fb429e893e3973"
    $a23="52e9f4483b441699b16276094af78f1cea6670bc9e359ca4fb984d69a0dd767a5acc9290515ea597639f629f76b25e198a3d121c1c7e82b553fb429e893e3973"
    $a24="7b817910a46064762097c3a6119ca5584bd0822e1d3821c2daab55135b2732ea2f9976fbc75aee3923b5ebf18338cf206386559ec611c39ee6c8072c28543e24"
    $a25="7b817910a46064762097c3a6119ca5584bd0822e1d3821c2daab55135b2732ea2f9976fbc75aee3923b5ebf18338cf206386559ec611c39ee6c8072c28543e24"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2s_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="9a6b2fa676a478646c95adde41d12532132afb7cb7d78745d141d06f88e09e93"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="fd597451aa62a0e4c76f7801007f7169d4a354de56106748f59e0385e20422ae"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="309d4021807c32d3135c512b63aa35eaa712ecd016557c758650e38444b54f1b"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
    $a8="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a9="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a10="80c86cf3a5c01a69b8a7ff71e0494169e29091fbdcc74deb27b0424b063da631"
    $a11="80c86cf3a5c01a69b8a7ff71e0494169e29091fbdcc74deb27b0424b063da631"
    $a12="47677dd17a17a8bc5b12a38ebc591c4dbb68499e929807a83244e372f639a32a"
    $a13="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a14="47677dd17a17a8bc5b12a38ebc591c4dbb68499e929807a83244e372f639a32a"
    $a15="27ca50c9efe17c2d0871a3a5b07058eee51e0fec449450a463badc34be9cfb72"
    $a16="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a17="309d4021807c32d3135c512b63aa35eaa712ecd016557c758650e38444b54f1b"
    $a18="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a19="c7867568fc4b7b2650b83f24a57e6d028f3c40e2b232f5ccbe8e1e99544a3833"
    $a20="94a80f8591a0d6bdfa8cc2126602a3852d92708079bad3ca3a814619898e7067"
    $a21="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a22="fec1c25022e096836f4a607ce3f6c200abea8775cbb8bf8a7ca78dbd867c0e0c"
    $a23="fec1c25022e096836f4a607ce3f6c200abea8775cbb8bf8a7ca78dbd867c0e0c"
    $a24="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
    $a25="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_224_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="2db4d30c77274fc3843bd69401f4f32b7e2ffbf8142597fe9c046ff8"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="1409b85499f5c370c638e50aae569c0eb092275dc23233046573e0d9"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="55511238d0d82eba3d5e323fe3d0f4c6dbae811f3ba28e136ce6063a"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
    $a8="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a9="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a10="e08ddc7460d3a0339638ff6a250888b2fdd5279ff8a13c1a8f84bc6a"
    $a11="e08ddc7460d3a0339638ff6a250888b2fdd5279ff8a13c1a8f84bc6a"
    $a12="37788067fed012db40ecbaff604c112684f0685d131bae1649b7ae76"
    $a13="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a14="37788067fed012db40ecbaff604c112684f0685d131bae1649b7ae76"
    $a15="dacf4055fd6f8f8b4af04ba59f7da52b72ae3ac620f8c6bf985e847c"
    $a16="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a17="55511238d0d82eba3d5e323fe3d0f4c6dbae811f3ba28e136ce6063a"
    $a18="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a19="30026b68fe664d44c650bc4445adb5806fcfe8129a77b32112cab8d0"
    $a20="ad89019dde61894842a61f2f2272182a68e1b5000ba353aa9e3e9205"
    $a21="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a22="d20652273bc03d450977787afeeb7b83cb394d78eb3fb1c2237f8e06"
    $a23="d20652273bc03d450977787afeeb7b83cb394d78eb3fb1c2237f8e06"
    $a24="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
    $a25="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_256_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="f90b44246c557f78965d64f2f4f90898c92ecb954b94b7484f5ab54e27077193"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="3f1528db03a83e372fecc3922fb84d2e81cfb32b902136483037dc4e9afc2ba7"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="eb03687b75749f50dc368946860642f928e14e00aa80ff438ed0105f3a608bcd"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
    $a8="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a9="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a10="bdaf93e1d2634a74791d37c11904211325d89d7dcf2c6231960f8ae15d1c3401"
    $a11="bdaf93e1d2634a74791d37c11904211325d89d7dcf2c6231960f8ae15d1c3401"
    $a12="f51812338f1d3993ea2fc873e24a049420606a22e8d24f2a9f2aa4687d98f0a3"
    $a13="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a14="f51812338f1d3993ea2fc873e24a049420606a22e8d24f2a9f2aa4687d98f0a3"
    $a15="7f2ca0d7e8d2e1e283fc1bb42b26da97da44ac170909d2fd831eeb1e0c5fa49f"
    $a16="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a17="eb03687b75749f50dc368946860642f928e14e00aa80ff438ed0105f3a608bcd"
    $a18="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a19="50ae02b46526f6ce0bedcd33b475840f27e148b312e8089dc2dfbc10ddca960b"
    $a20="be2f847879f73004a0da3c8dec8efd24d8671a15d4f67d51a9782f8c4394abd7"
    $a21="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a22="86cbdabeba46c2f05e460f7183d20a09cb01c354fcb81d29ab54773e4c7cd490"
    $a23="86cbdabeba46c2f05e460f7183d20a09cb01c354fcb81d29ab54773e4c7cd490"
    $a24="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
    $a25="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_384_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="0dbd8790d814cbca13c3b886040426160c0d67e998ae14fc8b17afce9c99831e8a5ee857f02111f87eb4212e933220e4"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="99ff92b7ab047d970ab77590e6f2ebfb12c41cc517ce0a8a908a4e9c3f0b8f03fb08091b141a81ca340f5166e387ca8e"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="5b6ec279e869c119bb09329a67bc3008bf193b9d08cc125760576e557ab01985cf3dd9d949e4e3b859ad8d68abd48d04"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
    $a8="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a9="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a10="18116244f5df2ae4f2650679c451d9a31aa03b9b4c66db3045e88afa9acb9a2f7782c85b82ff10ee3f76727af52ffb8d"
    $a11="18116244f5df2ae4f2650679c451d9a31aa03b9b4c66db3045e88afa9acb9a2f7782c85b82ff10ee3f76727af52ffb8d"
    $a12="ee45e3ab25285f3457a73f9cd40362598a53ff5e11aa929ea92eddca1df8f96f129dab5e0dc10bf91a8f1584caf046f3"
    $a13="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a14="ee45e3ab25285f3457a73f9cd40362598a53ff5e11aa929ea92eddca1df8f96f129dab5e0dc10bf91a8f1584caf046f3"
    $a15="88bcc6999eb878c6f2f8c6b4e4d53c16cef8b404a2e2a535184f613516821f6582f2b2047becefda5dbf1d578607b824"
    $a16="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a17="5b6ec279e869c119bb09329a67bc3008bf193b9d08cc125760576e557ab01985cf3dd9d949e4e3b859ad8d68abd48d04"
    $a18="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a19="859f4acd5845ee70358ee2c50f345047e4c52cdbf7940dc7e5585d7008af14ee6a4a5d88aa12dff4c50eecf6c5c42e1b"
    $a20="a7a88afadf5e6559987e2a7e031337a99ef1085074cbdf43ad046e40156897de70d34663a97c3427756090b3782cb92c"
    $a21="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a22="16ecf09833cfef4d951cef07cb9f6808c2486aed0fdf70fa1422db442ef8abfe0f36a5677afb555f695291e3804eaed5"
    $a23="16ecf09833cfef4d951cef07cb9f6808c2486aed0fdf70fa1422db442ef8abfe0f36a5677afb555f695291e3804eaed5"
    $a24="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
    $a25="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_512_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="a8f9c7d6499ab2c51ae0339acb9913e8eb711036d89614ebee3511c84ff297add9fc098ca1834e89576759547e17f2d7484807616e5e0f4e92320383606c1a4e"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="449518fdbd9215bf8d071a33af1992e70c7cea4369e676165a8f8e35116a541809864de3836298e4a49de3776d62cef10acfc3a00399e10a5029c02a8109ce97"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="f376c5f7052c441759b1667c4d80c125c7f5e377f6f0fbb9cc055cef1e0d237c8bc596fdb3d1ef696259b8c91fdb58406659e9eeb08cba614ddf77700891a741"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
    $a8="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a9="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a10="cc7b8225e921d98472b1fdc77a00ca8b2ae02cb6578a3b9e9e6bace00252311c1e3264df33426b3aa36dafc03d973bc5fdb38f1ce5de9283393d8c51a4183804"
    $a11="cc7b8225e921d98472b1fdc77a00ca8b2ae02cb6578a3b9e9e6bace00252311c1e3264df33426b3aa36dafc03d973bc5fdb38f1ce5de9283393d8c51a4183804"
    $a12="e53ad98cf3081f292dfaff1c5c9a2532dd4cf87c023d45ddfe3bbfecafdd60317f30d88d990cf02101a33dbefe4c29f0634ebd53b962bd91e9d4937f0f006c5e"
    $a13="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a14="e53ad98cf3081f292dfaff1c5c9a2532dd4cf87c023d45ddfe3bbfecafdd60317f30d88d990cf02101a33dbefe4c29f0634ebd53b962bd91e9d4937f0f006c5e"
    $a15="29bdf6e37475a3019d6aaf797d7c015403b0596ebd26a307a6d9d2e02b2843d541853a00a77e7c43dd214682abe2f1c89ffd0a3b5a2622c4746bce84ce1a71b2"
    $a16="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a17="f376c5f7052c441759b1667c4d80c125c7f5e377f6f0fbb9cc055cef1e0d237c8bc596fdb3d1ef696259b8c91fdb58406659e9eeb08cba614ddf77700891a741"
    $a18="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a19="ebb1f467a01dad7841e4db3a8495461a51d64d5b986f218dedaaa3e3c20a82e9f29ae0d3d4c2653d580d6e5062589a523f04912fe0cc3d760bbd029b78e5dad2"
    $a20="efe4903d927ec614d4591348e0266bea1f74e798eba058dd8fa7ca685726c1d6d9575e450d5650a8610313f06c2835abdf73555abb3807789c5df8d913fe1107"
    $a21="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a22="099fd622c3a5797b980360ab230600ad42ec392d25d68b715827211eca3e2971c9f445e8161ec80dd3c0e4a55d1bb82a5d0da8164b1f8816cbec43cdab8d4e59"
    $a23="099fd622c3a5797b980360ab230600ad42ec392d25d68b715827211eca3e2971c9f445e8161ec80dd3c0e4a55d1bb82a5d0da8164b1f8816cbec43cdab8d4e59"
    $a24="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
    $a25="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule base64_hashed_default_creds_nokia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nokia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="OTk5OQ=="
    $a2="===="
    $a3="bm9rYWk="
    $a4="===="
    $a5="bm9raWE="
    $a6="===="
    $a7="VGVsZWNvbQ=="
    $a8="Y2xpZW50"
    $a9="Y2xpZW50"
    $a10="bTExMjI="
    $a11="bTExMjI="
    $a12="bm9w"
    $a13="MTIzNDU="
    $a14="bm9w"
    $a15="MTIzNDU0"
    $a16="cm9vdA=="
    $a17="bm9raWE="
    $a18="cm9vdA=="
    $a19="cm9vdG1l"
    $a20="U2VjdXJpdHkgQ29kZQ=="
    $a21="MTIzNDU="
    $a22="dGVsZWNvbQ=="
    $a23="dGVsZWNvbQ=="
    $a24="VGVsZWNvbQ=="
    $a25="VGVsZWNvbQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

