/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="172192ec5eb1a7893cabbd2418691eb6"
    $a1="0a27eb684802bfd8963b4520f35c082b"
    $a2="b9a2687707534d60726a28ec47d13939"
    $a3="b9a2687707534d60726a28ec47d13939"
    $a4="6c34629835d389f3cc4b449f2e551f5c"
    $a5="6c34629835d389f3cc4b449f2e551f5c"
    $a6="0cf972b58ef9c84f68d98f1e42df0edc"
    $a7="0cf972b58ef9c84f68d98f1e42df0edc"
    $a8="3d60ed60dc05663587f78e3f7078a3e0"
    $a9="3d60ed60dc05663587f78e3f7078a3e0"
    $a10="3d60ed60dc05663587f78e3f7078a3e0"
    $a11="b3ed03788b9229834f1d7abda17ce672"
    $a12="3d60ed60dc05663587f78e3f7078a3e0"
    $a13="d31297d2c5ef01ac1b5f74ad8d3c8d9a"
    $a14="3d60ed60dc05663587f78e3f7078a3e0"
    $a15="2f1c5e5191255007f2833450c4acdb27"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0cf1243379926bf80f3089d829da78f605276cea"
    $a1="c78e476751ee6bd0056d9d5c6c6b959624784ef4"
    $a2="cb160ae3b0a78521c1ad19d22c7d05e4de0c5aa7"
    $a3="cb160ae3b0a78521c1ad19d22c7d05e4de0c5aa7"
    $a4="8b6f1599b3e981940c285c8f3aa63f5d65bfab33"
    $a5="8b6f1599b3e981940c285c8f3aa63f5d65bfab33"
    $a6="455a333004bd3ffa199e082189d7a741f1eb5a4e"
    $a7="455a333004bd3ffa199e082189d7a741f1eb5a4e"
    $a8="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a9="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a10="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a11="c451389d15a3a5349dcef1f1c03e0485cebe8715"
    $a12="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a13="6bf49d7c234129c2600d4c70b0234f4e036a892c"
    $a14="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a15="fed87e322da2d305584c0e5800525a0529bf241d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed05253147bb1264fd8ba2ec17dc5aad55ebce753a06729fa519e70343d102950f79d5866d9023f112f7bf3cbeaa3391"
    $a1="708a30d296765478ea9d0dc885a9dd2a91910a657b9b08056b633b4fd29ef02dc9f1de6f9f857ce34068578e604793fa"
    $a2="a6b8aca84fd5ea2e59792a72a1e3cc252378cf3f355461e4ad79644490bd5dcdee1d6513099ff20f91b9d6d2e4faa556"
    $a3="a6b8aca84fd5ea2e59792a72a1e3cc252378cf3f355461e4ad79644490bd5dcdee1d6513099ff20f91b9d6d2e4faa556"
    $a4="eca996aae3580145a6c6b631d11e3e776d3ee19219dd6ba5a9719c447795aa9a6b9424fbe24baa66fa866039279de904"
    $a5="eca996aae3580145a6c6b631d11e3e776d3ee19219dd6ba5a9719c447795aa9a6b9424fbe24baa66fa866039279de904"
    $a6="ec0a06a45c12a6e9d4a649587e8fccbd77ebbd8d040ed2b949af716e713c50a500645dab58de3cef98e7e099c8f92bfc"
    $a7="ec0a06a45c12a6e9d4a649587e8fccbd77ebbd8d040ed2b949af716e713c50a500645dab58de3cef98e7e099c8f92bfc"
    $a8="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a9="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a10="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a11="c2df787d00aae590a18b7140c03cf67206d224ef555415356f7d78451e88a4c37de08b868ac3da9ae948f99dae62ffa7"
    $a12="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a13="8720d41ea20604e93d759b6a47ad5238284daefca8da7ed3f849cd7dcbb2fb599ed421787be148e26a357e794f2c020a"
    $a14="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a15="4cb1bf67418f5c820e9be529c84ab800c926cb284de13a6d0e574c01a5951c932f6eb782d6d16eb419504ce60ecc329a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a4b8c32bfc385a9694f8b7a83470e5afb0decf1054fd63714137af8"
    $a1="b16fb3b924e301032472a00a31b2f40c96b19018bac9dc2713a870e8"
    $a2="212f6c99f11e5c23139eff0202c1efe2f7711b49316c506df3bfd8d3"
    $a3="212f6c99f11e5c23139eff0202c1efe2f7711b49316c506df3bfd8d3"
    $a4="788018a63e19a251fab419cf26aef5332dbadbce9ae9c09e7cf4d3cb"
    $a5="788018a63e19a251fab419cf26aef5332dbadbce9ae9c09e7cf4d3cb"
    $a6="7b0cff901324c4aebf445b36f35f093c46c597dd81b85079a18ea53e"
    $a7="7b0cff901324c4aebf445b36f35f093c46c597dd81b85079a18ea53e"
    $a8="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a9="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a10="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a11="5b04bd2d190d52f06df012761def78b2c0cb9f99270cd078db2663ef"
    $a12="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a13="18792bac7bfcd5a3d4d5d6a3a66f9538b2fc18ac0d588ec8567f311f"
    $a14="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a15="9e21dc3c98e10cb9d8c3a94295e8fc946c1d96e7d1db93ad65e46d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3ed2c2caa9572427933f826bc605713641934c63b7854da993e1f16735410f84b408d4383c5b2a15a25f433393e7762628ecd3000a17be6ee8ed66b6f3dc3fd"
    $a1="b66386d20fce16f959d01b3ea27b3ebbe8f652c92206ef73e5cea224ba32f9a4d8765f06e1767741efd44033e4c466faa1905bf8dd8d5c49c00b52eebe4deec3"
    $a2="b9f317d08875374ee7699288e43995db2d9246e251b60271aa7d04728ea04e93b3792ddd413386f637b392b6a19256495f30ac00d21b42cd251b10bc4e5397d8"
    $a3="b9f317d08875374ee7699288e43995db2d9246e251b60271aa7d04728ea04e93b3792ddd413386f637b392b6a19256495f30ac00d21b42cd251b10bc4e5397d8"
    $a4="95b8bc47a31cf99c7916fd3065419d29a3fe396fbf3241cba2ab7aa6342ccd5c7d14833a9cf35af316575205ffb795aecb0268823ac3c5f43bda3f6ffa6f76fc"
    $a5="95b8bc47a31cf99c7916fd3065419d29a3fe396fbf3241cba2ab7aa6342ccd5c7d14833a9cf35af316575205ffb795aecb0268823ac3c5f43bda3f6ffa6f76fc"
    $a6="7e2660e1f5fc6f21e3e1286423debee329cfd6e8ec74094582834901ea0576cf417e996397ed7dda5f39abfe3c146e945ef3e9020070366926afb5537e8c2610"
    $a7="7e2660e1f5fc6f21e3e1286423debee329cfd6e8ec74094582834901ea0576cf417e996397ed7dda5f39abfe3c146e945ef3e9020070366926afb5537e8c2610"
    $a8="92c7d5b45f063a5d082e42682e1e23e682eb8daf9f27911b522d4015c90cc671523ed773c39431a343f4f0aec0be0facb8186c5fc327da9b98ad3ee630f78d98"
    $a9="92c7d5b45f063a5d082e42682e1e23e682eb8daf9f27911b522d4015c90cc671523ed773c39431a343f4f0aec0be0facb8186c5fc327da9b98ad3ee630f78d98"
    $a10="92c7d5b45f063a5d082e42682e1e23e682eb8daf9f27911b522d4015c90cc671523ed773c39431a343f4f0aec0be0facb8186c5fc327da9b98ad3ee630f78d98"
    $a11="73f602a6f55f72ce7ff422575d98c0fa2cd32d02c0c288132059817fb5273fcda7e2ad1db107cb4cd50359cdf95315817f8c5af0be7385317f26c7d4f61b5f47"
    $a12="92c7d5b45f063a5d082e42682e1e23e682eb8daf9f27911b522d4015c90cc671523ed773c39431a343f4f0aec0be0facb8186c5fc327da9b98ad3ee630f78d98"
    $a13="3fc294a15c4a7cdb1b33bb5d17dec47661947bdb206ecbf15844045376b9eea3c9a1d44c7d7b7c1700ca5f75a320455799141e6cacc9245139b5b441ed5bf5c1"
    $a14="92c7d5b45f063a5d082e42682e1e23e682eb8daf9f27911b522d4015c90cc671523ed773c39431a343f4f0aec0be0facb8186c5fc327da9b98ad3ee630f78d98"
    $a15="16ab918dc26f829f39c9958d646ab44a3e7b1b9ab070b71b62fbc6f4eceaa3047b1b821781eec5a2649041ebfd789fb50f63d12952ce4c4fdcaf6de5f2da2977"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a854f223272439fb3283b59b6b8b2fe2af9bb8928195f8e95c6df1f1d3fb108e"
    $a1="a612393342c59ffbfa75d39d4d835b8a9c4c7304f905c8e7c4f0daa3370b9a39"
    $a2="36de721b186948b4b4cb57646821ab92bf1f3761e6a20c60aa9e4f95c745b411"
    $a3="36de721b186948b4b4cb57646821ab92bf1f3761e6a20c60aa9e4f95c745b411"
    $a4="a6d59b0e8887006a67705e4f3dca1d17255189d72246bcc02029cae88b8a1390"
    $a5="a6d59b0e8887006a67705e4f3dca1d17255189d72246bcc02029cae88b8a1390"
    $a6="e77acd8538f6e047e5554aa775c5b5faed636ee6756c4fa341003d7d4b79aa2e"
    $a7="e77acd8538f6e047e5554aa775c5b5faed636ee6756c4fa341003d7d4b79aa2e"
    $a8="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a9="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a10="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a11="48ad05c64445e697d835d27d4e1bd117a87f014ba24d972d5cb1e9f6b1cfcfa8"
    $a12="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a13="dd44197298d027962fec302ec92f19666172d40fd73be7070cdc6b9a1f875c0d"
    $a14="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a15="95312f267f428a3a5e31cc6608919a91e72fc046b54b84f81fc0c5276b3490ed"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f2f844ed670448ec99e84c8379f85af5e57207ed91cfbd325a98587bf6438992799d152238322f41fea1e957f381e1cfca338c659d6f60f421a0d17872008029"
    $a1="4a39919492dcef371cffae3e7e603767e3ec4b489eaad74e4f520f8d143d7d6d8abf222a05abfa8908ece125f9bee7d0a4778cfe28599262ab845a1f1c718896"
    $a2="00fd53c7717b93b995f990d342c7b5610f6d2aa2c46fa39b12898437253762b31fa7ef6f7bd09dce56ac655a4b0193a3923de291d4562bf35005e965c6e6b59f"
    $a3="00fd53c7717b93b995f990d342c7b5610f6d2aa2c46fa39b12898437253762b31fa7ef6f7bd09dce56ac655a4b0193a3923de291d4562bf35005e965c6e6b59f"
    $a4="e1d466e9154e97899a4583edcc72a8aefc498bb83aea541ec78564bd5c5314934d0518d49cfe7a7bc8e4b2a9ef0a61cd272eaf91215859ceed94960ff9aa68d4"
    $a5="e1d466e9154e97899a4583edcc72a8aefc498bb83aea541ec78564bd5c5314934d0518d49cfe7a7bc8e4b2a9ef0a61cd272eaf91215859ceed94960ff9aa68d4"
    $a6="ceb272e8225298bde56de0e90da769cbb30a0539e73efce8ac8c89647a7e77341d699207eed3546f1c67804909aa39848f4a4077ea018637d0e791a993d439ef"
    $a7="ceb272e8225298bde56de0e90da769cbb30a0539e73efce8ac8c89647a7e77341d699207eed3546f1c67804909aa39848f4a4077ea018637d0e791a993d439ef"
    $a8="8049c5783cf3f8623dc174251cf686e1d688f8d607d8ebca2c7aefa3a7ce14852550243fe07fbddc78ea26e52d6e8c15ae9c65c01903055e4cc3998dc9b90786"
    $a9="8049c5783cf3f8623dc174251cf686e1d688f8d607d8ebca2c7aefa3a7ce14852550243fe07fbddc78ea26e52d6e8c15ae9c65c01903055e4cc3998dc9b90786"
    $a10="8049c5783cf3f8623dc174251cf686e1d688f8d607d8ebca2c7aefa3a7ce14852550243fe07fbddc78ea26e52d6e8c15ae9c65c01903055e4cc3998dc9b90786"
    $a11="b3c557398160e09c0fd3c0a49a24233365185830542e06c25d4f4ba992b43a4bfac79f3d199b8d7ccde77c7956cbaa0676ef54d7a6219133b47e983ca641532d"
    $a12="8049c5783cf3f8623dc174251cf686e1d688f8d607d8ebca2c7aefa3a7ce14852550243fe07fbddc78ea26e52d6e8c15ae9c65c01903055e4cc3998dc9b90786"
    $a13="3d2fe928d5c09b0c8049c90925d1ed4fd62d074cd0d009d88407b72a3a21102addcbef12dd20901273b71cc8f26e5bf06079d39594b17dbec0518193c126af04"
    $a14="8049c5783cf3f8623dc174251cf686e1d688f8d607d8ebca2c7aefa3a7ce14852550243fe07fbddc78ea26e52d6e8c15ae9c65c01903055e4cc3998dc9b90786"
    $a15="56f1116bd984eb451b35c6764a98ff6c77531ad2c7d7c8cef1bc2387afe7867615ed1de9bb9d5a1894fec4db83f67dedc3501c889378c18498ae061fe816a986"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21fed00d06017af953781c6216a7c31bc1941935f6d0f4f12d3fd4966e9af5b7"
    $a1="8d59a7cc6209c3f94370d665a9dda648e474e83a83ba9a35d3b1bc55aaf69747"
    $a2="65ef37a93e93616117afbc660a7933679c93c33bc8e7f8c09390723f1488546f"
    $a3="65ef37a93e93616117afbc660a7933679c93c33bc8e7f8c09390723f1488546f"
    $a4="028f7971807c550a57574a3f68c3389b3d2e8ef5dc3cd6ac5a41f3f5ad26779c"
    $a5="028f7971807c550a57574a3f68c3389b3d2e8ef5dc3cd6ac5a41f3f5ad26779c"
    $a6="edcd35326f7667f4ba1e0962b0e09c12d6d23398100664589fbb573d7defbf28"
    $a7="edcd35326f7667f4ba1e0962b0e09c12d6d23398100664589fbb573d7defbf28"
    $a8="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a9="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a10="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a11="52e5c4fe9968a568e3c91e6dfbd5a9587a5acc4a2d66d4dd574f0dead1ec7e81"
    $a12="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a13="32f1261f54b28d886cae4a15359166354b62168b5d0ced4b1207773c8d99c3b1"
    $a14="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a15="837be7670986f6f8f4c4bae281b23e9538665da5a90be1f1a9bce75fd8c12a5a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e763cf4d4305979a2cedd11a7a1d8e7568bfd1f29496987ae00bdc79"
    $a1="08212cf33081e27a009858c2af540145b6a4539ce4b2336fd8e8dc25"
    $a2="61099482c43bf31c34699e9d57645cb1e50a32ec77e3faa16f0b0b86"
    $a3="61099482c43bf31c34699e9d57645cb1e50a32ec77e3faa16f0b0b86"
    $a4="b508e30c8f3417c52c2f36e45dab5a21c6d9914c67ae2a1281000fa2"
    $a5="b508e30c8f3417c52c2f36e45dab5a21c6d9914c67ae2a1281000fa2"
    $a6="97ee1ec1e0083803a23989529638c71f99a9ed518a092ad391a74dec"
    $a7="97ee1ec1e0083803a23989529638c71f99a9ed518a092ad391a74dec"
    $a8="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a9="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a10="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a11="f08fe17613bd7fd9968bf0d2de0717b017bad0a3c9c2b92c3feb573b"
    $a12="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a13="c6d03611c648198aead4cd584b11b6b1f8c8535fc467c7976a198a1c"
    $a14="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a15="e4d404dee09a360cbf2513803e38892b546e80286cee71bfc4016c0e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1f1df6fe9ce32d33df425136ae7bcd1240ae631fd0dd77cb3c834ee91b7895af"
    $a1="589e39f67c3fb3ad3292b34e1928ff402264934ef93f9845f17179276148a1eb"
    $a2="e2f80d07553f0988663d789843f37132cd19f4ef2555b00cfd2378457ab35014"
    $a3="e2f80d07553f0988663d789843f37132cd19f4ef2555b00cfd2378457ab35014"
    $a4="a378307f71cb1d8b9c1a3a8c1f49cc7d33ab33d27cfd4ad10f07acd8ee720464"
    $a5="a378307f71cb1d8b9c1a3a8c1f49cc7d33ab33d27cfd4ad10f07acd8ee720464"
    $a6="3e1f6036a07308c385e0c7f0137ef9f8b686609f4a0898c3d0039608f059edc6"
    $a7="3e1f6036a07308c385e0c7f0137ef9f8b686609f4a0898c3d0039608f059edc6"
    $a8="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a9="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a10="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a11="f7e9a4050f2a4abddc406b4acaf0403eb7d11f002298c90859adc2e58e7c4ae2"
    $a12="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a13="0cf8252befc33ca56dce45342f5978d47b8eef41180ead2ae4e977edf411b208"
    $a14="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a15="0d809e4c5b7618f9c64971243fd7632724545c9acda1b89f24d519ea8ddeaa58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f7d31ca9dd025b43c49b6c2c347bf9224d2149e59d34cbcb305a6961223345fcf422da45d4a066f034b0f144c64d237"
    $a1="3e9eb23a06d38bd2cdf54509a7a62270886c22f3aed98d4173ce790dbb760cf39449a57725192b88e7dc0918a431c8f0"
    $a2="860a04daa7d631ec9457f8a6774796410a52b66fa59e518f7d65723bd2efa93bfafaf09b85262b0053569815080e7eb0"
    $a3="860a04daa7d631ec9457f8a6774796410a52b66fa59e518f7d65723bd2efa93bfafaf09b85262b0053569815080e7eb0"
    $a4="f132684a4eaa1f3eb9b14be791c892cde5090361ac8b15168c7057ca8a44fab8a9f910e9f971cf1942fae573f396f6cb"
    $a5="f132684a4eaa1f3eb9b14be791c892cde5090361ac8b15168c7057ca8a44fab8a9f910e9f971cf1942fae573f396f6cb"
    $a6="046267a387db0d417a3770efc35e6a2f256ad654e68c8758069825389347a009561ba37d8df56b1bb3c03dd7e10387ba"
    $a7="046267a387db0d417a3770efc35e6a2f256ad654e68c8758069825389347a009561ba37d8df56b1bb3c03dd7e10387ba"
    $a8="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a9="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a10="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a11="84ae223476e3cfa04664ba722ced9673201ad952c54dca643e2232e53a84dd0de10e1f39ea224992c7ed899158d06782"
    $a12="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a13="f3798844891b25382185c34712f3b59771cfbb2dac1b84c874dba99ad36426b9410064af83fdc1694b332cbbeead3f79"
    $a14="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a15="a182187162d7333ad05857b12b760c9683fc10bbc2fe1ad9ea982e1473ba668b1c6e0d55e21db8b7ca53c0d9c6556bab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01cd0a94250882dcf22c358fc872c1f54787d3eccbaae6bef60d9ad7b36acfd694c14627580d821a200de77b3fba4842a718aa9f5240500eea430110576e9c73"
    $a1="81b9a4c4774e36ea76916431f85dd466081d6d6049e84047076923ae8e42e3688516f8bca0ba8931e0e8a9a720cd41849e033158c34d272863d9e76cd0b1fdc2"
    $a2="b38db545289ab9be36b09017edb7fd9a3a3e84036d4dd1b94107d6b90c01b3d43292e853cc7335c709199beae6e23675db7453978d9bf4f3b7fa4fcaae63d769"
    $a3="b38db545289ab9be36b09017edb7fd9a3a3e84036d4dd1b94107d6b90c01b3d43292e853cc7335c709199beae6e23675db7453978d9bf4f3b7fa4fcaae63d769"
    $a4="21982bde5c64a4dd34ed55ee11b99c2e540404656a5b51ce227b6c01cea7cde88a0b2211e325f6e032485593050884eb35224607b19d0afdd0d153b860bd6179"
    $a5="21982bde5c64a4dd34ed55ee11b99c2e540404656a5b51ce227b6c01cea7cde88a0b2211e325f6e032485593050884eb35224607b19d0afdd0d153b860bd6179"
    $a6="bc58eb28bfb4c91544ff73f3d78a304f16afb1c5b6b76e45c6779523e2bdc707f6c94d0ebed502d8b426ea3fa69e222e6e206208d4dc177b928697fbdb0fd33c"
    $a7="bc58eb28bfb4c91544ff73f3d78a304f16afb1c5b6b76e45c6779523e2bdc707f6c94d0ebed502d8b426ea3fa69e222e6e206208d4dc177b928697fbdb0fd33c"
    $a8="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a9="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a10="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a11="958aa303d7343f0b4dd0930f3bc34e462049638c80c9f708ae5ba00df74c626505249e671e6b1b2f7f7590a074d96a5589df9b99f0fc71ca615f8ff3fdae9cc5"
    $a12="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a13="127722a6c3fe98b9239edfefbd312abef0e110b453651ae77ffd6145cd5504e7b1ccaa5779e1d950b7494447f81358f63720fd8b2194d1261f3ead6163ba666f"
    $a14="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a15="32cc80d634ebca8d2017ce94e5954d1f8e468e4f3ce2201d0cd246dca0562742edd084744031eec78334be805b95a388da5ef346cd0ebd2ae5dd55c7f05baac0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_db2_db2
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for db2_db2. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QURPTklT"
    $a1="QlBNUw=="
    $a2="ZGFzdXNyMQ=="
    $a3="ZGFzdXNyMQ=="
    $a4="ZGIyYWRtaW4="
    $a5="ZGIyYWRtaW4="
    $a6="ZGIyZmVuYzE="
    $a7="ZGIyZmVuYzE="
    $a8="ZGIyaW5zdDE="
    $a9="ZGIyaW5zdDE="
    $a10="ZGIyaW5zdDE="
    $a11="ZGIycGFzcw=="
    $a12="ZGIyaW5zdDE="
    $a13="ZGIycGFzc3dvcmQ="
    $a14="ZGIyaW5zdDE="
    $a15="ZGIycHc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

