/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6489ee7c554faef44dc324e110f3595"
    $a1="854f36c709b662f53c00ea2c11a40f7a"
    $a2="c1174207802b9ac58eacb57e67febb68"
    $a3="6a29cf18161f652ab0e0b2943249c52e"
    $a4="07b4672c5f1de542c2c3833aa5c6ccc0"
    $a5="7f903d844b517574584c8669a963227f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="780ce71b10160b23f5a7ce4e2a094d9c06e33398"
    $a1="b1a13bf0f73d84955c28e8c1d35ae18701dd91d8"
    $a2="55679234f1f665aa88ff02ed238833b096b99693"
    $a3="388b7f1f938cfa07c12296f832b1e6cca6dabd81"
    $a4="09dcab79f53da5793de73bae09ccb325c98eded5"
    $a5="56aaf2aa9eb2faffeb54679f530580b1c4aafe5c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21715b408927d6eef8de7f59241dbfd27c7c01e06f8153fe20aa2afd94623f641815cde23d887ad75b49ac5d4fd37729"
    $a1="6e53a80692550f761f1dac51feb336dfbe973f089b2d5b3e34ca8284997c5de7cbc55d18b0334a9dbf5c80677138017a"
    $a2="0fb5fdccdbfcdf43f33cfba26b36d6e691aa82ed6acad3583caf0297f3b4fcc15dab2663be2bbda5d68e11be6dab35f4"
    $a3="67ac2ffcdd4ac70876a66b95ab887ff962b31f542b7ef0d35287109db31543906e13bdf8ddbcb37bfd61abb699410ad3"
    $a4="dea79ac15ec73e8eb1d0ced8c782bc37c63272287484286c993a2bc202ae8819c3284d2cad3324492a6c56b932d858ed"
    $a5="2912076b336ebdd783b83a95f3e114f736c8fbf6ebd8c091def825064c8dcce9d21f997858c49cb658891d7452b81c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="08c8e4bd5c31533ef86dd65712b2270cdb6bdd4b355ff2e256be618a"
    $a1="7e0bb6ef7aaf18827ae1795e0e0c4a1ad04f757e52f7be4d1a64a309"
    $a2="2bb6da4701038c5586ad48ea2ce0310c9c0db13003fe7f3feed8e179"
    $a3="974919085ef3eb519735f922ebe848a39cb232e16753d7beea28a7f4"
    $a4="d56de952c2b48bb50abadcc10cbacddce31a977b93450ff57dbde5ea"
    $a5="2116ce8cc0edb956788533a040f4674e505eb2b36213a8eaaf6d48c2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ceb9ddeea9f9f20696e71439cddb317be20d7cbd0eb850275d4d1977024f5cca10e7598e316818fd8b52fa92fb3a54287796fa4282c348435c5db3fbb99b96ce"
    $a1="91da79ddf69596bb4144bcb5e9746a811005886be51702ccf51dbfee6855c37ea39672512a0bcb4ec140cd547cf989ec313d230c4537c87de4e62c5878c49e57"
    $a2="70c92f038d4ae10f9609dc7c65dae1c248b8a742d555b1a7a8ecec7e600e41be2b1a0e4a513f77ec45c54098dff28898661dfb68a7521fae1b9b1d133ff6c3d0"
    $a3="661e5fb8a6902bd9b1ea1ca6e274b716b1f8dca03a13a0860d40cf77aadb4cfc72155cbb1ff858e918a25815398f7045034a0fa4db6ae9f034930fe0d54e5899"
    $a4="cbf4ee2754f3b81702e85a4dda6a8d53253f7ac68943e96f0e80014cc7e5d2692947d4846aa1902694664a843b96ac6db30d0b84dca141fa29c3869e1ddcf643"
    $a5="8cf561bdff3acfebe7fa18eeb180d2e02cabcbdef59755c906a2d27123290917a4ea152426de267ef6580b3677819c8b6451b4f89f064d423f3e1bd0cadf4d7c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="800fd460d26ee2a1ca23c523b4d17bac8480761ce4224f27419dae1ee52038c6"
    $a1="0d335a3bea76dac4e3926d91c52d5bdd716bac2b16db8caf3fb6b7a58cbd92a7"
    $a2="dc0e3ef8ba6780d1e9d537c3047f633617f6947e9dffa34780e7cbdf6c247191"
    $a3="1f36df49fb1212b7860da023f4c28159e16070cf8f4e4934c76a9ebfa52d3671"
    $a4="7ede771b4a6bef4621de8746fd94d004683c2ef46808bc0b5b2065e2f8256cb5"
    $a5="c89296cdecdbca0b46e74e4d7d25b93ad19b95a88b1cc59f13b0e01975693424"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="003d79c3d6f9e9308a460b87174a2e815fe38c1cba5c9e1d1b4a3b71e1cd0eb5a189920969348c7e47cec65b5ca9a735ccf732490a87a71c3dea8c427bde64d3"
    $a1="aa224afe871f55b53ecab25ccfefc9c72b3ded0df405356b1678b3479547b9bcb37cbc7e4dfff91851122e9173ff6d3438a0a7e6913222e6d9508dcd54d758f5"
    $a2="d314ec522eb96a936055fc0faafc1f07a475c23e49d9a88d84190a1bea64a2d5a8aca75afc8c9b60b93bab3e704b6a23f2dac5f872573be2b63b3a26ec554572"
    $a3="9740babae0ee30787fec84991aa058a71139a47d4ce7632727e55e883dcd9297feec6a3b2cfdc563b5b1f0fb230e5f06b82778f62f4ca8de7f764f292c86cb9f"
    $a4="c8b575db946e92fcaa02dd7f42c529925d6ec0a380c800650a95d50d11bfce208521b13d2328cb28b96eef7d3a81cd7fa2101132522be1d5d7165aec0e61ac79"
    $a5="6184f589e4c67678ea3fdf1b45882167563734f570a92bcc3c4edc652eebf9653dbe81adb304d6399ee299b20998ea9960849327b3ede29bb5397c47ed164321"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ea17c5b31d81a40988a2618b43de1263b0f85da04c2d014904a72d87b79d36d"
    $a1="6eb349cccf1eafa37c8e0bca0ecbf49e9abceabef8b1eaf6945d9cd78f56fb6b"
    $a2="2d762d0c7c4a11eb6c51c497e09859defd97cf996f2b2c101b0a4fa2f0872af6"
    $a3="fe88ca356b4f5fba753dba289497f052edf54a46538658f306abfeebd79e532f"
    $a4="91ebf18f3b02ff336c408ee9f91305ed6ff3689d7a2d543fcbcfafc275a348f4"
    $a5="3ce2bf8665d90d3fe7716c31c11e2f04811d124271525816a1d4e9a7f9351728"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f4ba7815dbdea2769dec2551ca6e74f51b0b7c7d5e332d9adf88e2a6"
    $a1="9f68e7e2a4528837288778443d4cf829e4cbdd06e71fb04a444147ce"
    $a2="232636ded5559f4595b1aeeab35d8ae4d2de95408187843f4aa03338"
    $a3="95bbdd0cacbfb9dc56f5e05fcd3f1b4071cda06f40c667fc590c051c"
    $a4="cd741b70ce7dd9539ee135a2e3cd02a2bee076879b4ce62eb234f10a"
    $a5="e7a26a48d6b986cdb9bed18646d22642a655dfdf21d793c574199b02"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe8783e1c9c081a507b7d28f520d292ef62ac464f40660dd5823ea30ef14eec3"
    $a1="2ae77b32c212533eb7805f83d4f45fcdfb4f8da4eea248a088b39b1637172b81"
    $a2="c1aad3f30824c27683b44fc984e22b51a5a0b28b07ee1993dbf763c66fc656de"
    $a3="929cdb8bd0dd2ab6488acfc24fe92c336e3d9bb0df0299f25898cee9fea3b9b4"
    $a4="4684eed63157311e7581eb9c6cda94f88d1bf05007dee882af34d3781538b9e1"
    $a5="ce8dbacfdbbc77c351b6c1080f01a4f6313d8788afb345ed590f93051851685c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6c54710022a8933dd9011a65ceccde2c7c63e0423522593e656de682ae8a7a4c505f1740d00c8f168870d03fd12d0108"
    $a1="53501ed3076ef6f153e84a7af330bba544732c69b99a54743440286eaee9ff920fb16bb5b4d4b5c7dbd67d4b59ed700b"
    $a2="73094024fc0a8316b8e48af182bd808689baa8bf8b144ee444a065899c5acf3591211c2aa58aefbc1950c27d8152049a"
    $a3="7d6e486b6697ca11c2b07df0039a8be7fc6b411826cab0ea9133b2a312c5fa77ccc3cabd211dbbd2238f327e13d18314"
    $a4="1489ff227027eb2f8262d3e5e87f276e940cbe3849885ee59e6ab5b78a517617ef491e1f532671ec6ae18a4b7e3c17cb"
    $a5="d8584408ad7697ab33140915acec59af1d806a8cbaefc7ac406d113b0b30a8af2b30324205902f7e03d999ef8480dcd9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ff4059328d8431e2f675e8c874012902b6ff76b384f5eaff7c35657ac44ac9702d731372b2b1ce73f34e1247ac0822286d9aa88d0e875a72a58add8bb2f95234"
    $a1="4c1c9931b6af5e284fba09e79a8d408c089c9d68804403d0b0b2faab821516ed9e51419d752be8c745b9aee7b6978d5ae94560d71313597bb517096c696965f2"
    $a2="2b088ac0287ffe5b9183bc216d6bec09a16cde55d3e0897e20ef97af128f38f6995f5f6d19e63dafe14bbceb419314a6a1eaf5a07e3d0b7fb236450b342e41c4"
    $a3="e5b55333d7dd948adfc2f5d8b9d05f2fd41db77f35d8075be2afd0de7f54063e1d9fe8145062ff168ebb647f691a947a54c6c343735316c6a11fa1d8c8728d03"
    $a4="c9e4c132dbd8b4d69d151981b1e9add363a41618e42675744751ccd070b846d812aab3621ee5cace876dd74058b8b2362ed80f0ca5bbee66c1a5c9ff3ce10acd"
    $a5="4e83f57ac8047e43800fb4278d5c90f9252a79211c4ca8f13b445d98c831f885d00756cfcec4e09d26004f1aa910aa933fb0ec4e2426c7911326c420cf8cd080"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_server_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for server_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QURNTg=="
    $a1="YWRtbg=="
    $a2="R0VOMQ=="
    $a3="Z2VuMQ=="
    $a4="R0VOMg=="
    $a5="Z2VuMg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

