/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a0f848942ce863cf53c0fa6cc684007d"
    $a1="a0f848942ce863cf53c0fa6cc684007d"
    $a2="96f9963e25520a9011c82401920794f0"
    $a3="a32c3d3cec20f5a09595b857e45b477f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="80437a44a661d141174209119d54125a59a64b2a"
    $a1="80437a44a661d141174209119d54125a59a64b2a"
    $a2="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
    $a3="c6fcd99559b7b8626f622074178541e4cd4f6cd0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a1="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a2="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
    $a3="cf8cb7bd641fa46a496514440e4b0698b56e94aef126b960dbf81290fad7117511abfb9d2fa882225cbd94463f549e33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a1="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a2="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
    $a3="c8237ed786e1430e7a31c50bf3b9206634d35ddfc039c36c58ea0790"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a1="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a2="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
    $a3="773080f9e04346d4f0e9d746fd2b04beb1bb9491894eafd580f9e932bbaa59de4311d953a608290045ce3c0ed9185f09502f4dbb999ca045113460a2aa78495b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a1="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a2="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
    $a3="c797f6834c354fedaee9e19bd52583f73ee2255bea1d6cc412168eff78675c99"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a1="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a2="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
    $a3="8ba3a9ba1f70a08a652a6c98bea64a11dced25819903e5f21eed7db692fa1e382a3f4e9d0c24e18baacb42c7cef6c35349a61804451bb2f208623d39e8a26986"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a1="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a2="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
    $a3="20c86bb90d595717f02c30e7e36eabf994dc72a5e99aa728bccd75e52495f52d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a1="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a2="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
    $a3="e1f96d03c34f6a579e09118b4f75614614bc2b255f02ac94cb91cc04"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a1="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a2="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
    $a3="ab3096e75a21696828f78fae2ea6de1427c28a63a6d1a25f15855bb257ce91e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a1="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a2="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
    $a3="6eeb9a005a6a196390f7ab8bd7477922b7fd89c5b3768bdd27bf4da035206840900139baedabe0d888207bcdae10584c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a1="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a2="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
    $a3="d8daf7b12c0ad18465b4804f8889649405fbe2ca3caa3b54a2dd1ea0ea5b41b56fd8df455308ff67212267a4ac45c109a2b0076680c39f347939228bdc640950"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_telebit
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telebit. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2V0dXA="
    $a1="c2V0dXA="
    $a2="c25tcA=="
    $a3="bm9wYXNzd2Q="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

