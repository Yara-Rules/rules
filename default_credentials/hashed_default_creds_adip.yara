/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b504301092fbfe21c6a27f88768443bd"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="b504301092fbfe21c6a27f88768443bd"
    $a3="3d2e6bded046ca2e3f906f04235b279b"
    $a4="b504301092fbfe21c6a27f88768443bd"
    $a5="b7bd6536bf9b3071c642718c7a514eac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c548ed53c99449bb838aa54fe0dde85db00b22ac"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="c548ed53c99449bb838aa54fe0dde85db00b22ac"
    $a3="00ff262976e32557950c39bd1061176fb1cfa02e"
    $a4="c548ed53c99449bb838aa54fe0dde85db00b22ac"
    $a5="aa7ba874b7e98cfe4cb65e9282fe72e1d31d3669"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7cc85315924bae71cd2b761ce69cdad4bf281f44579af5f0c406c310f9da1f42ea97620ca5d8d2221711f75346525e28"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="7cc85315924bae71cd2b761ce69cdad4bf281f44579af5f0c406c310f9da1f42ea97620ca5d8d2221711f75346525e28"
    $a3="8443b821a4931ade157c2895a9ebc37dfa909fb918785a8f53f929980b3a2f9750df0ed1e437bcfa9632dbc188d55f34"
    $a4="7cc85315924bae71cd2b761ce69cdad4bf281f44579af5f0c406c310f9da1f42ea97620ca5d8d2221711f75346525e28"
    $a5="36200e17d899777de018dc515a1a4103a047ef73cc71d10568e30f2b3a10952db04c47088c99fea25f42fa7aea986133"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7703ba74becbd034d28d798f7eb86d923f844431b1a827dc4835ab49"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="7703ba74becbd034d28d798f7eb86d923f844431b1a827dc4835ab49"
    $a3="93348fbb6bb798810ebe4362688b6f321e6e2ae06031d270ab70a6cc"
    $a4="7703ba74becbd034d28d798f7eb86d923f844431b1a827dc4835ab49"
    $a5="721210c1daf915694b3b50efe7c47b08317eed22d889bd54b6bfb533"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c9e3459f126bb7a7e1e1f2985f06fce35d3bfd991577a66828bc3531d34a259c4016fdf15d2318f8928fe9030192e105c89c5ecbf982dab885ab22e6bc52a8b6"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c9e3459f126bb7a7e1e1f2985f06fce35d3bfd991577a66828bc3531d34a259c4016fdf15d2318f8928fe9030192e105c89c5ecbf982dab885ab22e6bc52a8b6"
    $a3="f5098252f9c3e4cd9b48d5066f9897f9aa8ca30e48a0bad04288525a994d07603a98f73c9f2ed9a88bcce8e106ccf738b7ef09c1346ea012694a1e164348b0bc"
    $a4="c9e3459f126bb7a7e1e1f2985f06fce35d3bfd991577a66828bc3531d34a259c4016fdf15d2318f8928fe9030192e105c89c5ecbf982dab885ab22e6bc52a8b6"
    $a5="8d61523a6c320d907be2631cfc43a87caf218ab667ae1e121d48f73360561af81afa99f316833f36ba01d57aa21a446a9cd8726304f4860e368114dbbcebec60"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="47b7b77863db62c2eb258b8701d6047f634372ef4ac11ac3f4419529694ff723"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="47b7b77863db62c2eb258b8701d6047f634372ef4ac11ac3f4419529694ff723"
    $a3="b713f0bd8f48dfad2263cabc455ade78f7e4e99a548101f31f935686dff67124"
    $a4="47b7b77863db62c2eb258b8701d6047f634372ef4ac11ac3f4419529694ff723"
    $a5="1c1b3acb877a19945abf4a6d7aef1be60ca834cd599e4b75d5dff774ab4bac17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c8f5598d157e1578ec5d081f4743dd12da7dd225019ab9d01f52f3d6e3fc8f8438d8ac52c4d74062a24336f3c0113fb1f93e5b84604936ce0996e613985d840a"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="c8f5598d157e1578ec5d081f4743dd12da7dd225019ab9d01f52f3d6e3fc8f8438d8ac52c4d74062a24336f3c0113fb1f93e5b84604936ce0996e613985d840a"
    $a3="2f6c18f7e5a3be1f7db74b1750bdd5421217e3d6cdc639c6f9f233fe61557f2103280d5cf92ddaa200af773bf44e6185725f7081d8cde88fea51869ccfb6ea01"
    $a4="c8f5598d157e1578ec5d081f4743dd12da7dd225019ab9d01f52f3d6e3fc8f8438d8ac52c4d74062a24336f3c0113fb1f93e5b84604936ce0996e613985d840a"
    $a5="7632c06bda5f566f8e921a3c25714fb6d8c7a53da096609aa8db793ccd3bfbcfb24fea36294fae132d2e7cb2ddb9339742c788078309691e0a1dcb48260dd56c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1b666c34cab923a091b1380efe105dacdeb1b4b986a0ce2391e776be2cb31fd7"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="1b666c34cab923a091b1380efe105dacdeb1b4b986a0ce2391e776be2cb31fd7"
    $a3="02f9978203cf0bf2c890efb8a6fe31c265ae0127e30c5ccd04ebe21ba282c28c"
    $a4="1b666c34cab923a091b1380efe105dacdeb1b4b986a0ce2391e776be2cb31fd7"
    $a5="989c68997dddaf938c7bf176762327869db4a9f0dbaf618342adb4df26d4560a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3e393a76b984e4041c1cf22ac250954d6bc418fd2289e14cbca299b"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="b3e393a76b984e4041c1cf22ac250954d6bc418fd2289e14cbca299b"
    $a3="66c6da46f681e332ed21563416ae6f05b33a487bab4c68447faea72b"
    $a4="b3e393a76b984e4041c1cf22ac250954d6bc418fd2289e14cbca299b"
    $a5="bfd43f4ca512731d8486e73f71815fee4bb5ce68818e81d7f2c322fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="be087ae86f1378817134f81c3dd22cf672e7b6e9253a38bbbd4c2a9c7a4d5453"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="be087ae86f1378817134f81c3dd22cf672e7b6e9253a38bbbd4c2a9c7a4d5453"
    $a3="4abbfceaa9038d037424a47d60e4748b7eb8a68f18a2b89aab84eb8e06a6544c"
    $a4="be087ae86f1378817134f81c3dd22cf672e7b6e9253a38bbbd4c2a9c7a4d5453"
    $a5="825fe9ea4de4aecfd78f01e422e9777cbb66904272b9306cd81d9c260efa2a37"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9f7085f2e6a7030a3f9d9865a5252c8846e3c9636882967b503713fd4b5d7fdea36e42149ddfe22a7900a7d66097bf1"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="d9f7085f2e6a7030a3f9d9865a5252c8846e3c9636882967b503713fd4b5d7fdea36e42149ddfe22a7900a7d66097bf1"
    $a3="bdfd8b4bf5911cbe13974f4f89d928b7b6801a95d58c949649271a4fad404b882afc086d8646bbfae01a4810546564dc"
    $a4="d9f7085f2e6a7030a3f9d9865a5252c8846e3c9636882967b503713fd4b5d7fdea36e42149ddfe22a7900a7d66097bf1"
    $a5="9ffcb76def133c529e40599109e2c7a1192e94cefb8cc34c1d472698603c1e642a88bc74223dd7076cb9a23224464b2e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a37046b1875c3749a963156605aa4e2de7daaa11c8e4d05dbece0e9ac77b00aa7e7872cb9a9d134569d71d706f911650f2692b8ab4790550ef769f93b3810312"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="a37046b1875c3749a963156605aa4e2de7daaa11c8e4d05dbece0e9ac77b00aa7e7872cb9a9d134569d71d706f911650f2692b8ab4790550ef769f93b3810312"
    $a3="49a3bd9a59750d43cd342842da8420e3a35a564a013e9719f046b3c2ccc8800b1ccbb8fbb766f9888acb971bfdcb23ba1016eb10a092f8eb0945bf50b2857f7f"
    $a4="a37046b1875c3749a963156605aa4e2de7daaa11c8e4d05dbece0e9ac77b00aa7e7872cb9a9d134569d71d706f911650f2692b8ab4790550ef769f93b3810312"
    $a5="7a60196f7917d91d476d007c8f04a5d9369add010ac2c6831e2c0fcad4e2ff5b6e9a6ff0d6aed0e9445f6bba1dde8f97face7569dbc5bf7ffbe480d1e070611c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_adip
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adip. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRpcA=="
    $a1="YWRtaW4="
    $a2="YWRpcA=="
    $a3="Y29uc3Vs"
    $a4="YWRpcA=="
    $a5="aW5zdGE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

