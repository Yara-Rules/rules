/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="5f4dcc3b5aa765d61d8327deb882cf99"
    $a4="3d36562899c388a7ed9c40dc5c2dbf07"
    $a5="bed128365216c019988915ed3add75fb"
    $a6="e8a48653851e28c69d0506508fb27fc5"
    $a7="202cb962ac59075b964b07152d234b70"
    $a8="e8a48653851e28c69d0506508fb27fc5"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="e8a48653851e28c69d0506508fb27fc5"
    $a11="59548977279905234b7ed3b1710837f2"
    $a12="e8a48653851e28c69d0506508fb27fc5"
    $a13="5f4dcc3b5aa765d61d8327deb882cf99"
    $a14="e8a48653851e28c69d0506508fb27fc5"
    $a15="e8a48653851e28c69d0506508fb27fc5"
    $a16="e8a48653851e28c69d0506508fb27fc5"
    $a17="86d0eb9b4f483c36fd48fca91211b5b1"
    $a18="e8a48653851e28c69d0506508fb27fc5"
    $a19="f89f124c0b230be9557c714912ee3320"
    $a20="21232f297a57a5a743894a0e4a801fc3"
    $a21="f89f124c0b230be9557c714912ee3320"
    $a22="21232f297a57a5a743894a0e4a801fc3"
    $a23="25df3104c0d6f0c1abd9c97bf6910771"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha1_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a4="9dcbd1aed153180d96a490ce54f4d135089406d3"
    $a5="7c6a61c68ef8b9b6b061b28c348bc1ed7921cb53"
    $a6="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a7="40bd001563085fc35165329ea1ff5c5ecbdbbeef"
    $a8="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a11="ef4bfd1e6d278f6bc7d4a478f02be2cb9581a0a5"
    $a12="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a13="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a14="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a15="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a16="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a17="3d19cc2979d1a577f9638faf43efc639f3e45aaa"
    $a18="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a19="5f2db4ccf14c861f406e678c4c5eb0e45053f604"
    $a20="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a21="5f2db4ccf14c861f406e678c4c5eb0e45053f604"
    $a22="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a23="2ea68420690fa9444daf83a68c9bbf249a7bed0c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha384_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a4="7c52a1a4cc0a5a564a59f2ce47b7b9526430268c9c73658fd0071aba688e258aaff67decea41ace266fc760c18e1fe78"
    $a5="68daa2085274c092300bc1893351b9bace14870a6982124409e5b27ec14942508d606e69654ce2ce6ff4729823e26254"
    $a6="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a7="9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f"
    $a8="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a11="741802f2fcaf951a053c4ca2897488d5a52f19ff6032ba748e84c06b3752673d337a97ad2f47da5bd50966c3a39927f9"
    $a12="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a13="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a14="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a15="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a16="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a17="3a0eae7020e85e2c14f5f8fa8c21f53f7888bcb38b79642256b005ebf56d14ee58e2df2ed69fa9bcdcefb56b2c48286e"
    $a18="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a19="78a0191b5a30f4d1dac97e7d0aa189e64e2dc8d4f4c581ab14034bccf5a8784e4487e4fbfd9b5f9c9e67c4e58a36f40f"
    $a20="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a21="78a0191b5a30f4d1dac97e7d0aa189e64e2dc8d4f4c581ab14034bccf5a8784e4487e4fbfd9b5f9c9e67c4e58a36f40f"
    $a22="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a23="899c40bc35b265bcbc064443aa0d14c2dd75ab9be998ae3226e0b18f070661404ffab049058ef92291cf467fd2ec1bc0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha224_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a4="fc821e0b0847b80d23696d188e9c8bc36248099f61657fe7b7921fc9"
    $a5="4fc07c8146ff8d20695edb3d980fab332183eb02af267d5d68de188d"
    $a6="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a7="78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"
    $a8="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a11="b32e5865214ba5b064445473cbced17470582e0d48f74f1ba1c4fd0f"
    $a12="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a13="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a14="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a15="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a16="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a17="5583f387b1da968ced7c8da81d954f37516de091ad13993ad1317ed6"
    $a18="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a19="5dfc3a8323baf0e115aa76fe8bd0c8c8b4bb82815d5b91edbc005dbb"
    $a20="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a21="5dfc3a8323baf0e115aa76fe8bd0c8c8b4bb82815d5b91edbc005dbb"
    $a22="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a23="eed7b2cbd1ee238a7d30cabd77310e9a772065944ed82fc99dae2ef4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha512_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a4="b61457a5d6378149218313d824dc6a4154b556b2926a144f4cb3916786b37b02fbcc6074e5a6aa649ff4ddb1243c7c33f06970c2a8117e51397f96d286c5e814"
    $a5="e0469addd8d57a3623494096dabc19bebca1a038c9da696940b3f853d106a6ecfa5bd60ce8e72884efa3bd92b930da178fd616f40facad654212d7c2f8817dd4"
    $a6="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a7="3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"
    $a8="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a11="3728e221db5745612ba47a3af070639388f5803646308e944fa0b41064c84a7139e9226aa3320ca7e919cb5acfe4f5b7c68fd6ae6a0a0b11b38187829897adf5"
    $a12="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a13="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a14="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a15="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a16="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a17="0268eaa7bece8a00a946c772a60fc45bfa629108e157ba3a93910127b86a6b3bddb593ed1fcde906215d715880ae1c2ee0b9e2ccc555ea225e2871c7d6448a9a"
    $a18="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a19="a1d220382228290b9b090568e06c5a537370d95e70a3943a55d4dcf8b6f4f8a384ccc95a80968c57e426cb6f8b511eaa901a8f92622e405904b1872f501c08d1"
    $a20="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a21="a1d220382228290b9b090568e06c5a537370d95e70a3943a55d4dcf8b6f4f8a384ccc95a80968c57e426cb6f8b511eaa901a8f92622e405904b1872f501c08d1"
    $a22="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a23="119063114fad6ad6153a5917a1ace6c22430cfaaf3b94858ccb37ffd58ed14dc394a0e814d45699362069ac888121abc23eba49e108f41934347109f8f007f53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha256_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a4="4ca1018f8f72fc8f22b13cdbf8a44acd2b1e406d9f6dbf946006ba79871c8813"
    $a5="8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9"
    $a6="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a7="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    $a8="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a11="b1601f694b9d336c35fc456de5697dfde5e1b1ce4e8c40766fb6cb763aba91c7"
    $a12="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a13="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a14="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a15="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a16="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a17="fa0794c0cd75edf9b0c7356d2204953cb4dc76ab09b74b815ce1a75a86d08034"
    $a18="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a19="8e1f26139c47388ee05a3aa84fc04a78eac158fd4260ec90f2773ae11a49fc4a"
    $a20="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a21="8e1f26139c47388ee05a3aa84fc04a78eac158fd4260ec90f2773ae11a49fc4a"
    $a22="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a23="c16e8324ec510723c3370e590d8f4501e216b427b37fd5ef09ebba78deb12112"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2b_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a4="d444c2b40ad5a1ed5f780966ddbbf64fc138e67c8e500e4b52497a46066db56d6343b7dfaf06c70b227bc56db0b239b35356c82c6e2a1b1491a64c790fe92e04"
    $a5="493ad8c53ccbc1109d8db20847d7da79cd6055c86c0c0f5a823d3cfb593f8a8e266d2d560fd9713931f0975db479424a3101c308743f792860924a7b5010f749"
    $a6="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a7="e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3"
    $a8="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a11="34575fcd1829a362d496d13d9c4ab58cb6044478f7d8351175d5507d6b82aff92173c7068404db57a3735c53d20b9a74c9fa40afed0754a3f7b0a25aea8e9775"
    $a12="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a13="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a14="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a15="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a16="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a17="ef895938f8b126415cb74b7389c4ac340b57f81a60234e0581ceb0dd45a518b436cb3ddcfb76e50d869c1ebf26a94f3b63cb9553312ccb26507eaaca4b2b016e"
    $a18="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a19="75f501d3e4ee3568e47a18e6cd82e4d41f8f7fbc3007c025330cdfe82d2f579c8d33763d7932bd45f9e901654fc0e30443b9e52e42ff263cec696c6528973c63"
    $a20="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a21="75f501d3e4ee3568e47a18e6cd82e4d41f8f7fbc3007c025330cdfe82d2f579c8d33763d7932bd45f9e901654fc0e30443b9e52e42ff263cec696c6528973c63"
    $a22="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a23="b593b2e93c0dd16bb8a4681f452d04c76e85d0160cc7e76b1ca20de4f00d20478177a5824d70f4f5d797de9b78da13ccc04e3944e70f9f6b5f99e758cb52c2bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2s_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a4="0b417584c26fea0269072efa404634a30a93c1e929226917d229ca50dee85649"
    $a5="0da254bc3667d03941a3095a2256300c4b25089720d4a324e02843c22fecdde4"
    $a6="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a7="e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605"
    $a8="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a11="aedaed5061e8497b526a90c179783a3df87d23d7af08f01c0cd36763dfd7a759"
    $a12="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a13="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a14="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a15="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a16="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a17="90ad0f1fcf4f195caf6c4c7efb9230fbacc76a5cd94728cb60a81895f3608451"
    $a18="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a19="76fada65948ac2e8ff9a1ace9b082bbdf7c547b9a693865ae37ce29b624eeb98"
    $a20="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a21="76fada65948ac2e8ff9a1ace9b082bbdf7c547b9a693865ae37ce29b624eeb98"
    $a22="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a23="06c72149011421e1f91fc6242d6c3b1a95cd9febaada1d3c79781beb2c8e035b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_224_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a4="4f7ca2890fb7312749158a56dced45a3416bd50e3b2a21fbe73ce370"
    $a5="7dba765e4642eb08f384328cd06aba95b33e9a872ed559bf50131458"
    $a6="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a7="602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"
    $a8="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a11="d1e135617b1dfeaf29c767697e054083fb4cab90682fc59e41363bf3"
    $a12="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a13="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a14="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a15="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a16="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a17="20cadf40052adfc3b0cefb9b367641475e5573b3c6a7a1f2cdf83384"
    $a18="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a19="daf90d1eb720d4863cc6f87b96ca0b82f908545508d89caa34c7fc8f"
    $a20="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a21="daf90d1eb720d4863cc6f87b96ca0b82f908545508d89caa34c7fc8f"
    $a22="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a23="c317c0ab11d7c71a4c7286471e7c9be31c2f79ab18d211ccd8a48bbd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_256_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a4="708c415af41c02c2da22e3db678cbfd2918bb2f82bfbba34fc792af1f98596e1"
    $a5="be87f99a67e48ec4ec9f05b565f6ca531e24b9c71a62cfd3a58f54ebc60115ea"
    $a6="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a7="a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"
    $a8="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a11="d2102befa98bf91c59cb8edeb04feb74e77d07d5417bc036b976176c9f6457a8"
    $a12="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a13="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a14="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a15="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a16="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a17="97912135444a7a57c188aba364e445ba5cf006fc23a85efca243b8ace433922d"
    $a18="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a19="25c05a20fc664fe2e343d272f4d42d24dcb6756614b554fd862a51c28052364a"
    $a20="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a21="25c05a20fc664fe2e343d272f4d42d24dcb6756614b554fd862a51c28052364a"
    $a22="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a23="567166287d1e3e1c701262d1b36e3f55af484d45b531501d0a12b686a81e6f80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_384_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a4="510708f9246678a11f23ebc3320fa169663b13e17ec2652b136e3e5bff9ef6e602043c45690d4e9028c999fddfc80949"
    $a5="d1d974afe6993a728a48bb032fdaea8547a0b676f718b6c2ece8a583e98a20aa3b48ff211f88ca7b0116ee0e41bd62ff"
    $a6="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a7="9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007"
    $a8="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a11="38d95059ad42bdbd28eed860428ccfd696fdfd2c9c05b2db074f019f981cc6af2a6793e38afcfdf9a3ad3b0a4b8c88a9"
    $a12="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a13="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a14="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a15="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a16="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a17="a82957ea207016da5b14bc00f0484484c780f79dc1cc926538d7e4ef5f25e862ca95b129bb2ae3e7da2cf9ac195c237d"
    $a18="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a19="ef4d0938d4736f1800f39a606219c2fbf2261e3b194ab2aefe283da6d0fbe62ed0083d1025bd2e12807393c0932ed684"
    $a20="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a21="ef4d0938d4736f1800f39a606219c2fbf2261e3b194ab2aefe283da6d0fbe62ed0083d1025bd2e12807393c0932ed684"
    $a22="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a23="7cd3b5765fb19d9d3a5a085dbb031824e8261c7e3f622315f2b6efdcf7715cab24af15c59bdbb20ecbc03410e52a586a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_512_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a4="8d789c13e6f4c834f517bed9c0607fe0325301cf3aa587ae9fabd42df193e919e0da0512f939b5d66550432e756d00190557b9742cf5eee7f996c7fcb0651986"
    $a5="a9d14097c6b60a6c07a8d7b02b48feac60e83f43e59122ad00cad8122c492eec52f4590a18b733b909e3f17f2fa555012254b1ef6800ab815eb36a4098079532"
    $a6="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a7="48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"
    $a8="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a11="7ccb726c79b481d16bb7be5eb694ff3d440c4c6e53d8e23ffbb679231daf113ae2a488ccac5e7645640a2c6dfee28e14085a8843d1d7a4352c5652a56c2c600c"
    $a12="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a13="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a14="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a15="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a16="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a17="667c5ea78b5d9e6020e4d7a80a4702e3cf9ad5ff9278aa82cc9c632e8d30e3beae5fc025f8c064952f10b8145846ec0c18492b5d17297f0425b85f7033b4d004"
    $a18="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a19="2a90793825a81c9a0fe5d8f28a7dc11bb9c805eb2c484cfbad446d5751c15f6def6fe371a8232c767a3f06ea7c2b30b9bd89c8ae898eaacac9141abd3da42c8e"
    $a20="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a21="2a90793825a81c9a0fe5d8f28a7dc11bb9c805eb2c484cfbad446d5751c15f6def6fe371a8232c767a3f06ea7c2b30b9bd89c8ae898eaacac9141abd3da42c8e"
    $a22="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a23="e0b54c04ea703d4b3da3d838687b2b8c454bca97fff7bbce424aed9bbef60ef622c44b0228442ba93c6f59c42d5b0a603dde74e36ba9b66c52ce1c37c9f9131d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule base64_hashed_default_creds_postgres_postgres
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for postgres_postgres. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="ZGNtYWRtaW4="
    $a5="cGFzc3cwcmQ="
    $a6="cG9zdGdyZXM="
    $a7="MTIz"
    $a8="cG9zdGdyZXM="
    $a9="YWRtaW4="
    $a10="cG9zdGdyZXM="
    $a11="YW1iZXI="
    $a12="cG9zdGdyZXM="
    $a13="cGFzc3dvcmQ="
    $a14="cG9zdGdyZXM="
    $a15="cG9zdGdyZXM="
    $a16="cG9zdGdyZXM="
    $a17="cGFzc3dvcmQgICAg"
    $a18="cG9zdGdyZXM="
    $a19="YWRtaW4g"
    $a20="YWRtaW4="
    $a21="YWRtaW4g"
    $a22="YWRtaW4="
    $a23="cGFzc3dvcmQgIA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

