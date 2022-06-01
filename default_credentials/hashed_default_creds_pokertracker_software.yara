/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e8a48653851e28c69d0506508fb27fc5"
    $a1="5e13f5f57d9792d3b38d5f3795e15d0b"
    $a2="e8a48653851e28c69d0506508fb27fc5"
    $a3="ba756b3e4e93533bf0c8fafd5dab9a5c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a1="745d0b2380e21353d526db47a87158f2065563ee"
    $a2="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a3="f76c18918cc75fb69ce299338a13f24278ddbef1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a1="4dc8a5cf162cb741950819283217c3f9fd667c87b964783363e760f3944e62c1e7c7969da79361a0e5d34a880619e8b0"
    $a2="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a3="9dace96ea60eaf0a2aa29136f63c9e6dcc40a11e38c02d0ac82ca3f15a96f289c39a33a44db3a298ee888112431094b3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a1="ff265e0ac8881bdb8a64ab653840c680d81670519b88585f958a896d"
    $a2="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a3="638d1fe493896e76363a57926604a0ccf9e825aafa96c659f8657614"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a1="fd9d3f0c2eb9893754f4ca53779e8bfe514a1c61d5e44526a323151cc5b34b742a41f79feb02d6f2e581c173fd55e73a3dfa96f6f720f1e4b035a62f72565b45"
    $a2="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a3="783df3fe6ab1cee1f6cd60dec3362abb74ada7cbdf9bac6fde6a32514f52de83c69193a9004b2008480cff495ea57d0fc67cb07a93d7aeced5ddfb1821d267b9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a1="7c7853e3659d1c01e65f3cb460ac07d079288bfa5bc21aae3d31fe01a0814278"
    $a2="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a3="cfe6a1d191f7f64b15734bc6a54ae10deedc0c5df936ce1ba2b48ec117112e49"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a1="d441e702fb07b873451c77529f9f335a2ab25b366bb9506abdbc4aad763bc1d386a35461dd9f052ce32fd24900f44e70967190534a9fc92808f8d4e696200e55"
    $a2="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a3="b90adabbaf359ff867a8244f8578e42208b1b31adc4fa3467a97d1fa0182690c66863568f360887183beafa242f15de0dcf092b9210ea2bd459e015e666b7ac1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a1="8cb1f679eab1704dae0706209187dda9814c1e64e253f5d392b48094ba2326a6"
    $a2="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a3="2b6960b1810a43c4d841e7459f71b4612f67f6e0dcb6db5c2da82b245c3cb544"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a1="47a38f4b5bc88d3c6839ad535b801aae8873cb10720d59beb0689664"
    $a2="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a3="0804a519bda432cc382df7ca38d5ca53377597e4f3d5625c5a0269a0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a1="a6e8dd12dd477d6cc85af9ab82584e90004a76ef37472962a3e29043553f1435"
    $a2="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a3="002f155fe3eda005e73e92fafa6300190c219e8198d9c0b74f325b586174e509"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a1="53d93821daa5cf6912fc22216118b625b0261cbfa4666d5847d42b99664137aacd4e31e3ea4a4d0df2a1695c2c1fabce"
    $a2="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a3="9b5a4bca0c036e9cb3ac5a2bb3c9bda4e892a2a66bdca42f60459e6d6e01497cdacdf09b4a7f05d2b5169dfa7b98a06f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a1="987e939fa2bbac745e66672525d4afa672de58df204febb20ce61060336b89254403fd8692bd26ef4974875e3a0102ccbd9fe7032f7560adedcfd70ae6ec957b"
    $a2="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a3="c935abae9e50c4fafe2c3f40ed6478696344694e797a0283bb97cf275b4c7ccd02d87a7473e383e9c726beb28fdad65b288c0cef81c3b4f925558e17316e1745"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_pokertracker_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for pokertracker_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cG9zdGdyZXM="
    $a1="ZGJwYXNz"
    $a2="cG9zdGdyZXM="
    $a3="c3ZjUEFTUzgz"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

