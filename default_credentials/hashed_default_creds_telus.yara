/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3a898f3c4aac2370cf0a57a27c495169"
    $a1="30191c9a1f92142e0276bcd4f01b216a"
    $a2="3a898f3c4aac2370cf0a57a27c495169"
    $a3="fcb48d6431625ab4d04a9b492e66a978"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37c4d4e6b7563ed9c11807555861cfb00c26ebe8"
    $a1="6b287659e23d2fff7ee8dc4f4c0702af2851e50d"
    $a2="37c4d4e6b7563ed9c11807555861cfb00c26ebe8"
    $a3="bdccd599d668d69474f75c5570596f8a66a3a47e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="206795dd496c2bb83fc05e66d67818cc10a49b60199e6ecaa3b3eae7de2203b199282141a0ef0a7ba13715d021948125"
    $a1="2c89e0bbe65cbb7f9c1bac6c525b922d53d2c3fabeb53d72e5c9d0051be43efdf57001463812419440516349f0cb1552"
    $a2="206795dd496c2bb83fc05e66d67818cc10a49b60199e6ecaa3b3eae7de2203b199282141a0ef0a7ba13715d021948125"
    $a3="2fe90d730cbbab95bada1da0e098f2b68bb84718137e457196f992494d698d5df7211df19537274728fc2964713a6666"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4ef4e2cddf11f46738494e5809502cbf1f852a99341748334a7ed2e2"
    $a1="c4e0e6fccbb722d2fde1b0ae020b0ede6eda0df32a7cc7d4a50b017e"
    $a2="4ef4e2cddf11f46738494e5809502cbf1f852a99341748334a7ed2e2"
    $a3="7f28abf4c6a774ae262377695282c60527f07a09f31de7b17b8cdc22"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="33d3b5cefc8fce266388b4561cf580e0dd1eb3fc974913fe680f08f2229b09419994128302f9c778c14e49e5e012e7e2a11cf2eb6c5f1325d5985ade3224a6c3"
    $a1="6979a9d6156790e228d1055b094d2128b9090ccc403d313d092d7667222fef27edccd50432aaf3b92fd8e5c3eae05ef5507c031f7ad6138cf34337ad880de124"
    $a2="33d3b5cefc8fce266388b4561cf580e0dd1eb3fc974913fe680f08f2229b09419994128302f9c778c14e49e5e012e7e2a11cf2eb6c5f1325d5985ade3224a6c3"
    $a3="37701c68172ce5bc79c33826ef4bd451322c979426731e74bab520134f3941374a98c4e4954f7a2854776fcfa91f2dac8ebe8792e060b361fa0fbf5266d7eb51"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3501f5af745c255af263dd1b0fa83896c80737c0f1b13e1ced0b7e9c18782b53"
    $a1="5528480f04639b8c1894d2f6782b92b42c358115b7dd1c37216ed5a6acd59357"
    $a2="3501f5af745c255af263dd1b0fa83896c80737c0f1b13e1ced0b7e9c18782b53"
    $a3="103016a7a788de47741b47dc718dd0ecc406a2f056d52555de6880c8dfcad568"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d93f9d35f79ceafd33c1c4024ca7feec4a9c7408a1b4d7c1f8a898ecb139e8830382b42c3ece2c1dc17220d3f4cb5b0f37a8ce9619b9e0deee69261ddbb3bb44"
    $a1="2e3905dd4aa84f9ad96c333224eefe12a18afb3f25a4e7a5ca598b2cea3f4549cc4068b22f3149f3d4ea6c9329e2cfd6c7863ff436fec9df6741073732430e8c"
    $a2="d93f9d35f79ceafd33c1c4024ca7feec4a9c7408a1b4d7c1f8a898ecb139e8830382b42c3ece2c1dc17220d3f4cb5b0f37a8ce9619b9e0deee69261ddbb3bb44"
    $a3="aaec58b7aa31ee5b46e0a4115d5418c1f0ca252b0aa38cf3574b6fc37eb1f78ea9891a16b5f3757d7a90a118266cf3bca834b20a672b58b88759b6b52044a588"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0b665730c49c9d45159bb4f1e4dd416acf77b791b05c5c1a1d7c21a844d81deb"
    $a1="92f64ea0614f5d41fd64f96ccd5674c08c797e06aafa3db40ac4914a766325da"
    $a2="0b665730c49c9d45159bb4f1e4dd416acf77b791b05c5c1a1d7c21a844d81deb"
    $a3="ec43e53f5c4c39ea1edd437579fb76d14577ed3d2d01a8f2595f54f909c5d52b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f2d2a38af14127a223148a7454dfa3f1dbcd4c22f642d9a67bef0459"
    $a1="bc25b08020ca7c36369d181d03295a81673a4ac117fe954e64ce136f"
    $a2="f2d2a38af14127a223148a7454dfa3f1dbcd4c22f642d9a67bef0459"
    $a3="8492abd0d93eb9d818caf96799c8191c8b7b2a2f5337967a02725219"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1ba6d1172c326f0276cd13258aa5571d166ef190c23a32075d908cd9c1fbdd04"
    $a1="08de57d9eeac10ff3436e2b9bd208ad3b935b7d426c02bb8fce562535a831a89"
    $a2="1ba6d1172c326f0276cd13258aa5571d166ef190c23a32075d908cd9c1fbdd04"
    $a3="c4b57df7881cfad459bdcabe2d9d8768b015fd8f5d4f936ce78c780efbb6f74b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a6455a355979701693debc30537554659a8d1c598dd42b107aba9c803c14c2991727b63981248be477578eb84d28bdca"
    $a1="9777d8d868b5e5987881f8b7d4287307dd45a0e6313c4871e2f2dc4da09069f1d9082c24343f090ee0ababef2e049fb8"
    $a2="a6455a355979701693debc30537554659a8d1c598dd42b107aba9c803c14c2991727b63981248be477578eb84d28bdca"
    $a3="e6436f25ee7c56f0a32468820153b6b46c56f51ae7f4bb765eca24716785dc439bb57a5542dd5e4bbed8cece18c24b5c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4d588945f0a3a3ce4b928704d2549b34841d6f896504d261a7dae8b7bdc9746559994579a2ab4fd4e4eb83e58733aa741f2d8ab50f304a02f2509d274fd851aa"
    $a1="b4d464f69b3204ebd21af9f4943a91d956312678968d878bdd3be820e3464f54ca296ff29a6a2009527e888837e5109c81eae14d8fa9087904d718ab102b1dd4"
    $a2="4d588945f0a3a3ce4b928704d2549b34841d6f896504d261a7dae8b7bdc9746559994579a2ab4fd4e4eb83e58733aa741f2d8ab50f304a02f2509d274fd851aa"
    $a3="b8a90e7abb56d2a94a750fa27abf3597515f17468779346359743adba40ea0c3ff5a7cb9d2559047883b95465bedebd1046e79daa08722bd9f52e37e18496c03"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_telus
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for telus. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="KGNyZWF0ZWQp"
    $a1="dGVsdXMwMA=="
    $a2="KGNyZWF0ZWQp"
    $a3="dGVsdXM5OQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

