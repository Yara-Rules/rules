/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9e9898c7daba7e4e626296dc7c99bd17"
    $a1="5f4dcc3b5aa765d61d8327deb882cf99"
    $a2="ecac6fe5e9f6619a392d146e8b0c692a"
    $a3="5f4dcc3b5aa765d61d8327deb882cf99"
    $a4="f0258b6685684c113bad94d91b8fa02a"
    $a5="5f4dcc3b5aa765d61d8327deb882cf99"
    $a6="f6039d44b29456b20f8f373155ae4973"
    $a7="5f4dcc3b5aa765d61d8327deb882cf99"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ea8b8d89e4b7320d73236b375a7683a4ccd3a296"
    $a1="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a2="966355535b56f1ab69d1be7297722bff45943563"
    $a3="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a4="e52c854d5631eec7468ba4727b4c77eb745f2965"
    $a5="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a6="84c29015de33e5d22422382a372caba5c58f8c01"
    $a7="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a28d1366f93b98aac429dcce1a670edf63488c0400720a77c2fc4890f514e93c0476ec6b6df5e388eaf0b7cf7a154cb1"
    $a1="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a2="ecc8b9e30f105b8f50cebb6aca60d3e6106cd2a65b34fc315a69a26ba6336316b1ebfa55a89e18cf828d55cf3f69b544"
    $a3="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a4="5c1488428584f373fe5de7089ac4dc2d6af42bcc038f9876918ae33b4c3c0678e5a9b90bfb05947722b3637d462666ba"
    $a5="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a6="2a161a2ccc61d47bf69a1c3710d7e4e81625ccedba205552086aa0bf5a902cccd0213065a2fe8b67230f562cf7ce5310"
    $a7="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f83fe22c5d1f29fba0410c28e50a91ffa909f84570152558d7d3fce1"
    $a1="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a2="187600a5bc426f436a588ce4a150fedcbba494c9e5189b8fbc2c8e78"
    $a3="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a4="edcbf9795847b8a2127aa24594e32fb9e47158bed610a23afb09236f"
    $a5="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a6="531105236d0f537062e00dead709e5586948380805ec402c12e1f772"
    $a7="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="36f0d36e6f020fc648af15606ecda7c25fc78db989fbd0eb5948504b389f92aaa3c3b934b2ae18f1104490a033f732efbb03526938ded59e944be89e0e9c6bc3"
    $a1="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a2="9ec66837c9fdc1508e24acaa41d148e22e03bd473fc5afd11d230c587c766be13c8f865522bc6bf3e0eaf927c97b6dad80594881bedaf1c06542b55842f45698"
    $a3="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a4="4cfbff66f656e328b2b7c593bc198174b1e09b113816040c8f567cc26f03c6abe13ef411f6f5e4c99d7928c23e45ffcb5714aca00bfbc626c8d31ce068dfa8fc"
    $a5="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a6="2422209232976a5ab86c86ebe89e63638ecce4c6eb6fc09896e5528b08c89f9db46cabc46f352c12faeb6e08afdeab43b5924f111c5c375211696d267d4fb980"
    $a7="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="766cc01117955ddd300c57d26a3ad99462ddc11c7446ab610a5baf7a4b993221"
    $a1="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a2="f469beecc6e76fe41fc4556460ffbc64e57bc2161422a9d54657232e3c631e1b"
    $a3="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a4="8a2cc0673b1c428315fe84c0138d95c3ddda30baf81e7d9aa821f1ca47098193"
    $a5="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a6="e3b89e9d33f88e523083d8b4436adcc3726c89e97fd3179a2e102d765d1b16ed"
    $a7="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfbe0941012164e0ebe7773db6dd1e1847501917d16d34c44aab160b67a45091f69ec0bb56f4de91d6d5b953adabef6bc6867230d89f645e294300167937250d"
    $a1="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a2="8ba5b1805544195a73a4a523850d088f20f9a6618ddfb82fdedfaa7d3b90753a24869010a56c396928719fc85a2eb7160d5c800de75390032c7c41ee9b3fa41b"
    $a3="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a4="d0648eadb01154c79b43028fe4f35825d28c13cb0deb390ec754d89c6530c1ed5781844f20d0b133a5507bf08821e815cb69876c93faf003a84e4eadaf9b1031"
    $a5="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a6="f249d4309451f14dae44fe0fdd87cc1e34d2720d3b09e220237e81bb673879ecdbc7fb00efad6311ec531f219fd7088a02deeaa48399dae0b6dd6134bb9bcdff"
    $a7="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="76463344ed6927e84913687b34962e1fe36478daf4d948328c697de561bb4987"
    $a1="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a2="1a4644c3f2b6600a4056f5db7c82b54abb23d9a3187db7f777a7f618aa7c1623"
    $a3="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a4="db896e1aec0f06f4ef36f589bdc2e7dc96d4fd0deb51538a90806f6025ae3291"
    $a5="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a6="8b1d631ca5f3da655b5ab728ab0712650f16585c86b2abdf1606dcd2bdaca61f"
    $a7="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f948650be931713674a3be682d6b6a1b58b2a6849b46218491b5cb09"
    $a1="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a2="1e6f2de922945eeaa42204a8d5d8af95f50609578e3e8429507254d1"
    $a3="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a4="584329b667261e773acb3f183233dd682c225a0a9bdc551e0f10da8e"
    $a5="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a6="eca85ad4df91e877b0c299df0cd0dae2a84457bdb1dbc0a4a119643e"
    $a7="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="136801b319f82bcdf4e6b1fde390e8bbc2bfea542fa749ff6b7d625d0194359f"
    $a1="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a2="33a944926ae2633d9ce18cd7c2c8f7295b5632061ab3e8cb1adc1dceaad2fb2b"
    $a3="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a4="ddad25fb24bd67c0ad883ac9c747943036ec068837c8a894e44f29244548f4ed"
    $a5="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a6="657a4cf2a64d6fc3a8d217a4e1b79547d09efb1db74e8eea4e4cd799132c8bfb"
    $a7="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="74f4f7f06d611aa589d314f00862805a1fd0aacd6570abf369f3b4530356f0944c06c45e7d1f72b3aa0a603baae0488c"
    $a1="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a2="e045c6bddd0cc3c6cf894ee706ea7f5af2e77f37a61fd98f8cd5e12aa0a00161dd595f3e8fbe48c6be437a30b6148fe8"
    $a3="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a4="34fffde42c88523308447aa4af6b10f6ef258ab6e15a0a4c364fcb40b1f980febdf801a72ccd980fd2669ad4f40396be"
    $a5="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a6="9e0407173e24b9c7b4f0137ffa93f405f8b38d6ef86853a5b28d35ae0e7b07c685512cfb17521591d9ec43b3c9c16e87"
    $a7="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da0c5013c9573a8180a672f335ab7d8f7dddb4a39d71514c40193fa537afb39fadde316eec144d73524adf70e5bcb4b1d5ba67150d3d52e5df29058418dc5a57"
    $a1="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a2="ed49c59a1102e2d1a9e587ba701749ce0a830119501738eaafd88dba2b1ceacfff416233e480b370a2ae5984aee680b69eca0fe6ae2075e57ba3f0f6394d4bc1"
    $a3="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a4="7201dcc5994fb5d74bc79c39ed7c755924c0d29a71f2ddbc257f35c69f06b4f730b357f71469e7087597e77e9538c300ea5c988dcc57e21a3f93a9a1d466310c"
    $a5="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a6="c4bd18fa15530ea1532d144aff5e7665dc92db28e03c7a0a421d1d0e16948c05178f47df0d5044c35a2c8a2be82e3ec881e81d4127dc6c301a188be799e14aaa"
    $a7="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_atlassian
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for atlassian. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y3Jvd2Qtb3BlbmlkLXNlcnZlcg=="
    $a1="cGFzc3dvcmQ="
    $a2="Q3Jvd2Q="
    $a3="cGFzc3dvcmQ="
    $a4="RGVtbw=="
    $a5="cGFzc3dvcmQ="
    $a6="VXNlcm5hbWU="
    $a7="cGFzc3dvcmQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

