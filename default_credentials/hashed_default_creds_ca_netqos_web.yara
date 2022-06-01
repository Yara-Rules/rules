/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="553188acbaedf9e84d3e2802c399720a"
    $a1="0cbe44e34ea1eaf8ee7aad7f7f60e337"
    $a2="8b51cbc36aa0daf9cb1305c3e7b149d8"
    $a3="0cbe44e34ea1eaf8ee7aad7f7f60e337"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a0c03f2fb811382d9406ea3fe5a61da90476088f"
    $a1="d122031b45f83cd889411f3fa8c802028947947a"
    $a2="fcb8c0b1b38715e1b9c7758b0f93976aaff65c5d"
    $a3="d122031b45f83cd889411f3fa8c802028947947a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="edd90d4380e18e8ac54cf72e8802d35fcb929b5c26ff819498eb08b0b3de7aa76331eabf64fae2206e2388cf013199cc"
    $a1="82488aef6a1e7e27f2fed25da07a4e8b2500bdfd125b15e927d22de129fdc16858b1c9f8133112c3349114dcd59b0b5b"
    $a2="2b3574a9fad343bb0856da62a7aa719c117510bca31e766ba77061930cbe3cf38fa84c54fc3140d00830140ac4e04b07"
    $a3="82488aef6a1e7e27f2fed25da07a4e8b2500bdfd125b15e927d22de129fdc16858b1c9f8133112c3349114dcd59b0b5b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ea324e0ac4777e58a92387912c5b505d7d0a6f5db9d39c445d7ecb90"
    $a1="5f9da6777dcee86e3b0c3fdff90eb7239580415da08cb2bc632a5323"
    $a2="f6eb53fd205295c3a4e2bd7c419c880872e73bdb279b7ea91c4b856e"
    $a3="5f9da6777dcee86e3b0c3fdff90eb7239580415da08cb2bc632a5323"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a0ad1858d8e5490e51e6c79bbe244e4efa67c19baaf6206d71be662c41262615c20819da94984531b5d2762cf0d885085ab5fcf7751b239bae23587e51dd6823"
    $a1="b4b47425204debb72cf4bbb14d32520110b357378c2009e90838d10ec658c72b2243897e93682a0e00bb811338ad6791cbf5bfa5808380164804b0381a68457c"
    $a2="1d141f905badd7d0541a9afb1eebde8019f179220a2342395259acd3e737959e584869b4a32488eddf86afb515fca8b47e3aeb75d82649b636d2dd198e3141f6"
    $a3="b4b47425204debb72cf4bbb14d32520110b357378c2009e90838d10ec658c72b2243897e93682a0e00bb811338ad6791cbf5bfa5808380164804b0381a68457c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="62af322f1b4c8486c31070e10cff6ff44842bf56069e1b60c8270d43a4aa7cb8"
    $a1="af1a411ed6a2fdf0eddd9939082f31132f6bd6b7aa1248e7984c8df1ffd0f783"
    $a2="8eded4f2ebb9f52f61dde870aa854c8ddb06c51bb7fe8e3c8294c1df689a4b57"
    $a3="af1a411ed6a2fdf0eddd9939082f31132f6bd6b7aa1248e7984c8df1ffd0f783"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1985408c56f9a09d04c375c25450a08912e2c572964e7b4ec3f9c15caac00d7a56ddbc494bdcf0c9acc68d56e8a8cd0cbe0869d5c31abecfc209c75b35143943"
    $a1="40fc9a6b8899f9cac60ac8625073e1e38d9b9b28808d890895b51c33f663b2522117d5f7232351f479ee0c8ee2c672762e6bd05f3e94641b8060b73609c6b4ef"
    $a2="b64c0d850b7740d926f4c4ed9d58d29a72ae928e52b0962134b0e246a54f6793b9b0a4e285c6089795271a028015c2bc0ab4868b2e9b7ee522e7aa0eeb610613"
    $a3="40fc9a6b8899f9cac60ac8625073e1e38d9b9b28808d890895b51c33f663b2522117d5f7232351f479ee0c8ee2c672762e6bd05f3e94641b8060b73609c6b4ef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="01385c4d3f3038c1de7c5593409e9ac937c46a9ea9d376fda0c747b389451f32"
    $a1="20b76afeb2ba472287a9e663c13233559211cdb904639369d98ad2d0d48d1e41"
    $a2="67536e76f4557c75fc3e48f28d359b6e24c082c64f8aefa949717e1233e6e3b3"
    $a3="20b76afeb2ba472287a9e663c13233559211cdb904639369d98ad2d0d48d1e41"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="70a0334d7895281bd14bfb98e788d5ab45bf0afc30901dcadf038e0f"
    $a1="4497d476664c5cdae96ee733ebb8410f41d2532f8c75e02eb9b30235"
    $a2="f0546d72df8036431ab74245d0366432a0af204097cbfc5649ff61dd"
    $a3="4497d476664c5cdae96ee733ebb8410f41d2532f8c75e02eb9b30235"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4041d8aad7dc3e88a67358053cda689eca3562ed1fcacc7d367284f61170f87c"
    $a1="10fc63c92fe1228ac86cb575da83dab26fd66b70b98a9d12284d22bcbbda796b"
    $a2="5fb62909fca27fd55bde18f90056ce92da9a82b204ef11d36abf15b72d40f5b0"
    $a3="10fc63c92fe1228ac86cb575da83dab26fd66b70b98a9d12284d22bcbbda796b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e4fecca7f483440a85f2104ab1cea61eff9b9e5495d3b021e965cd345f88586aa0d4908ce5d72f7da6ee5c067b97615"
    $a1="c82e6990c1734f950c4f88d3fc736debc43b14be4bcf9664d01d50e0c1a8c0a1011de2e6714d5a7d6887f25255edd305"
    $a2="9abfa7785611364bef23ecff1692dd48ef85d7ca6094fcb75f077b1427b40767214eae8aa9a65a4d738c40baf13860e4"
    $a3="c82e6990c1734f950c4f88d3fc736debc43b14be4bcf9664d01d50e0c1a8c0a1011de2e6714d5a7d6887f25255edd305"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7afd2de3c9e03f3254b9cbc545ee7594bf9ce416b52373d04eb1f51c573005052afe244517d11a2b7c1387ce78d333516bbec41bedad3c43062ef42b0008e43d"
    $a1="7b8efb1164e3b09c35749e60e804fe5d1b1193ac6f9e7c9c0cfb8a09f235b470e7ec5a0e60279fdf44bbf3dd5c0c9c2a73df77dbcfce26c0a8bc746bf8df5b63"
    $a2="5b9d6056946ae91d3e55a61a3604a1aa7d0e8ade4153ba30065da10c870298473996a6df39edd1bc81c5c7dabab0196aa3570421b57eb193101d7e53f2319f04"
    $a3="7b8efb1164e3b09c35749e60e804fe5d1b1193ac6f9e7c9c0cfb8a09f235b470e7ec5a0e60279fdf44bbf3dd5c0c9c2a73df77dbcfce26c0a8bc746bf8df5b63"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_ca_netqos_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ca_netqos_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bnFhZG1pbg=="
    $a1="bnE="
    $a2="bnF1c2Vy"
    $a3="bnE="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

