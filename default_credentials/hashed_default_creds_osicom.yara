/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ad42f6697b035b7580e4fef93be20b4d"
    $a1="29297f786f4ad15384c7480c84a9d253"
    $a2="29297f786f4ad15384c7480c84a9d253"
    $a3="8f9bfe9d1345237cb3b2b205864da075"
    $a4="cbb11ed87dc8a95d81400c7f33c7c171"
    $a5="cbb11ed87dc8a95d81400c7f33c7c171"
    $a6="cbb11ed87dc8a95d81400c7f33c7c171"
    $a7="8f9bfe9d1345237cb3b2b205864da075"
    $a8="084e0343a0486ff05530df6c705c8bb4"
    $a9="084e0343a0486ff05530df6c705c8bb4"
    $a10="084e0343a0486ff05530df6c705c8bb4"
    $a11="8f9bfe9d1345237cb3b2b205864da075"
    $a12="ae94be3cd532ce4a025884819eb08c98"
    $a13="e3afed0047b08059d0fada10f400c1e5"
    $a14="ae94be3cd532ce4a025884819eb08c98"
    $a15="ae94be3cd532ce4a025884819eb08c98"
    $a16="e0cbf0e62d03796f31da47099682b72b"
    $a17="e3afed0047b08059d0fada10f400c1e5"
    $a18="e0cbf0e62d03796f31da47099682b72b"
    $a19="e0cbf0e62d03796f31da47099682b72b"
    $a20="efb2a684e4afb7d55e6147fbe5a332ee"
    $a21="2c17c6393771ee3048ae34d6b380c5ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha1_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="32faaecac742100f7753f0c1d0aa0add01b4046b"
    $a1="55089334dd9c7803537f7351ea6b9a11a77432f9"
    $a2="55089334dd9c7803537f7351ea6b9a11a77432f9"
    $a3="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a4="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a5="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a6="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a7="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a8="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a9="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a10="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a11="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a12="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a13="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a14="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a15="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a16="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a17="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a18="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a19="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a20="e1d0c6c1c29e6ad5164072a5b21340dca7fcb052"
    $a21="e80721793c24ae14edfca9b26ad406a9815cd3ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha384_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b345909bba936cdc8ea81ae3ffe6c668481d351df7c46efd502f7f7f94dff566d40a9ecaa6621609419ad1903f74a799"
    $a1="bc660922e6db670bc9a6d33208b387da80fc60ef4f56d65754579ae8a787635178da7fe849ae3c55cdb730855ff366d5"
    $a2="bc660922e6db670bc9a6d33208b387da80fc60ef4f56d65754579ae8a787635178da7fe849ae3c55cdb730855ff366d5"
    $a3="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a4="87859ccf51716260936c266b4a3ac697a0695ed043abac013cc69eb04f5829fb4eea5b15b51adb334f150161d3fe1dbd"
    $a5="87859ccf51716260936c266b4a3ac697a0695ed043abac013cc69eb04f5829fb4eea5b15b51adb334f150161d3fe1dbd"
    $a6="87859ccf51716260936c266b4a3ac697a0695ed043abac013cc69eb04f5829fb4eea5b15b51adb334f150161d3fe1dbd"
    $a7="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a8="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a9="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a10="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a11="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a12="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a13="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a14="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a15="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a16="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a17="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a18="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a19="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a20="49f042f1390c116a42a26a42bf1ce4f3904d9004cced0b9ef09824a7b2d494d82dcf892f48ae9136501d2ba326832e16"
    $a21="40fe2d4072282a91177bd8d13977c0ed68c7dfccf6e7eca10d481238487e4e318ca87263da20ded9138ca7725aa10263"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha224_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5cd7fd4c793de52376f74a016cf373db2426deac143682521f0d7779"
    $a1="88796e3e59767d3ff43367b26f6bf9ebc13168d3ef032b7a674de5f6"
    $a2="88796e3e59767d3ff43367b26f6bf9ebc13168d3ef032b7a674de5f6"
    $a3="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a4="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a5="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a6="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a7="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a8="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a9="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a10="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a11="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a12="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a13="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a14="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a15="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a16="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a17="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a18="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a19="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a20="d951a81aca79223a7f557f032ea0d8f773f9867b74004a4f3125c23b"
    $a21="2a12e8d906468d24de4552c04fac544c36a2775d6a4d206bbf20bb43"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha512_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="225d05b918519458a8fcc1e6493a4e854c004da76f6250b8f52197f47094f71ee984725c31446a1967f0d55f4dc74793dd44d932f2bdf50d77d4288d663bf1ab"
    $a1="2ff7c8b30e2d8a2e5775b1055e91e94a81e6bf6570adf528547e13fabc4942a5935edc73a059ae882b837bbc1cd58e0f4331c82523023dbe918279995f4f3a3a"
    $a2="2ff7c8b30e2d8a2e5775b1055e91e94a81e6bf6570adf528547e13fabc4942a5935edc73a059ae882b837bbc1cd58e0f4331c82523023dbe918279995f4f3a3a"
    $a3="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a4="1e1e70b7fcb2621d95b9ce261cd5d03b30dfaf01f1bbc68af639e44f50fa5c31a4adee8ffc9517ae62db3b1ba7f06a8d9bb427106ef77c5a4cccdd7490f87721"
    $a5="1e1e70b7fcb2621d95b9ce261cd5d03b30dfaf01f1bbc68af639e44f50fa5c31a4adee8ffc9517ae62db3b1ba7f06a8d9bb427106ef77c5a4cccdd7490f87721"
    $a6="1e1e70b7fcb2621d95b9ce261cd5d03b30dfaf01f1bbc68af639e44f50fa5c31a4adee8ffc9517ae62db3b1ba7f06a8d9bb427106ef77c5a4cccdd7490f87721"
    $a7="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a8="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a9="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a10="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a11="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
    $a12="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a13="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a14="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a15="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a16="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a17="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a18="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a19="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a20="8039e274249e5df52a780f1c3d913cb1769d8edb30707ed14fa453f701c8177fbc4e72c423fda59dbd95b5ccd951b2a73c73307ea4eea72fd0383cb49d1274a6"
    $a21="9d9f1d99d6a2e8488d0c330269f0a15d1f56bd4b309c840ff678fc6a32f15e2cf6efaf76e4d5471e7af9f88a12014a7ae6f91fa2e08fc622493920a555290c93"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha256_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0b8e9e995d8d77f1e4770f0f79665aee6f3f70247b3735422daba73df4c3096f"
    $a1="2aa10c7e1ba8d76746634bdb832005103645e62913f9f5cfe621e8f088915abf"
    $a2="2aa10c7e1ba8d76746634bdb832005103645e62913f9f5cfe621e8f088915abf"
    $a3="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a4="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a5="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a6="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a7="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a8="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a9="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a10="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a11="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a12="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a13="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a14="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a15="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a16="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a17="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a18="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a19="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a20="10fd874b68dad080ed706762c8e163dabb20514bddae38fb159c56f714a3b143"
    $a21="715dc8493c36579a5b116995100f635e3572fdf8703e708ef1a08d943b36774e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule blake2b_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1261c79e61aae75b7c20e76f0e04c29647a6effdc2d41a7a17582402fd6858060bf834cfa56771a1afa7b5da1ac3bf9eaae3d96fea8873b3eb17b48e9b733081"
    $a1="1bcfffa65462818f01cc1026e1fe370c4dded6aaf1c5a43dfee71005c90d942f95f9a8172d72fc7833fd6e5971325518f0904ffeb334f5219e9ea1b262d124d0"
    $a2="1bcfffa65462818f01cc1026e1fe370c4dded6aaf1c5a43dfee71005c90d942f95f9a8172d72fc7833fd6e5971325518f0904ffeb334f5219e9ea1b262d124d0"
    $a3="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a4="425c9b0a3c4272f4d9df0d0abbab3e1a178f3d21045c34053910511af2d0a42bf1cf4c8a628e8f5e95fdd4cfff75ecf2e72cd87904650952be87cd7094519d6b"
    $a5="425c9b0a3c4272f4d9df0d0abbab3e1a178f3d21045c34053910511af2d0a42bf1cf4c8a628e8f5e95fdd4cfff75ecf2e72cd87904650952be87cd7094519d6b"
    $a6="425c9b0a3c4272f4d9df0d0abbab3e1a178f3d21045c34053910511af2d0a42bf1cf4c8a628e8f5e95fdd4cfff75ecf2e72cd87904650952be87cd7094519d6b"
    $a7="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a8="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a9="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a10="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a11="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
    $a12="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a13="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a14="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a15="d4ee695d84d47ff4cbb16c47fa7364edd5b8c0acaf21ba78a32cfa403dbb6dfe597547cefc004638dd1f8a8e6cbfbe90f7f10afd6412e912077d370bb4a4c39d"
    $a16="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a17="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a18="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a19="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a20="214c0939a3c1d53d80461c608520dac05495180d6da60bbcbc27809b6ba9874271ac318934b8cd4650f9e0d9f9c47c018f12c081050334595e5f4870e1543176"
    $a21="dfa0fc6b62c5255b0612dcabb84e7ba987f7ed7d704ad64bd63cd955614a648bebe267e528e1523d9d860a5eb4e7cabe04b16fd7c1023960586211d3bdfcb228"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule blake2s_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="61b83c12ccabd0333a492ba2d826cbeae8d9b2febdc369da09614c29342a2bd1"
    $a1="95c4b7287769151aa0fab9550000b24a35c29a962b1b83796f6436320331552e"
    $a2="95c4b7287769151aa0fab9550000b24a35c29a962b1b83796f6436320331552e"
    $a3="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a4="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a5="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a6="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a7="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a8="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a9="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a10="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a11="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a12="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a13="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a14="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a15="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a16="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a17="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a18="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a19="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a20="fac3810507075ee8b15f29b738065feb912e349f9826411cb5507e00073c6cd6"
    $a21="934804255c453972da99bcdec2e4d99aad2c277bc7469bb335d4a835cd32e529"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_224_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5122338bd461aecad5e9cd8266c965d6068c3a17e6283d041e4d4627"
    $a1="0ead148441198813f78304269fe89dd5dbca5d603121029b54b118c0"
    $a2="0ead148441198813f78304269fe89dd5dbca5d603121029b54b118c0"
    $a3="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a4="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a5="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a6="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a7="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a8="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a9="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a10="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a11="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a12="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a13="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a14="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a15="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a16="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a17="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a18="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a19="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a20="061f8e291064d95e8c1dbd1a6f90bfd2ebf5a90150f9e36cd8529eb9"
    $a21="5f5c82ceba48805254828ca4c8e61e236fd9d04d948e5f05169d35a4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_256_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="789cf532419e99b67093f10b9059465900d073c466c25efd00771189d38f7e66"
    $a1="9691993c31365ae98b83d8273129aebd97d23140f0a028b24b057ee402596b8a"
    $a2="9691993c31365ae98b83d8273129aebd97d23140f0a028b24b057ee402596b8a"
    $a3="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a4="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a5="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a6="2c99ba746fe048c72ac15b2875c70554fc8373980f3ed859bdda41ea8daebeba"
    $a7="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a8="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a9="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a10="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a11="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a12="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a13="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a14="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a15="0bb9383cc5cc81ff3b80d1db0520af11fc6c03bedfac605c5c6a718097a9d3a4"
    $a16="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a17="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a18="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a19="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a20="91aa470491a98aca115499d2d65096e90c14e286414587df08ff7304851afb95"
    $a21="2032a7663effc6b47d3d2476625c0f085d89cdb9d1df44904fe558b65a703cb8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_384_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4e5a6f0fba604547745375eb56ccc6f7cecb54dfcbb0b3b65813667ed0ad417ab61e9be79f05ad44e85b29dde2b3fbe1"
    $a1="cb34fadf4c364254dfac2e0a24a93cd814c2032942ee4b75d7aa85cc4cee782ce7dea4f0732bcafe88f96588e174d6be"
    $a2="cb34fadf4c364254dfac2e0a24a93cd814c2032942ee4b75d7aa85cc4cee782ce7dea4f0732bcafe88f96588e174d6be"
    $a3="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a4="8cadab5ae059ddb24a20fbb97b212cbd04f553ce8a121b424ad443f965877c53847dbca33629fcb6b079b2fe8a02876a"
    $a5="8cadab5ae059ddb24a20fbb97b212cbd04f553ce8a121b424ad443f965877c53847dbca33629fcb6b079b2fe8a02876a"
    $a6="8cadab5ae059ddb24a20fbb97b212cbd04f553ce8a121b424ad443f965877c53847dbca33629fcb6b079b2fe8a02876a"
    $a7="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a8="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a9="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a10="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a11="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a12="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a13="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a14="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a15="9fde29cb657614f4dd02c1329dea73d4e409ce50a8275fd34c9fa00ab6a590211814bf8b5254581e99383bad238d4174"
    $a16="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a17="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a18="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a19="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a20="b500e159254cce19c7b53b0c83bd56be1e2c991f8f24590e4e84d81cc036c323d4e36e2f8ef335c167565b9ddd89b945"
    $a21="92f70453f8557e5a5b78148358f4f313a8ca005c910c5d47966413a6d7b9424fcd7b769ae05980ddb1e8fb09c5946a21"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule sha3_512_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1b553e6e2f919758eaceb4c940055d95507e3a6f2bc82252dac4ba0e72bfd3cb1faff77f8d2d727c309ecc92f3571f92dc5cd1c77ab1d62c91e3187da543026b"
    $a1="c6f52a0727c73e544bfc529d3f2bb864d8efe4aa532f96a6aea23236020b604187310dbe251293a91fd948a626be432081371fbe11c45fd6ce791b74cacfeb29"
    $a2="c6f52a0727c73e544bfc529d3f2bb864d8efe4aa532f96a6aea23236020b604187310dbe251293a91fd948a626be432081371fbe11c45fd6ce791b74cacfeb29"
    $a3="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a4="4ca3b7215d659c39d1c53722ca55e6ef297ea06e2ec4a66a6c5268a4951bc5129b4e0fa6f150ebe06d2dfa29d78c92dd855a274525386b0296caf6b952507870"
    $a5="4ca3b7215d659c39d1c53722ca55e6ef297ea06e2ec4a66a6c5268a4951bc5129b4e0fa6f150ebe06d2dfa29d78c92dd855a274525386b0296caf6b952507870"
    $a6="4ca3b7215d659c39d1c53722ca55e6ef297ea06e2ec4a66a6c5268a4951bc5129b4e0fa6f150ebe06d2dfa29d78c92dd855a274525386b0296caf6b952507870"
    $a7="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a8="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a9="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a10="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a11="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a12="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a13="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a14="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a15="23da8a9053fc47ed8afb004dd1559061050ddc8ddf1d38f0b02566b9a2f6962345e22bd807f576775b07cd8a63aafc583fe7747bd73f0633e7eb83791d3967e9"
    $a16="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a17="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a18="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a19="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a20="adb933810d393a945f733e97757f50d71cae5957d879ad8d2713a30991b79e2685edc1f826f65ac4d1e9d063ed8148767d564d4617e7d68dd06b9274de83e2a9"
    $a21="c10a176fd1741b90f0ffc3b57ca22bc2c96abce4623491897a40278ca9c9e1a47b13f443efa8deb64589a65342fbe37cae86eba972561b910a620555e721d03d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

rule base64_hashed_default_creds_osicom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for osicom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZGVidWc="
    $a1="ZC5lLmIudS5n"
    $a2="ZC5lLmIudS5n"
    $a3="VXNlcg=="
    $a4="ZWNobw=="
    $a5="ZWNobw=="
    $a6="ZWNobw=="
    $a7="VXNlcg=="
    $a8="Z3Vlc3Q="
    $a9="Z3Vlc3Q="
    $a10="Z3Vlc3Q="
    $a11="VXNlcg=="
    $a12="TWFuYWdlcg=="
    $a13="QWRtaW4="
    $a14="TWFuYWdlcg=="
    $a15="TWFuYWdlcg=="
    $a16="c3lzYWRt"
    $a17="QWRtaW4="
    $a18="c3lzYWRt"
    $a19="c3lzYWRt"
    $a20="d3JpdGU="
    $a21="cHJpdmF0ZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}

