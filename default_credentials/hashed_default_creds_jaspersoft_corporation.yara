/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe01ce2a7fbac8fafaed7c982a04e229"
    $a1="fe01ce2a7fbac8fafaed7c982a04e229"
    $a2="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a3="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a4="a33df7161cb7977492b0f07abb665627"
    $a5="a33df7161cb7977492b0f07abb665627"
    $a6="0baea2f0ae20150db78f58cddac442a9"
    $a7="0baea2f0ae20150db78f58cddac442a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a1="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a2="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a3="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a4="bada309e51e6ea60a1dd20fc3b9173a197ed06f5"
    $a5="bada309e51e6ea60a1dd20fc3b9173a197ed06f5"
    $a6="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
    $a7="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a1="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a2="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a3="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a4="2e157da6de9055f70e39d07ce58370c8d355b304a159bee4d5858fed189706a4f7a1adfe272bab9324948123aaff3155"
    $a5="2e157da6de9055f70e39d07ce58370c8d355b304a159bee4d5858fed189706a4f7a1adfe272bab9324948123aaff3155"
    $a6="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
    $a7="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a1="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a2="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a3="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a4="8ad7062b79554042a6442a3733d44b459974fe59e8dd1e4a13fee0bc"
    $a5="8ad7062b79554042a6442a3733d44b459974fe59e8dd1e4a13fee0bc"
    $a6="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
    $a7="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"
    $a1="26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"
    $a2="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a3="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a4="0ae25a277f843f7494ad3600543fa0f8d81e935a9ccd6aaedef991fb2ab61e9f9f6ac02fe646faa3463d656cd57a6c161443238a1ed83501755af29e3d20e1c7"
    $a5="0ae25a277f843f7494ad3600543fa0f8d81e935a9ccd6aaedef991fb2ab61e9f9f6ac02fe646faa3463d656cd57a6c161443238a1ed83501755af29e3d20e1c7"
    $a6="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
    $a7="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
    $a1="2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
    $a2="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a3="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a4="5072cd21aff496b31d0ee9a4ddd4533775c24391d4fbb7e30b1bfd837c52b062"
    $a5="5072cd21aff496b31d0ee9a4ddd4533775c24391d4fbb7e30b1bfd837c52b062"
    $a6="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
    $a7="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a1="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a2="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a3="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a4="aa1c04caaaae639bd37d767ac9022fe6ef7f56c271a4a01996a28aadd4c952d067516f82857bef9574ca77c6818ef4a42cdb6d43ac79fe3b1992864de132ce60"
    $a5="aa1c04caaaae639bd37d767ac9022fe6ef7f56c271a4a01996a28aadd4c952d067516f82857bef9574ca77c6818ef4a42cdb6d43ac79fe3b1992864de132ce60"
    $a6="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
    $a7="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a1="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a2="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a3="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a4="6223e24f2373486564e57a7c9124f5b5fba0e00bf8e54cd5830ffe10ec7b3fd7"
    $a5="6223e24f2373486564e57a7c9124f5b5fba0e00bf8e54cd5830ffe10ec7b3fd7"
    $a6="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
    $a7="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a1="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a2="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a3="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a4="e000396654a89fa993f47db2cabde37b5583705c99f6c953396af3b3"
    $a5="e000396654a89fa993f47db2cabde37b5583705c99f6c953396af3b3"
    $a6="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
    $a7="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a1="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a2="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a3="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a4="ca2f07eb65e6cef9c0208c127fcbaa96a183c40904b96d2a4ed3be1ab5747e7e"
    $a5="ca2f07eb65e6cef9c0208c127fcbaa96a183c40904b96d2a4ed3be1ab5747e7e"
    $a6="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
    $a7="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a1="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a2="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a3="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a4="fb3e508804e79703e22505e60e22e2f73518aa7efac78c5cca205d3dfb17dde87b4495e2368320a1b81676d4ea3cbdec"
    $a5="fb3e508804e79703e22505e60e22e2f73518aa7efac78c5cca205d3dfb17dde87b4495e2368320a1b81676d4ea3cbdec"
    $a6="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
    $a7="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a1="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a2="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a3="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a4="370f0db03538cdfb4f230f1338131ef212179b7473e4ba53860487c0f2a8e470a95bd1bab15aac2f4f3d9e70263b79d353aec6840fbd5b93c248983d856ca7b2"
    $a5="370f0db03538cdfb4f230f1338131ef212179b7473e4ba53860487c0f2a8e470a95bd1bab15aac2f4f3d9e70263b79d353aec6840fbd5b93c248983d856ca7b2"
    $a6="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
    $a7="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_jaspersoft_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for jaspersoft_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZGVtbw=="
    $a1="ZGVtbw=="
    $a2="amFzcGVyYWRtaW4="
    $a3="amFzcGVyYWRtaW4="
    $a4="am9ldXNlcg=="
    $a5="am9ldXNlcg=="
    $a6="c3VwZXJ1c2Vy"
    $a7="c3VwZXJ1c2Vy"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

