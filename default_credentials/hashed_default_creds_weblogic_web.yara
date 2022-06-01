/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6bde2a01c490e177d6dcd15c149c129"
    $a1="e6bde2a01c490e177d6dcd15c149c129"
    $a2="08b5411f848a2581a41672a759c87380"
    $a3="5f4dcc3b5aa765d61d8327deb882cf99"
    $a4="4b583376b2767b923c3e1da60d10de59"
    $a5="5f4dcc3b5aa765d61d8327deb882cf99"
    $a6="4b583376b2767b923c3e1da60d10de59"
    $a7="4a96374e6cedd5ea88c3409a317a304e"
    $a8="cd0c6092d6a6874f379fe4827ed1db8b"
    $a9="cd0c6092d6a6874f379fe4827ed1db8b"
    $a10="54b53072540eeeb8f8e9343e71f28176"
    $a11="1d0258c2440a8d19e716292b231e3190"
    $a12="54b53072540eeeb8f8e9343e71f28176"
    $a13="d41e98d1eafa6d6011d3a70f1a5b92f0"
    $a14="54b53072540eeeb8f8e9343e71f28176"
    $a15="5f4dcc3b5aa765d61d8327deb882cf99"
    $a16="54b53072540eeeb8f8e9343e71f28176"
    $a17="44327681dd926addc2a74225226220f7"
    $a18="4a96374e6cedd5ea88c3409a317a304e"
    $a19="4a96374e6cedd5ea88c3409a317a304e"
    $a20="4bc3fb252edf8e4f12acf85c0af633cf"
    $a21="4bc3fb252edf8e4f12acf85c0af633cf"
    $a22="4a96374e6cedd5ea88c3409a317a304e"
    $a23="64c5b12b7729e5076eaa577436042951"
    $a24="4a96374e6cedd5ea88c3409a317a304e"
    $a25="44327681dd926addc2a74225226220f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha1_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9659699670b30983eb4e3c22454887e3c9c6ce39"
    $a1="9659699670b30983eb4e3c22454887e3c9c6ce39"
    $a2="9796809f7dae482d3123c16585f2b60f97407796"
    $a3="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a4="fe96dd39756ac41b74283a9292652d366d73931f"
    $a5="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a6="fe96dd39756ac41b74283a9292652d366d73931f"
    $a7="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a8="d1785ca28c3a4d29a6edef1520c544b838a93db3"
    $a9="d1785ca28c3a4d29a6edef1520c544b838a93db3"
    $a10="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a11="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a12="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a13="ebfc7910077770c8340f63cd2dca2ac1f120444f"
    $a14="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a15="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a16="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a17="31b01d405f74a13c94d97a9e0287a511451f4dc0"
    $a18="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a19="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a20="44a985b851c5ae75033309afb7522f84b8238d1b"
    $a21="44a985b851c5ae75033309afb7522f84b8238d1b"
    $a22="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a23="af8f60dd67906ac8287ba38343ee5f6b821ce6d9"
    $a24="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a25="31b01d405f74a13c94d97a9e0287a511451f4dc0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha384_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d0410983819f99f766e81404b059fb5e83b729d28223eb1d243b56a7e59324e2679c001e2498c5be99c89a0d299ba88f"
    $a1="d0410983819f99f766e81404b059fb5e83b729d28223eb1d243b56a7e59324e2679c001e2498c5be99c89a0d299ba88f"
    $a2="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a3="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a4="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a5="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a6="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
    $a7="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a8="cf99e42de5731c36d6f8fe1781df332e9f339f14973884f79556f91a79c4e9080b65a4497b23fb457775e68ecb55940c"
    $a9="cf99e42de5731c36d6f8fe1781df332e9f339f14973884f79556f91a79c4e9080b65a4497b23fb457775e68ecb55940c"
    $a10="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a11="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a12="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a13="053409a4197558e5f75ac94858361c8d82acf09d7a4189508ca8bd9bba57f824ca1d91187902b893e2c4b07dd85b969b"
    $a14="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a15="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a16="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a17="4033cac29dd3bf8cb93d89b9de51845be5f853c9b4e7ec05114d2468c90a08566ca76a858e0cbd238f27ea7452e6eb97"
    $a18="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a19="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a20="38c26cd614a0a5c87b0d50dd7b184f1bebbfd84d13b66aa510c21dbe9362d1d06e875a197635d329ef27315eb6cc199e"
    $a21="38c26cd614a0a5c87b0d50dd7b184f1bebbfd84d13b66aa510c21dbe9362d1d06e875a197635d329ef27315eb6cc199e"
    $a22="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a23="ea243a339b6f220ce825135fd933f318c220ab75da5663f8d5f595754124a0a97572dc0e194f634b34978dad6c283082"
    $a24="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a25="4033cac29dd3bf8cb93d89b9de51845be5f853c9b4e7ec05114d2468c90a08566ca76a858e0cbd238f27ea7452e6eb97"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha224_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd5afabd20815aa3fc49a278aef4f8c011766a118f14af3f673e006a"
    $a1="fd5afabd20815aa3fc49a278aef4f8c011766a118f14af3f673e006a"
    $a2="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a3="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a4="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a5="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a6="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a7="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a8="2929859b5d777b7acbc9deb2a63d9e7382b648bde3a0fbdc44418cac"
    $a9="2929859b5d777b7acbc9deb2a63d9e7382b648bde3a0fbdc44418cac"
    $a10="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a11="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a12="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a13="bb3dde385e8be09d6a46a981d471fe621ee35f79d5423e2faeaa9e3f"
    $a14="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a15="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a16="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a17="1f531a3e37a0d190ac7324954eb727d124704c614d61bf3538741231"
    $a18="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a19="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a20="9849d2513b1c579da45230d3fb8aa8a5a380412a27befb41b0024c58"
    $a21="9849d2513b1c579da45230d3fb8aa8a5a380412a27befb41b0024c58"
    $a22="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a23="58cda4a7095eca3d3ca4530bcc50071fe126f3942564f1538be4a687"
    $a24="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a25="1f531a3e37a0d190ac7324954eb727d124704c614d61bf3538741231"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha512_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="23f2413a5829cb15581e6e15b41839b9e185d126005519a1d028486aae9bb3d85eeb5ec756c6712a3d2496c9536b1cd6b6f740d5f8ebaf768b7cd5c7905e8872"
    $a1="23f2413a5829cb15581e6e15b41839b9e185d126005519a1d028486aae9bb3d85eeb5ec756c6712a3d2496c9536b1cd6b6f740d5f8ebaf768b7cd5c7905e8872"
    $a2="d1a29ffc0c004008f8a6b5baf04a220e902876bf03758bde949c995c8c7fe9bf1db7c4e9d30d42761675d6815022138eccef2a54fc24d586aaa00939f261cc2e"
    $a3="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a4="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a5="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a6="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a7="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a8="32b3f54502ee37ab378d8c3d6ce3f3789776f81c6bb7618775d279e40b5e78970115695afed4d0f058e66593bde953aedfb2d0f124381806ae4c1f41fb928f03"
    $a9="32b3f54502ee37ab378d8c3d6ce3f3789776f81c6bb7618775d279e40b5e78970115695afed4d0f058e66593bde953aedfb2d0f124381806ae4c1f41fb928f03"
    $a10="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a11="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a12="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a13="fe0d8456dd3f1a0f68cde11860c34bddce97dcbc20f389f534af8c4c49e225f6307ca16e414ac04c8d67b80821690edceb86f8de0d5286dd37ee562e3dcf2e80"
    $a14="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a15="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a16="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a17="0ae301bf82f7e773787d81996e514c655e8663f36bf3bb764d2ffbaae74f00a6143672409fa9cce1d8ae34b9c72bc45c3bb48966d6d366196bd98540cd045553"
    $a18="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a19="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a20="bd4c76607945204b94711d3685a8ab0916a2a38df508283fb11c18f1ae7a00081a41ecc736d24b3953a4e96a24abf3e6ffd62e627a07e5a5e76b7062a1f8dfdd"
    $a21="bd4c76607945204b94711d3685a8ab0916a2a38df508283fb11c18f1ae7a00081a41ecc736d24b3953a4e96a24abf3e6ffd62e627a07e5a5e76b7062a1f8dfdd"
    $a22="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a23="a58a7a6f363e5056cfee6391644c30c354c739178cc9dab619ac10e06346a6f897da8b709444c99fff70e41d688074428de32df13c5dee8fb8bc49889c852a49"
    $a24="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a25="0ae301bf82f7e773787d81996e514c655e8663f36bf3bb764d2ffbaae74f00a6143672409fa9cce1d8ae34b9c72bc45c3bb48966d6d366196bd98540cd045553"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha256_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="04a81e6b4883fbf2553a5e9baf9a84b4502b1c1f67eedc4fb20e8f2458b663d4"
    $a1="04a81e6b4883fbf2553a5e9baf9a84b4502b1c1f67eedc4fb20e8f2458b663d4"
    $a2="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a3="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a4="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a5="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a6="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a7="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a8="d9262e7fb868c502061473089e5212378ac3935e2f96294266da6d7eec7d44e0"
    $a9="d9262e7fb868c502061473089e5212378ac3935e2f96294266da6d7eec7d44e0"
    $a10="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a11="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a12="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a13="ab38eadaeb746599f2c1ee90f8267f31f467347462764a24d71ac1843ee77fe3"
    $a14="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a15="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a16="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a17="18fa5faf897b9b8c3375efb6fdb3ebcf56ba4442812c3df59fe791d8f6a897ef"
    $a18="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a19="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a20="5a3bc29fe6c9cf21f71bc92ac2f00d3be32ef02d98fb831050866ef6031cc77c"
    $a21="5a3bc29fe6c9cf21f71bc92ac2f00d3be32ef02d98fb831050866ef6031cc77c"
    $a22="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a23="8298b9ec0d12459098a93234d4ff75a83e054f7254901a64939f9a4447793a07"
    $a24="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a25="18fa5faf897b9b8c3375efb6fdb3ebcf56ba4442812c3df59fe791d8f6a897ef"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2b_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2889c7167c7ebae0ba079c4c1303ec9fbdf64b60ef8afafab1e422208b267465ab774569c5cfcab045d4298bf588d1c725a7ae1aa6616c3d9553a2cc4af96b78"
    $a1="2889c7167c7ebae0ba079c4c1303ec9fbdf64b60ef8afafab1e422208b267465ab774569c5cfcab045d4298bf588d1c725a7ae1aa6616c3d9553a2cc4af96b78"
    $a2="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a3="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a4="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a5="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a6="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a7="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a8="a3c50b5b0f4c5dbc0ff036e11d98da98f66e962ef62594a0984c53bad9c1b0ed86f0a0b30468c588759bf55ec947f039d501e35dee6dc7c2c7a3f4b47168c485"
    $a9="a3c50b5b0f4c5dbc0ff036e11d98da98f66e962ef62594a0984c53bad9c1b0ed86f0a0b30468c588759bf55ec947f039d501e35dee6dc7c2c7a3f4b47168c485"
    $a10="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a11="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a12="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a13="b4b2a7043856b7ceed2dca20a921310884c741ab4e478b53d85bec56ef0aa2af64b499a57665e4bc8199700d1665c48827d222f33fb61346c8692f75965c75a1"
    $a14="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a15="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a16="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a17="7fe0ec76e3e052715dc27c854b2278a38b73ca9aebe40fd38c0598a7d928b0425e8ff33b4226726286c57fa26c07c136bc244e5a411c975a8b34f2de8d56e283"
    $a18="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a19="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a20="a3efffd6133134aceb93151ad44ed9890ab366807f7a6e0ae977fd19770ed9f7be25b6833b200baa78d9c6ce2667211ae015f0f2087a3a3c423709ff167e55dd"
    $a21="a3efffd6133134aceb93151ad44ed9890ab366807f7a6e0ae977fd19770ed9f7be25b6833b200baa78d9c6ce2667211ae015f0f2087a3a3c423709ff167e55dd"
    $a22="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a23="65a32d7ea5c8bfa35990336130d1e0ceba7d88000a55d0cb6a607d8ec5a3ac7b3c7f448ba50253aab42ec32533dcde9d67cbef238ca0e4d0c3540db70be514e4"
    $a24="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a25="7fe0ec76e3e052715dc27c854b2278a38b73ca9aebe40fd38c0598a7d928b0425e8ff33b4226726286c57fa26c07c136bc244e5a411c975a8b34f2de8d56e283"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2s_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9b48bb4dfc4882ff7b733062973eb14d8d78c74a3aefd73864be13724d75f662"
    $a1="9b48bb4dfc4882ff7b733062973eb14d8d78c74a3aefd73864be13724d75f662"
    $a2="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a3="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a4="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a5="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a6="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a7="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a8="d8a1bcdcb4d9622c81582515341ca59311cca927000b61143955aff84c064f95"
    $a9="d8a1bcdcb4d9622c81582515341ca59311cca927000b61143955aff84c064f95"
    $a10="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a11="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a12="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a13="2b3e97675aeca50cd4e00252abc5d8cb734540cd86db41fd5ff99d2e37275575"
    $a14="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a15="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a16="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a17="d232ec25aa77ee8c561090fd6bf285d543aea9545c71753ed972201271fc9cdd"
    $a18="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a19="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a20="b2dcc1b51d415a097d7c2e5432cb95775b25c67e7e1791cebe6b5a974b9c3c7b"
    $a21="b2dcc1b51d415a097d7c2e5432cb95775b25c67e7e1791cebe6b5a974b9c3c7b"
    $a22="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a23="8fdca6949ee5b2063746581b0d8ca89926e163660fc99afbb731c6d683f1097b"
    $a24="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a25="d232ec25aa77ee8c561090fd6bf285d543aea9545c71753ed972201271fc9cdd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_224_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e09698e1aedfb454e0009610f341a60d3e09e679ad39adf9aa279c9"
    $a1="2e09698e1aedfb454e0009610f341a60d3e09e679ad39adf9aa279c9"
    $a2="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a3="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a4="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a5="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a6="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a7="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a8="92198a905f60a0f01036be1fe87616773251701ad160d0d397b5c813"
    $a9="92198a905f60a0f01036be1fe87616773251701ad160d0d397b5c813"
    $a10="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a11="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a12="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a13="7407d101c6ec8cab3ece152481870447479a1d165f3ff0ee42872050"
    $a14="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a15="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a16="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a17="eb2eaaf9ee70988807168afebf88c1448c2a51859ddf7d1747c08df4"
    $a18="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a19="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a20="26d99ddc43ca52688cbf0ec95bad21a6d0f44a9e6e3f633d64955e42"
    $a21="26d99ddc43ca52688cbf0ec95bad21a6d0f44a9e6e3f633d64955e42"
    $a22="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a23="5afecfeac04ee939ab7df76c8619bb20d8400280820a6a8d71189f94"
    $a24="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a25="eb2eaaf9ee70988807168afebf88c1448c2a51859ddf7d1747c08df4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_256_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bde90c25ad6d01ace5ae0cfc9d17437bb7741f698a922de35f8e624b1af93a00"
    $a1="bde90c25ad6d01ace5ae0cfc9d17437bb7741f698a922de35f8e624b1af93a00"
    $a2="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a3="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a4="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a5="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a6="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a7="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a8="720a899ab40d960db60a5381aa73c573b166b68c3c88e861e5310b102b55b13c"
    $a9="720a899ab40d960db60a5381aa73c573b166b68c3c88e861e5310b102b55b13c"
    $a10="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a11="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a12="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a13="abdbd5fe0eafa959a296ffa0b3dd55c7413a4f1917b5fe5599eeb0c361501b56"
    $a14="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a15="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a16="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a17="ee2ba9a8201ef4ce1c2f294358095cf2723b561e45bcc8730fadadee6d6a8164"
    $a18="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a19="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a20="10821183917e589e180bfce385e7e0e661929c4069c4057c0f463e73d0d478c2"
    $a21="10821183917e589e180bfce385e7e0e661929c4069c4057c0f463e73d0d478c2"
    $a22="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a23="3b14cc7ebef3e3ce26ddf7a2add934339ebde92b7bad2883541d2d46c4467df9"
    $a24="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a25="ee2ba9a8201ef4ce1c2f294358095cf2723b561e45bcc8730fadadee6d6a8164"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_384_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="75f1ac7f6003f9689bd9b13f1e6900c7add21062aacf75c40efa086794fcb83dcd1aca386812847b2a060be12f099a0b"
    $a1="75f1ac7f6003f9689bd9b13f1e6900c7add21062aacf75c40efa086794fcb83dcd1aca386812847b2a060be12f099a0b"
    $a2="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
    $a3="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a4="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a5="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a6="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a7="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a8="38a562575767b8c9b5adb319c98cd0c7de24caf181970820ce940b22d5fff0f5e686ab142c326eb14dabfca9c1b4dbdf"
    $a9="38a562575767b8c9b5adb319c98cd0c7de24caf181970820ce940b22d5fff0f5e686ab142c326eb14dabfca9c1b4dbdf"
    $a10="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a11="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a12="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a13="3bfd8dba3ba5129c6b372ed2defd56522faf6d0b31fc820b7f8e4a43de90bb70356d08c71bca39652e7e4996b12ca8f1"
    $a14="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a15="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a16="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a17="f8d9fae2d0189ec3a27cc1d877250e9ecefdc33515d6556d823fc23ca86f06a584d6a022d595fbe8ff4337fe26444911"
    $a18="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a19="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a20="49c6ff165cc2d1abde96764f48a549ec7c53ac7a6cc32a3a6b1b9b43a80b9b3fc06db1f1a3d8d5cbb432c25fef1e3bb1"
    $a21="49c6ff165cc2d1abde96764f48a549ec7c53ac7a6cc32a3a6b1b9b43a80b9b3fc06db1f1a3d8d5cbb432c25fef1e3bb1"
    $a22="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a23="83e85683667d6d4d7be3ff6d77c87f71633220087be311d14fd3f01771ecfc2e16a0dbddff65c5b18984572fe2c50986"
    $a24="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a25="f8d9fae2d0189ec3a27cc1d877250e9ecefdc33515d6556d823fc23ca86f06a584d6a022d595fbe8ff4337fe26444911"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_512_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0d61e321538923a7622067b4470acb370bd374ee5ac2f32ce5a73ae2eb5db9bbef715b049b014aec132384c130107a17cf3a63541ff24470a4c5a5ab02ad6175"
    $a1="0d61e321538923a7622067b4470acb370bd374ee5ac2f32ce5a73ae2eb5db9bbef715b049b014aec132384c130107a17cf3a63541ff24470a4c5a5ab02ad6175"
    $a2="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a3="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a4="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a5="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a6="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a7="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a8="d3f7a04c3f7043140929fb1050af28da1acd0c9b4523a11bd3a8cf0244bffe9488ff26a68f37e645a3eaf66e9a922f6c5689b529a4ce6da4e061a1f08e0a9c3b"
    $a9="d3f7a04c3f7043140929fb1050af28da1acd0c9b4523a11bd3a8cf0244bffe9488ff26a68f37e645a3eaf66e9a922f6c5689b529a4ce6da4e061a1f08e0a9c3b"
    $a10="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a11="c36924f3ed986794b7430c969970a95cba7d0e3ec907acaa72377ee8df60c6ba9e4a649dd699f89ebb8258216d52a02fb21f84ef0f8c690bdc8c886d1ad4ecaa"
    $a12="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a13="4bdc214c7bba4a88527d78c8086746d18e8639d8f5b7a9f1ec105a3d002a3002fc05d98967fc68d0edaab6cec7fe46775ef8ba79db251bbfcacc098dad6ce083"
    $a14="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a15="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a16="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a17="77f3573a5c010cf75c8eb02ace460e9266405f004dc49284897c1f93f5c05d7e60766ffc7395a9d30cf8db0c0bada3e0630812f3b861d71ad5164765a3a624e8"
    $a18="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a19="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a20="f756bb97863eb87e507b3f1f8ae294a9292838336655e46e707933e9f2765b81f71210742a8ccf1b488e59b2318c2fbb7852838f9556d77cfbefdb27212fc3c9"
    $a21="f756bb97863eb87e507b3f1f8ae294a9292838336655e46e707933e9f2765b81f71210742a8ccf1b488e59b2318c2fbb7852838f9556d77cfbefdb27212fc3c9"
    $a22="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a23="19035e2133e25d778cd336705bed4b3d2c478cf3903eca74799bf2d4b8be023d4b78692a20f7b5deda7bc7a59c93931e8efb9da26e9582bdbe6ca2204b14a94b"
    $a24="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a25="77f3573a5c010cf75c8eb02ace460e9266405f004dc49284897c1f93f5c05d7e60766ffc7395a9d30cf8db0c0bada3e0630812f3b861d71ad5164765a3a624e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule base64_hashed_default_creds_weblogic_web
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for weblogic_web. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="RVhBTVBMRVM="
    $a1="RVhBTVBMRVM="
    $a2="bW9uaXRvcg=="
    $a3="cGFzc3dvcmQ="
    $a4="b3BlcmF0b3I="
    $a5="cGFzc3dvcmQ="
    $a6="b3BlcmF0b3I="
    $a7="d2VibG9naWM="
    $a8="UFVCTElD"
    $a9="UFVCTElD"
    $a10="c3lzdGVt"
    $a11="bWFuYWdlcg=="
    $a12="c3lzdGVt"
    $a13="UGFzc3cwcmQ="
    $a14="c3lzdGVt"
    $a15="cGFzc3dvcmQ="
    $a16="c3lzdGVt"
    $a17="d2VsY29tZSgxKQ=="
    $a18="d2VibG9naWM="
    $a19="d2VibG9naWM="
    $a20="V0VCTE9HSUM="
    $a21="V0VCTE9HSUM="
    $a22="d2VibG9naWM="
    $a23="d2VibG9naWMx"
    $a24="d2VibG9naWM="
    $a25="d2VsY29tZSgxKQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

