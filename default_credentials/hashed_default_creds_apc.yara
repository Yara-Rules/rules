/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3613d6751fc1b29e6439a6d15f13be7"
    $a1="6980590f2b65cc6c486adcf1726ee55c"
    $a2="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a3="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="f3fda86e428ccda3e33d207217665201"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="421f0fa12d0b8dc22dc39382077c13b6"
    $a8="d41d8cd98f00b204e9800998ecf8427e"
    $a9="85b701cfaaec180f955a3f9854cff9f6"
    $a10="d41d8cd98f00b204e9800998ecf8427e"
    $a11="6980590f2b65cc6c486adcf1726ee55c"
    $a12="913f9c49dcb544e2087cee284f4a00b7"
    $a13="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a14="913f9c49dcb544e2087cee284f4a00b7"
    $a15="913f9c49dcb544e2087cee284f4a00b7"
    $a16="55d598b417478d9e36928935437eafe7"
    $a17="0e68f753bc601f5d9d04717f95042762"
    $a18="336ebbb2179beaa7340a4f1620f3af40"
    $a19="cbdeaeb2cf5b812c628b2325bcc4c560"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha1_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="195d97a45d6eba2db274c7767aa4a3b0792a1ee9"
    $a1="2f0af123dd51e57e2be0615b16d5906a1887e780"
    $a2="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a3="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="21bf21f8a9aedc6a395dd0720a1e11ec2220804c"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="77717404332faea66ed79350132725e580c2e129"
    $a8="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a9="41e5782dfba5c4c8bcc261b89d6b3623a5bb59a9"
    $a10="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a11="2f0af123dd51e57e2be0615b16d5906a1887e780"
    $a12="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a13="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a14="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a15="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a16="bba2617056f3ad9b1aaebd2df10c0e69cf4f647d"
    $a17="1bfe152b965a4a3bcc493fe26b46fdf00509fa83"
    $a18="9a27718297218c3757c365d357d13f49d0fa3065"
    $a19="59b7bc438df4f2c39736f84add54036f2083ef60"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha384_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="443c56c1a9182dfc6664f0b0941cfee8779a986f6642f89f012f3a75b67b2a15eaa2466d96ac4f8ab4a982c8f9fc6911"
    $a1="5e8cc6f66e23ed722e48384a55fbae2df307f76c15d62016a31b97f293888a800eab3ca43052a84874a7428eae864067"
    $a2="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a3="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="8cdf10d044a1ef84c0ba374ab25d025f19a3a33506a06bd3e10c3072cc051e590af4a3c33a493ffa5e6afa4326595a19"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="b15327ab6db700468c381a3475a052aeb228ab7ff8d5c7cd08c1395fb4cf9eb8ce60f4cc55e87bd36ef2eb79ec5d2ff2"
    $a8="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a9="6a884dad2618ac880c4cc67627bc417b825cb22896ec3f7b1a0a0c1b8f806ed206986931cad3db8162257d1a12c9fc33"
    $a10="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a11="5e8cc6f66e23ed722e48384a55fbae2df307f76c15d62016a31b97f293888a800eab3ca43052a84874a7428eae864067"
    $a12="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a13="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a14="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a15="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a16="34936fbd99a6d707fffa289bf9c174a110ccc5c5ee3ecfbf2fdbc8467bbd2d89c9e08d5fea4cb31f55d1779b1ebeb46c"
    $a17="07da3c989714339f2dfdc9d8dea56cf410755bd8da3b5c48bf4530dd3228bd4025b4ecc43149915c222c94bdbbb99a34"
    $a18="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
    $a19="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha224_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1ddca6135999cb500f8beb89b9da31ca8d29f0bfd661e435ad03865e"
    $a1="22d863408b90f63285689a71549ceafd4512a7f29b17c52d99a62417"
    $a2="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a3="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="19f0039494f5f02f3f1af1a2ed491c334bc94f0e5ae4854b0ad8d02b"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="189dcb3e651cbabaad196c784635c48cb05eb80bcf8593e798bc8f49"
    $a8="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a9="cfd2cde5bab14aa50c60ff7fd93e2fca73be029d9cde9a89f10b239c"
    $a10="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a11="22d863408b90f63285689a71549ceafd4512a7f29b17c52d99a62417"
    $a12="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a13="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a14="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a15="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a16="92ed51bbe9c7cdf1c50d112af91a0462a4888fedf81965c66c55fe59"
    $a17="58714c17b0ab4e300bac7f3dae1b844e421b0832a84e0efc4cc0f9bd"
    $a18="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a19="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha512_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="65376f76f928cd5e65023e2dd0741937b10295c36cd98d61a55738b7940f9e406c48b838b93d42be3d160c36d86a785d81f2f5192b7e932089a70f3522cd55b7"
    $a1="d5d6f7a599de2612710b81c7455352ac446cffb34cf72f61f4c38368017a6f2a2caa780f66a6c0b5e2b5f970ab761cc8fe596437c1edc4afadfcba967d34ca5d"
    $a2="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a3="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="3cfccc03e3fb335c5b27592a55c0e6e96e50a65f03b823597a27a812681a1e0f2e0189ed3c225ddcb59a09d7caa43f46c1b510b8ab11ccde38adc650461fe04d"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="13e6904531b6452431fa8f49172144d9445bf406213e0f9b0f02c92bc5be9919c3fa9df58df98a9d56d6b4085aedfbc57a1ed9e269b18a5eee5aa3b0076b8ccd"
    $a8="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a9="7ac024f3a9a4618ca1dc258445dcb406789f1a9f90ce78d2205704404ef2178631e55ef7c32ef7da62ff2c39c0d9897eae3cbd248a813cf460641e5096e166b1"
    $a10="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a11="d5d6f7a599de2612710b81c7455352ac446cffb34cf72f61f4c38368017a6f2a2caa780f66a6c0b5e2b5f970ab761cc8fe596437c1edc4afadfcba967d34ca5d"
    $a12="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a13="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a14="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a15="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a16="bcda783cb1abf9cef08145640871afd7bf05c18ccfb6e45ea4d4c46f95b0a1e10fd87b6f4862b5d435269100d63902e000e9d8c3baa06396152516495fbf1eec"
    $a17="ff9ee9f31ca1dc3b54fa2169102ea5f1e908e5504af2058376726f6c1508f039ce559aba30ae0e7b55856cf79a603369d5713fd504d63b1a5950cfdc46a0cae7"
    $a18="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
    $a19="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha256_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3bbbbb1d2f9ca448af1fbb6c1c460970f8c1577b9f7ee65198036f56f96315b0"
    $a1="85b3a8d13d6ae604711706ec00795d82cbaadb400728afb4e09cf29dd2e747ee"
    $a2="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a3="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="32783cef30bc23d9549623aa48aa8556346d78bd3ca604f277d63d6e573e8ce0"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="46c848628f162a8c1b27193d549dac1bead6961dcdcfc773f85be0a71283f885"
    $a8="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a9="91414729425b34a3baaebeab52f06462962bd6070d6b450f2da894b52f392914"
    $a10="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a11="85b3a8d13d6ae604711706ec00795d82cbaadb400728afb4e09cf29dd2e747ee"
    $a12="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a13="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a14="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a15="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a16="9bea1a11c11649bc93ab31823bad0af7a83d70e7530c9b381056ed1deedc9220"
    $a17="a43915481c3b48d871d73fb0396701d3626c2cc5e5d1a95ec17e067cc8d3d7fe"
    $a18="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
    $a19="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule blake2b_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37e5b3a688ad0d302e5a2f149c56cb5258f8c100f4e59dec8c4305c3912dcad8b7860b32fa62bd99ce616a5fdf07c35b5a6667525e12477db1c039fb30279f1d"
    $a1="f4eb485c2efadfd503760d9d4a4a52f0eece4c3263d876300435cfbd05f40f276de9534158e9c15a887111d04f8c3037b3ffc20ef4d52a9e5f9a3ac848deae41"
    $a2="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a3="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="4f0a03ad86083bf95110ebcae7a41d9a596eb8511fec5186ce6cc4b71bd0c390b7256a40df066aba33440b1994d82e6f776bed147520ca3df912dcd7a280ffe3"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="ebb3cd9fb7fd2e6f82dab19f26d67fcae4a8131793bf20dc98dfeef030936722e51ab58cf7a4f7ff31cefdcf445cce2c887fe7a433473a69e90faa2f7d7614ab"
    $a8="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a9="73c6da74e07796417c53548c139d4ad5b6602f4e02008357a3a7510012214c2dfa0caf4f7928d71f8cd0b659e45595fc20752ffe919be88fd7823370de1ec7e2"
    $a10="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a11="f4eb485c2efadfd503760d9d4a4a52f0eece4c3263d876300435cfbd05f40f276de9534158e9c15a887111d04f8c3037b3ffc20ef4d52a9e5f9a3ac848deae41"
    $a12="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a13="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a14="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a15="2efa3755160d85e0ddc6a827f9a458a19829a83d286f0b6a46960491558320e74a3dc092986ead0b95e0ade7e368e363056a1396fdba590669fc1e631edf11ea"
    $a16="e1bf07905158276eda8f77e8fd984ad8085ce88c7f8eafcd8c64e56b74c39a4ffc5fd5752f482fa10aae16aba6e738627f0f430972e8a553005d3794ed9849d7"
    $a17="c57c6a00e3c2a33201d554ead54abae28ed7861dee647d854833e48fc97ff6654eef506087bcaa8f016030eea157411cbaa85d5d9afb43a05ac579a6b57ca567"
    $a18="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a19="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule blake2s_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="18a3d51698a9b02fa42d74cdfdf45537e57f2b175ed42c5aa5a63cc3b525ad98"
    $a1="b5a433504d5e0ab1c033a7ee95cf182462f7ae8cd01adb798543a0ed3a95f5f8"
    $a2="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a3="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="6c5713aab6f7b820cafdc95cb98330f6ea435120f92f7265c9b1ac7ab737a453"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="b51513245cfc3a40228dd161b48edc9ba231b3221229688381f5106dde638822"
    $a8="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a9="192169e3c893b20c9f2b325b2d27b414943cd44108f1bc73b2ee52ef053ae479"
    $a10="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a11="b5a433504d5e0ab1c033a7ee95cf182462f7ae8cd01adb798543a0ed3a95f5f8"
    $a12="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a13="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a14="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a15="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
    $a16="f2aa0be7eb0021b60c988c9cbdc393b122c02c549f19e49b251ad399e9e1f847"
    $a17="edd87c2a7ebc1d47fc691da77f68d600f0c87fd34f6ff49eca4fa61e2d1536bb"
    $a18="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
    $a19="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_224_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="61eb3c0842b515bc18d0e24e058a55eb9cc1ecc53be826a23e8baa06"
    $a1="519d6c1a4037668be0d03d080bb48196240414c5f488c3ff81a2fcea"
    $a2="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a3="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="a3a8a1abcb22c388b53e6f469fb0e128e55ab4fc0a8e4d2dd25dd8d7"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="82578fabe2aec21174d576287556643a3636729fa1e2c83be29149e5"
    $a8="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a9="f2ccb82231b45848162547419d5561dc35ba5ece623b5ecd9bc78fd2"
    $a10="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a11="519d6c1a4037668be0d03d080bb48196240414c5f488c3ff81a2fcea"
    $a12="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a13="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a14="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a15="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a16="f22db770eeb09733518c60b5db362616dd1f53d547a444db01b25d72"
    $a17="cee18a4cb12aebdb494bc2162bd4de85ee82649bc6b30953e6caa5e0"
    $a18="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a19="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_256_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d090dda4601ba970da1a5b37a322f16dc43eef5a5d63791141784ed4ee88a432"
    $a1="77a34142c3d4e2aa2f098b5c265d5649b1dde40623b4f29af6b1f7a710facf8c"
    $a2="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a3="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="e85503462d0ce6a6bb0db078cc797973d95b4a97232129cf2443a6d5ea9326df"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="8966141953b9c8b635f220590db40cf5ad69859d8cfd9c1b622dd95791119bfb"
    $a8="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a9="636cc447f4357def492cb35a924a8bf0c3e1f5e623d803063925629961eab20d"
    $a10="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a11="77a34142c3d4e2aa2f098b5c265d5649b1dde40623b4f29af6b1f7a710facf8c"
    $a12="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a13="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a14="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a15="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a16="551383ddb06f444e1e78d37df3a163b97335e5b07e15c837f049e70b90f45d94"
    $a17="2dad92536da841885bdfbaa56762c8bce1f627a450527683a2638b68d313cfe5"
    $a18="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
    $a19="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_384_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="263400433368cd8ef015ef4a983c61aeac09227d41cad5e58fc1c12c9c98db652f5f0c53831f3eb772b11dc41055136d"
    $a1="cbc18d899ed70d3fba2efc54141318254e07ce2627e69cfd7ee540f2853c4751a7274181c8f1ea51d2ca66e2dce4b24c"
    $a2="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a3="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="4c77e3d58d4641172334aefdee13af25979d33b2a6c396692b24a9958bd0ae5c02067fbf5b1d350ce32f4e0ee8b981b1"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="ce7fea31c5c90dc692dcd0ea7a98ed2d5caf1286624b934bdce380f7f88fb021724755ef08ace0778eaf91bb31d65319"
    $a8="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a9="8785aedfc1fac1a278dc3167feaba2725286a15ed1820d13de44df1461169417f033c65f7a7e933f804c3cfa991cc291"
    $a10="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a11="cbc18d899ed70d3fba2efc54141318254e07ce2627e69cfd7ee540f2853c4751a7274181c8f1ea51d2ca66e2dce4b24c"
    $a12="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a13="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
    $a14="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a15="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
    $a16="a910850260eb99156533f51f1946dbfd14082558b3d453158371b7088c90d3869b3d38b387a132dcbcafd5de7e9fb76e"
    $a17="97b22d309a6e74198abf64a5a02082cb4ff0019635e26b93241a86d7cd14b9ba31eea4d4deae6658d5730240fe4298d9"
    $a18="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a19="1fc25e944699ba9eec92ef00759ecc470e9800c0dafdedb7b5b9fcdeb6a2c53962d846fc883bfae1d878ff0402163cc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule sha3_512_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd2dc9fef12631cb76b2d40b1153b5ddcf3a99629fa89a5186658ce3177fda2b4b23711f24bce3847c6c06fd4752a2130a1c4d43bf301ed8f423063ffc2c4035"
    $a1="1ef14442170cf0c35281901f7daeb36be102083d22c8126722c311a6fab5a3817c6705cce38e2603eca0c4da6c3eed320536c7277e17577c83b3e143c03dec14"
    $a2="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a3="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="aab0465e10e1c2ef78058c48b6cc0d73ed24fdb0c9d107ddf4d23702a98b65742f5c7f8ad58b9065f634d4fa578e82b5d734b37efee6f995c95c508831997e0d"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="c49b566375c77d6c623f31f658e69921c74865e17b8c0f36749a5f6509413174bf6f4aab87c831ca54beede2ca3d62046cb08845437f318fd4f9a4018d7deb62"
    $a8="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a9="2c1c5c8795ddfd7bf97b0875056998de4755b85fa3e1732cb540ad970957f586d774dde1782f8d0fc491edf3cf9bb595a90aee54acf91ac658e62c01d679b496"
    $a10="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a11="1ef14442170cf0c35281901f7daeb36be102083d22c8126722c311a6fab5a3817c6705cce38e2603eca0c4da6c3eed320536c7277e17577c83b3e143c03dec14"
    $a12="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a13="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a14="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a15="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a16="a6619c87639fee3540a1127ddaabdb0543cc0ea2cad151796276ec0474179b3897a4a6eb1b274afbfa0653a2ddb4b4562e2472a7aa89b6691f9f6862a13332d4"
    $a17="b45387d6ffc14bf82fdd5a1502e04f82bc8ef7d3aca5b14a26bc7bbce1b262c47404b1a5ea25c1605b19f82b52c8aab2de3e30f2f9ab3a470947a1f1cf80d841"
    $a18="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
    $a19="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

rule base64_hashed_default_creds_apc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for apc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="KGFueSk="
    $a1="VEVObWFuVUZhY3RPcnlQT1dFUg=="
    $a2="YXBj"
    $a3="YXBj"
    $a4="===="
    $a5="YmFja2Rvb3I="
    $a6="===="
    $a7="c2VyaWFsIG51bWJlciBvZiB0aGUgQ2FsbC1VUFM="
    $a8="===="
    $a9="c2VyaWFsIG51bWJlciBvZiB0aGUgU2hhcmUtVVBT"
    $a10="===="
    $a11="VEVObWFuVUZhY3RPcnlQT1dFUg=="
    $a12="ZGV2aWNl"
    $a13="YXBj"
    $a14="ZGV2aWNl"
    $a15="ZGV2aWNl"
    $a16="UE9XRVJDSFVURQ=="
    $a17="QVBD"
    $a18="cmVhZG9ubHk="
    $a19="YXBj"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19)
}

