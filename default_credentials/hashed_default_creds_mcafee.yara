/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="0192023a7bbd73250516f069df18b500"
    $a2="19aa0026f6ad6a0cb78c87f953da68fc"
    $a3="5a731a984ad01873cafab2ba10449b9a"
    $a4="4111cb7b732b45c2a5a71eae294b4e1c"
    $a5="cddaddc65f8ad0714c7f63031eef60f1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="f865b53623b121fd34ee5426c792e5c33af8c227"
    $a2="ff8f5c593a01f9fcd3ed48b09a4b013e8d8f3be7"
    $a3="cb39bb55c95ecae0d777841ec4686d53c2f3d542"
    $a4="aece0db4254c765e46f7595b6db90c517122556d"
    $a5="6d585f738148fa78dcd8eed0c72d556082647838"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="3f75aa9266c066b106318aeb0301226ebba5399d4da3c9e5264e2f7b2f06ecc16653de49816b7f767b41dd138336f613"
    $a2="09385519474aee53a42e2d7191474ed4b0808b7397544e7de03592c51e91944f288e0329f3ff371c5712bc422e60357b"
    $a3="6593a396145ab27507c46a3fa04de5260498c394c48b7eceb17c46c9261f7297c22c28a33d67dfd98736d04a62bbfbe9"
    $a4="7ff7cb97b2e4e787f7129e88a56ddecb5eb23865ca95839498412faa533a545916f8053a8ea0523aa3ee9daf99013f4a"
    $a5="bd30a1fc0c93c29e79c60b2e84abf991d6d9f398e78800cb101164f6510fddd79931b2efd29593a453f8bd47a3df7fac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="b759497cf50772b2452434b3983eebcc1772f1e03bbd76dc2a139da7"
    $a2="8ab4ceca62bb85fde84d08431d00c9a4d143b476f4923ee7e043f58a"
    $a3="96ecf9f93354b91ef86f84e4e3df1d07575ab8d510c8147159166e4c"
    $a4="c45289d57b8855d6ac92496bdcd7ae23d94a7f0a70d5970453d60f30"
    $a5="17b20f7839c9cd33b72030805610ca375c8d2463bce1fda96c13b87c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="7fcf4ba391c48784edde599889d6e3f1e47a27db36ecc050cc92f259bfac38afad2c68a1ae804d77075e8fb722503f3eca2b2c1006ee6f6c7b7628cb45fffd1d"
    $a2="c31ffbfd6d9f25760d7b4f63c1052186d01e5da24aa4d84a02a2a9a6f7bfb82003b04f622bbab6ba671c5c480646741abd46b01e5deaa98e47c07363fd02767f"
    $a3="3b0d923ef504d45911b5faf90fe08f8b1ef9fa791f65533cacb98dc8c072e9ab2cd0ff40f340e01b2a816103c1633a70f5d16a2a230c5aa253720bcf94755997"
    $a4="40b52f07521541f96687a1bf0fe94c1e23c21e57f4d9dd62cc49ce0922f8f7a4f47d1972c2c29e2ae59313ea799e890ed6389efc5c1992add24321440e4053bd"
    $a5="b4953a66e8a7b959fc17858e8bd502919f3c8c68bb7faa5c90cf5a1d9ff464facdfbf4e9bbb23c176932dfae1c2c67ae52f9db05c6d6c4a3f10e78447dbb80e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
    $a2="9d1ba59aea6eabbac8638a9227eb9445e7ecd11fbb5215d4aabab5c77e8c45c2"
    $a3="0cdf5e87989e3cea40e51b5a8a3e22a6b7574424f74499a557eb02164464f86e"
    $a4="37ec336e7fd5d6b25e8b80dfe1ccc88cbc11826f38eeb881468227b25e02ae8e"
    $a5="8e21bc1543b4713b1de130b257708ea596a630feed6b381e8d8e127d9e9a795d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="eba34065a1d45b3bfd700926b250ee119b42b331977b43b61f6c9d383fcb8f2d898d2b003253796e0eda3a37d3fdffd131758ad348e94dfe9685f787c7911a42"
    $a2="8922f20e276ddb97d11d7d216d3ad7ccd72719248b86d3b2b4ba5c4f3bc844a38a3eb45cce63c0ff91bce1aabfb76906d94580646d1d61cd2680b1983094b432"
    $a3="cd3e449a83a12ffc0a38433df2543e4d9f3ed542b7acdecb4ff4fb583e0b7042a64de0a0ed4ad2073f21f6ef28428af312f7000d868e61c9d89ffeff98c03802"
    $a4="428c6644774fcd5578947a823c51c5fe21353d9885587811f35d262bc4628e37850d3fe0e52345b7f41d512877be1e95ba20d17e63f84c2fab5dd6261bbb7ff2"
    $a5="fab4786fde9be856f41cb7cabbd693ce8cfc97b2882ff984c205e9318756e6f9531cacf668cb87ad07cea095c2234a58bb3acb66635a9f2175d5ebd4001b1cc1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="251aba9d7cff47e60f7e1d9f229dc6427f8ad760f77845b8fb30c7250587b6f4"
    $a2="cd8d976c68b4d40f5c51feffa27fcd7d5a4cdbccc6588f47f51957389f9432f5"
    $a3="31fda5a72bb24db49b13054be61607ac7df48d30f1742db30bf9d89e4f9e9663"
    $a4="add2c0b54bf4697eb0aca52551a61d99d759644cfa2828b41004b9e77313f1b7"
    $a5="7c45880ed4fe8cdc628cccc4e9974b5f9bfde12491ec03c51c0dd45b8edb547f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="2a3c9c7a3b25e301b7055c67e9067a7bf61a0c0518ff0ad9178b940c"
    $a2="a382bff6b567a7d78da1a0ee0e814ed13f7d379291fc3081f222a54a"
    $a3="cdc3538a5add6a1cf4d6165a3ea3b55064d86cdc6926f7c123a5d4a5"
    $a4="617a032c5ce25f836f52ecc48c63e70ed6e5f8cf0aed405ea8354007"
    $a5="b101af0364bd8c361bf64048a7028aa22112295fb15dfe84abf74460"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="b227bff0d28823d4599a39a5b55725b0811c9c13184087e9a122eb572e6ff139"
    $a2="2fcea6680f9614bde24d425dc706e11878c8c595d0a73180c92c84c9fd0da305"
    $a3="99495699b2f425d716dbfe3c80587129885714d753e6b9fa273fcf80e3eae788"
    $a4="07de0d9df0f17a31cd9186634664c6d23d62236acd6022e6046bb2fe7568f056"
    $a5="4acf2d34752638e4da0d6c1845979efd51a8d6af417d7dc268f79b73813eec4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9150a266c71a4cf0cbd01a60608f395ec1f8f7082f4041e49195cad98f6ee0cb08efe60cb8d148d2e40520b33922bf40"
    $a2="0f67112ef7609ac784080ec00103eb0961ec3451c3bc846237fd7c57d67b6119f2735ab057a39b449ca7a807dbff2fa8"
    $a3="975506b0b14eae10bbbf291e51ba718d937d8597c94d83e17fc0391e7dcfac1545f8725219b873135bd7d71a18f2c25f"
    $a4="84a98ad14758f5dceb73743c42aa68c109a923e69d4c7c7a40cfb15552feb8afb6147e9e68c8a42f9c7f7fdd39950d5f"
    $a5="f4bde4dd62815a5215fb03cf4168e256dbdd61d85a5a1cfc46e072ff6d06fcf97ca72e333b3a89192b77b0ed891fbef3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5ec73815fe122068a506d57c351bdae988495237ba77b483e2ae01c3df3e78999e9870990b7d99a86906b6cbe2080b1ca5487646bdc70bba185e069f87260dea"
    $a2="0e62aba617f9d3daa94644997e70cbee522ed587f5355df2207aad40bb534c22f6f2126648636bf624ab160132d760fad51b829723c3252bfa112c1d844a6784"
    $a3="f76d1f114cc13d04bfd8e7d325db7d174d512b85cf5a7f798e101cb6779d2dd252fc6d8252d6a19d2a95ace64cf79ed8fc778093932fdd28b53261809c148e6e"
    $a4="bf66555bd86ac607e85a1f4d999b998e21a89f7d9320d75e8667303786ab4e82792cb208ab8f30945356cc304b01a5f1aa4ba96015207f4fbd1ee8591cf441bb"
    $a5="e7b2497f63ed357c02d08bc5a1bdb2018915d9e7ca47c9b0f4db25b225db569817ee8e4ff4c25ef175fa2248b0184bee172d0c67ce8bfb71b3009260b721f0cb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_mcafee
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for mcafee. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4xMjM="
    $a2="c2NtYWRtaW4="
    $a3="c2NtY2hhbmdlbWU="
    $a4="d2Vic2hpZWxk"
    $a5="d2Vic2hpZWxkY2hhbmdlbWU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

