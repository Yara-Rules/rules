/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1036ab2848c17d92d0433e8ce98e903a"
    $a1="2f6ce515b22ea0f321e8b814be1f6bb0"
    $a2="837129fcceba19fe87e4c1244ffa0721"
    $a3="23052fe3f5bc627d154d858efb40a165"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c26ed5e2918203184fc35d4fabab0a3841fc011a"
    $a1="90e733e3382e15d3136316b614caffe5ebd6442a"
    $a2="c63b77b4619ae8716d3f0a99e17383c2ad8e7282"
    $a3="d83a104ca192932466cc1e308b49757ba8ce39f0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2848ec31897ffdaed0b78de7c3b840dc47b956bd93b5a2c0a575e688d371974587fe12d8d6a4e9816120e83e95d23a56"
    $a1="193762f438590027af3741560adf2059a6580837d22349d802df83135db6afa2e29db6f7e46a9afc72cbee1a38c77261"
    $a2="4d252a6764c1e477d9dc97b9d96ec05f08f755b2ce0990025e0c6228281e3f9db8725d6efe4dce28629bb7b85318cd6d"
    $a3="334f7e2ce36ab62f4f8901e016d5061c1b3ce42f2a3d87b5d8025d9b81082c40b917bc88f61909964bd880736f391e65"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="41491e96da93d03981b6677040d1ac8f94b68d593fadfed5595e0cb7"
    $a1="bb8dd744c35071084cfc017afee9f3a492b762b93a083a6a5cdcdfe7"
    $a2="25193ce5c73a17baa8420eed3f8f139f34447ab0e8da490aaeb10d63"
    $a3="b0230b784117e470472294d167c34856eaf68d68b7e9307836464c2b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8d1a276efbb3cdfb4aa060818066c78417608fe9f457502388d688335de754f488731f201960849411c68a01c0c01827fff2d9d14fe868e3e8157e8c3ef18caa"
    $a1="4dbb441272177a8af5add51ae4c7012225d5f02945aa58c0837c93f8fbdabd5661c0dec1de578665accf19516f1b13eac440e5c72b73b4252e807d1b391a4049"
    $a2="c185ffa1290eb1d9ff7b87cb5fa6b3d0ef1f94808b8cf42e86655052d182128d5609f6e940ef972daa1bde28d9885822ca8e3331a529a270ca6278e93e233f8a"
    $a3="4705392774c804670fd1e7e6ee6842456525d6b6ef473d97f1c0db8d70339dcad36159883e0c2554172d0af36e4db63c8259298c69ca87edfb09186ac35528f9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="442e67f339040c13865fa8306cbfff3dbf789f62be42aff7f866f24f20ec9946"
    $a1="47e5a6cd5d35ae54f7d54b91f1101f8cd19e16d4de81987aebb1797781e57bc8"
    $a2="8b10163df5c8c0e1068927b0de7b040e8d567f4176da083a2ec059c4b0a36e1c"
    $a3="210d00ae954a907a9ce1b06c663f702917a6823ccbddd986e9f0a21f51e2af27"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b2ad3eae8f8dae047dfccc34afb109d363a895cc71e0540252d6fe37c2674aab2baf21f5b5b2089e7778ffc4165e816da36bb520a0d3ffff0259d14b7783a38a"
    $a1="6740ad43869a805dc9fd6ada5e556bd7dbf0ff27596827eb174e052c61d14ba087677a8872a2d229d8321943ab4ab759d6c74de0a34631149d48dbdb0dbb8e91"
    $a2="840a88e800876bc4e40f8c33d9e7c293c0e28f48c291398236764b0ba716c09a0276cb798e83f10415341cfc7889802accbeda169135716ba316d0c4afed80a7"
    $a3="bd4312ebc64e5aa86e3e8a952b14243c47deb93abb9fe2652679fec67629220868e7d3ac72c9308d119ce3208309ca73d426d350520f8fb33c6133e2e606d8fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83a62c3efce84e77ebcc76ae4132840d21e4fc28bc07a43ff9a67ab5bb58be4f"
    $a1="14b93338406b7166cefd29f6622e20e388c357ba6fc782e5f0b8f46977dd1b6c"
    $a2="27d1ca9e380f2d4224b5d8505a5715ceec6fca3b03be5a0d38344ab2fec2b116"
    $a3="be5bd5bf4ad1e62310b143736e8fb8899ba1e9f6ecfb76aa465ec12645c0a151"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2a69c0da1a8a203108e7dafdc18d206230bfdadb4e25961c748375cd"
    $a1="1aeed8455c7e500203c3680c8de04da20829722f02fa56643fde33a1"
    $a2="514bd8a2a12d978f367c7f70551e6688af3d72a89997907389df5ef2"
    $a3="3d2465a3f806df2b6ac34f58dae5021a32a0c5b4da45dfcea130aaab"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="56c42e2e7e039ed7d20fcf94b6ea70d383d912d389b510b24f008206ba85fd8c"
    $a1="1b9d3b1526324d37b28648c45cc8f21ad6eafd9a9eea3ebbe24b249a986023f7"
    $a2="375617b0affce95ce069be5d690b962f3b5994e94ac350eb83d32d2b8b342c79"
    $a3="e67822e59cdad773a782f84ad618c04955ebbfcd4879c75be1126287c7ec5edf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dbc5290bbeac891fe6f56a3b537a318a3a3c5cbfb5cc08995aad9e9dda73c9909b365af079b523538d6f6699c68b52de"
    $a1="c6afc90044c10cb59276a11284d4e6ee86580691ede399641caf85c110d87e7ed72208b5983e185dc8526bb988d2c1cc"
    $a2="9c22d5ae545171c67130105247577cdfdd60ee834953cd65f26a3598e1dc72944e94280b1a10a73d64b4f222b9a59ccc"
    $a3="5b85d6d6abee0cd02c8e86e8f1582d66d40b91b7f0fb1e1862ee6fef4ab11b2b87d9f5093958248a7677dd7c2ba5eba7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c0e18f2eb2eac30e7e30e20b5f5202f3ecbda35d5921b552b5dfdeff22761585cae92fc6ca496f136056d411350a4a10beaee5aaf29c56240679f5c38b8a780d"
    $a1="4f746af90aec8458b722248c8c015f8bd8b916bfc4eb07286f86cf9bf5468d8261cf0327ddedb612812ab5006620484625418e4919c81a1d399034270b4da79d"
    $a2="7390534efdf99c13932a57e08d226d44ccf8ecba0091ba8866b848fcec8d2437be3bd03ad1f0afa38c6b2057c4152b3fa36070a811ba67f6f1ddd008f0780fb7"
    $a3="9328c5f4ecfdc43027ecc941ae17eb0a2c015e6a75109a01ee123c0af2cd8944b90ca506a2240d460e3d5607090a6e046d6e421143362e630ade139fe58d18eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_honeywell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for honeywell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TG9jYWxDb21TZXJ2ZXI="
    $a1="TENTIHB3ZCAwMw=="
    $a2="VFBTTG9jYWxTZXJ2ZXI="
    $a3="VExTIHB3ZCAwMw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

