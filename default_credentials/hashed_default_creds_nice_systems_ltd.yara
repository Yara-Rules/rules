/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a1="ea8f45e704491cbbfb206a3ef729b363"
    $a2="da006d16b9128ad99906f58087b3af29"
    $a3="ea8f45e704491cbbfb206a3ef729b363"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a1="abf851e862f958be5d7b4a2fb12324249e8e9249"
    $a2="bca1de946a414060b8679e77853d9e32bc721c45"
    $a3="abf851e862f958be5d7b4a2fb12324249e8e9249"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a1="6edc785d060315bf45341937f9b09fbfa81078bb68858d34758a9e9642fcac66b0f8021f7e223ad96d4632ada6812ac5"
    $a2="6db9bad0dc3514b34221df2fd951015ffa19cb25a36e083eafc28937fbda6af33761eefac930003c37f3f5299ab64a41"
    $a3="6edc785d060315bf45341937f9b09fbfa81078bb68858d34758a9e9642fcac66b0f8021f7e223ad96d4632ada6812ac5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a1="0a8f86c56ca069a5fb9b3e055f56a6564fe63d0866d9e1cf7c4b9760"
    $a2="6591013f07ce88246fba141ee0914f0595ed05685e84ff43a8dc133b"
    $a3="0a8f86c56ca069a5fb9b3e055f56a6564fe63d0866d9e1cf7c4b9760"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a1="de66cc38e6c9951ef0aad2a99222f315e59e87d182895a2b4300d84567225180ad6273dbb4a4a2cc356c753a0ef6f74c9f03ad9465759960009a2969f081b9b8"
    $a2="d38e60df3cafc8bba462c4c141c6b175c74a116d9f54ada21b9b17769c6629097d5049579799d56b8432ced152863164638375328f8a07e9dc54f7a4070a40ad"
    $a3="de66cc38e6c9951ef0aad2a99222f315e59e87d182895a2b4300d84567225180ad6273dbb4a4a2cc356c753a0ef6f74c9f03ad9465759960009a2969f081b9b8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a1="4aa47f0fdad5e1c87093ddde8a219a75a0b2bf41cae1ebadbf8cff51957d3339"
    $a2="4e2b25facc0e9a98c6574cab867ea6a31c7c883ad4a4865fd60cdc80fbd50e5d"
    $a3="4aa47f0fdad5e1c87093ddde8a219a75a0b2bf41cae1ebadbf8cff51957d3339"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a1="dc19fe1819fbd7d4399914cf4fca237ec614929651ee69b6a2657fd8e1447af12daedacb5135ad4d1b62bfd6d6dbe269055559e1d1b4137859b925c49af957d3"
    $a2="6119e635e4a8e28b2b632d1b1dee38c16bce4f695cab9ac769866b1fd9c55b0a723349132dbeffeb7792c62f9e181207c50171c600ceccb39ec7ed7e5cca9d0b"
    $a3="dc19fe1819fbd7d4399914cf4fca237ec614929651ee69b6a2657fd8e1447af12daedacb5135ad4d1b62bfd6d6dbe269055559e1d1b4137859b925c49af957d3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a1="06990a34eb39f5c651f666c0557808f94a4f646ab0343d78b0fd545a373dc185"
    $a2="388a104398d2efefac205ed6559d100d1135d882200e06e79a48c5196957c13f"
    $a3="06990a34eb39f5c651f666c0557808f94a4f646ab0343d78b0fd545a373dc185"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a1="f515cb98b43ae1365b6e23e61e366ac8889b35beef0ce471e5d96d8c"
    $a2="353bdc81856e051f5aa1d1ebd9ed11691ba9cee08496778ed197b55b"
    $a3="f515cb98b43ae1365b6e23e61e366ac8889b35beef0ce471e5d96d8c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a1="cf3b2ffb2d0216861534a8064e6ce3662ccd643e6a76ec12cb84ba1e8ca9bd43"
    $a2="5c3a2a84d6c383d245654d508863a73004e9062ca8481a9f54fa3da9f7e72697"
    $a3="cf3b2ffb2d0216861534a8064e6ce3662ccd643e6a76ec12cb84ba1e8ca9bd43"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a1="192b8ac3fb4eb32cfc08fb7523a714fdcfd31e8fbb314cd447b03022f041271f8cb64a58f1c11c7fd14e1354e2b04ba2"
    $a2="0b57b7df1323cbbec47d05bcdb1aeea4c7e0b0936928ad838b3330ebd8d0e6d109264aa25d705c16a975d4bfc2c8628d"
    $a3="192b8ac3fb4eb32cfc08fb7523a714fdcfd31e8fbb314cd447b03022f041271f8cb64a58f1c11c7fd14e1354e2b04ba2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a1="a587c7f961b13921a8b6e438999a5ea931d36a2c404695683db03a5a601c01b623b2369e5e659cf51c13e93101b6ec5fe2770eb7ee91c4520e0fa5a6e99c0ef0"
    $a2="21528e7eeb8e93cf2dac57b56fbaea7dd91e60bf3242155a33eb957d368a9d636a8b7ea4148f6fd73ffbb4126a20c8b84c3e3446d76179c3701626677dd2420c"
    $a3="a587c7f961b13921a8b6e438999a5ea931d36a2c404695683db03a5a601c01b623b2369e5e659cf51c13e93101b6ec5fe2770eb7ee91c4520e0fa5a6e99c0ef0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_nice_systems_ltd
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for nice_systems_ltd. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="bmljZWN0aQ=="
    $a2="TmljZS1hZG1pbg=="
    $a3="bmljZWN0aQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

