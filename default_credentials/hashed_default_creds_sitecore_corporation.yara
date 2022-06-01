/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="92eb5ffee6ae2fec3ad71c777531578f"
    $a2="cc2f410031aea40769918b7adb73a696"
    $a3="0cc175b9c0f1b6a831c399e269772661"
    $a4="d92c25d41fcd9f8ab35545ef34b1e7ed"
    $a5="92eb5ffee6ae2fec3ad71c777531578f"
    $a6="6153e02bf67aa1bcfa34168d62e9da3c"
    $a7="8277e0910d750195b448797616e091ad"
    $a8="6ecec3241b6977a6c014d9614ec7ff9b"
    $a9="2db95e8e1a9267b7a1188556b2013b33"
    $a10="c1f1782a3d769c40484c849b8754c705"
    $a11="6f8f57715090da2632453988d9a1501b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98"
    $a2="9f56d9b292b55162ca3999b56f054b407a2ae67e"
    $a3="86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
    $a4="3d7346140016dfa40c770fa19ba722af2eb48073"
    $a5="e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98"
    $a6="eb7bf420a2ae1f2aabda8b343c7d9a4119e3eb76"
    $a7="3c363836cf4e16666669a25da280a1865c2d2874"
    $a8="5e6a4f171a2ae0ad43b1589c46ec889cef730aae"
    $a9="07c342be6e560e7f43842e2e21b774e61d85f047"
    $a10="22d66954ca280d9599497b28512fb7999f3fdd13"
    $a11="6b0d31c0d563223024da45691584643ac78c96e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="98a906182cdcfb1eb4eb47117600f68958e2ddd140248b47984f4bde6587b89c8215c3da895a336e94ad1aca39015c40"
    $a2="ac5e4af0bf94858024e368de990622af88b769335ff7f41e829f94e76192e894bf6bf00ea1945ea15005236ee9d38ceb"
    $a3="54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    $a4="bdd81937f38ab5d0828ae02bb236a668e0761990f2378deaf63d336ee24794346e38c36cbba69fd5e4c60adaf4c7d350"
    $a5="98a906182cdcfb1eb4eb47117600f68958e2ddd140248b47984f4bde6587b89c8215c3da895a336e94ad1aca39015c40"
    $a6="5beab25a43e17902abf92c2d0fccdcbbf010ff8fb64e65d804d10bd834804b7db8649eff28bcaf3f4608c727c49565eb"
    $a7="8ac10705a78a2dcd15fa577bac70762708597a02e130d8a6192d73dababd2b14502dbeee29d0e22bc341a0c42af6a4fb"
    $a8="b78517f162a7c5792cd74ccc019f1ba192b4ea5d6f61d659a700d11a7dff03619ef7dedb8d3ef2614990678555064ac9"
    $a9="1ad0ee901a40bf4536640f4f0c8c2b9fca9f5fbac283fd6dc4d1fd7021f8ca66c69c399619921f6dec5a2d9d942bc7ac"
    $a10="9e5c714c3b67a0cbf5744ec4ba3cbe7968f79a7d700fcbc5ee5c59ca05d84ee1d766478b74cdb920c55887c2af410e0f"
    $a11="7857a47542aca03c22c39461231a919d9904a5915937278535a41291791b96c06717638cd6b0a2e5b8a20a53ec980f57"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="c681e18b81edaf2b66dd22376734dba5992e362bc3f91ab225854c17"
    $a2="b060e3dbe9c4eeae27b5295ae937703c3c8b8356467df13b0526f7f2"
    $a3="abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
    $a4="e4538f747534ffc7ba7fa8c42319e2aa17dd02d27f7f1150a2266aeb"
    $a5="c681e18b81edaf2b66dd22376734dba5992e362bc3f91ab225854c17"
    $a6="8668490342591ecc520b05c40b690ce79dc3f9f79689ce1d03df2306"
    $a7="06c9f71496e24dec6acc44895648cf9ec40b5cebb7bc4858a3c69f25"
    $a8="8a9b11626feac5a3b533fd4d2b07668122b52ec10879efd32a5138b8"
    $a9="2e0cc996fafd71bfabc0717628bd3296306b078910b68f081f3d3fcc"
    $a10="11e5224a236ade3682067eaf06127ba7f92f3cae4335058050d29808"
    $a11="4fde0463771d8c4fb82794d5d6d003725c819dd34360e7bf9c70cffe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da"
    $a2="84148e7732c838449df1db8f9fec13129fd8cee09e0a11b2eecfd384ee30c5b3c7bcf79cf7947d39318d2f5db54c910fade20fc4b1cc1ee66c914c8fce13987d"
    $a3="1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
    $a4="c11fc00b41549c865ecc8219948a6a28a6f40671621a1cf1cb9397ae3d597e709163f1d46e627b9a494cebcecefadbef8aaa98f93dc4772a7a3c7ef67edcf0c5"
    $a5="5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da"
    $a6="39c134bcfbea849fc8c7d9eaf102de758d1343f0812e59e98053c14bce3d170f5a59422bbf166ca3543681e6eb3784f3fa171005dc84e5ad8bb136f612e78b0c"
    $a7="48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5"
    $a8="b371870320781e8c85c335dd627125a864c94dd400310ba5aa840bf0386a5b5dc1cc42393017685f80b5a6820ee1444219d32ec968e0f92e2289f05e399ac8d2"
    $a9="f10127742e07a7705735572f823574b89aaf1cbe071935cb9e75e5cfeb817700cb484d1100a10ad5c32b59c3d6565211108aa9ef0611d7ec830c1b66f60e614d"
    $a10="4e956412fd01690ca3c246a1520f1cef9603788fb132f7ae314241100052a7d642aa707e28f039ca62840bddfaf9c3e38735618743d361129a46be4947e25a3b"
    $a11="f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
    $a2="e07451d956a297e8e76d83b519ba07d48bdb19cbe04cb54afd276bef632f55c7"
    $a3="ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    $a4="e51783b4d7688ffba51a35d8c9f04041606c0d6fb00bb306fba0f2dcb7e1f890"
    $a5="3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
    $a6="67e1f11f554b39f1f6541d7b74439a90974ee4001a507f44737183249d5cd4cf"
    $a7="18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4"
    $a8="3be6c7a374d102bc596007c668ace05a8295a0ad7b86ed7679302be57e53b936"
    $a9="acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0"
    $a10="8d5c39b54bc9862ba36bc6488b27e67a42a7f74ef59a91e866da9d27540f7216"
    $a11="62c66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="c029c24b2c89db037fbf8b04930569fd8422f7c0d62f36c8dae35d03332139e546a1126f6c75be43685598f48cefff1d05a3c74d804fcd5c0a53734cfb0bb862"
    $a2="deeca6e590923ec4cf3b5f918a5720a77eaca97fb2accf6adf64fb755db53097bc4937ac9a127552fbc9a96baf7cb4f01f14b819abe90e294bb5fa3651ac2219"
    $a3="333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c"
    $a4="53aac41318b6489226bd21fa781227d2f7f53d8f12e24d40009eac51a51ea992d8d9b8fee4670c061611c4ae72303b5979fa045ac0c8af529dc8639b86c1f7e4"
    $a5="c029c24b2c89db037fbf8b04930569fd8422f7c0d62f36c8dae35d03332139e546a1126f6c75be43685598f48cefff1d05a3c74d804fcd5c0a53734cfb0bb862"
    $a6="60fc84ffd21044734508297ababc41079d1bdcbe2bab0e29adb469b66f7a977367c11b7dbf76fe33bb29fd28f32f529443c37e0f4d0d1a9bd78321da6f09013d"
    $a7="0fddfe69251fd8b811a37bb45f8ef0c8485d3e60d84361d15701a5603b30cfcd572bd0bccd1e108dd697c7c53c492c188a42029b1b8a47c9ecf9ac311fc0a3e8"
    $a8="4761e44a2a11a2020408369731b6fbd94156f23566c71d58714d6d74ba16bdf1f9cfcc1fb60a2c0e0c74f663e624afb164d570e0f9da04decb2453777adf5bb5"
    $a9="49db7a7a6bea2cd893596c1aeebf733c91cf89d7fa0fcb7271dcd5ddc9d12aeebef3e297eb161f01784185ef43b275026737a55678a0798c34412dd4873a0841"
    $a10="d71ad83b9210f75c192aa12c709c9dcdcf6e768b17efc82863a1357d825fe02d10209c2190314607db8993d7d5cab59f94bf86082e1ecee589a4481a42e83eee"
    $a11="d40bf097cf03db84252294c2a19544fbc01970231f36dca2de944e48a8d8b945fe84158070b568af2f6094f07088bd57446524c56751a10965954e5bfeb6c5b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="04449e92c9a7657ef2d677b8ef9da46c088f13575ea887e4818fc455a2bca500"
    $a2="3a4e065942271be19db7bb975a4a363dc11e7ea02453898d8b5b1f5abb053a1b"
    $a3="4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90"
    $a4="c03258055c94b6d7d05cc8efad49e26c5237b0de0ddf310a61391fd7c2a4c6a9"
    $a5="04449e92c9a7657ef2d677b8ef9da46c088f13575ea887e4818fc455a2bca500"
    $a6="230eaa3c2f7592c72c4588a17df09891a75557a9a87834492d1450aa96e605ef"
    $a7="9c5889e3ab01635e2936b93aa64f15c1d781f1bb7b64d3640c67d25ed88dd269"
    $a8="3bc17eca8fa9740a52bad0b3b574278320fe47c58969edd3eddc9544bdeeb7c9"
    $a9="347ed3dbac3394d262bd9b09a97a838e4c8391c8ec8b805b052ef3cac4d046f0"
    $a10="8ae2b4d552ccaf1c6e0388efeac25a6f222e90948563439f2c681fb1f5010ee8"
    $a11="2ec3cec278cccb2b2b2cfb246125cf41e2c0323156012c08bfb8ad7bfdc3c8ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="8ec94b5ae7bae885e5b1fdeaa6fc2ca2af27febfdb7cdfaa6745fd52"
    $a2="efd6b06cde0475722fe362790928b5f8f25cbc508ec94190080fdbab"
    $a3="9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b"
    $a4="5ae8dcccea571a5f29262890677fd912111bf56dcb1806837efc5bb6"
    $a5="8ec94b5ae7bae885e5b1fdeaa6fc2ca2af27febfdb7cdfaa6745fd52"
    $a6="ce39fdde24b909908febae7dfa2e296f4da3413e3a9bf028418ecbc1"
    $a7="af81fd2b118fc4b3ed11bd42e7c056de57e29fcde0b0f236adaa4e25"
    $a8="566366711efac35a5a00d667c33e522c7179324ca90dadb9dfda415a"
    $a9="35fd6f346c0b2fa77a32a1c8d961d08450da1cd6494afca64b57955f"
    $a10="76f7c81b268005b14b786c133ba671d2804ff28c3f01d714c3e39f58"
    $a11="c3835c6f733db2d1f556e5b2f32f11ad59ad0a7e996a25376951cd81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="b039179a8a4ce2c252aa6f2f25798251c19b75fc1508d9d511a191e0487d64a7"
    $a2="94c9db1c80801c100cfbef62e40c39a85679743f0190593cc77a8e8d9ed505aa"
    $a3="80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"
    $a4="55161e9ad867a412f7009dd5f1596548c2e7ebb71e30ed0f2d14684d08742014"
    $a5="b039179a8a4ce2c252aa6f2f25798251c19b75fc1508d9d511a191e0487d64a7"
    $a6="55310d2f3370d1c73c9121f190ad644068296f5a8201b95701748f650a18afc3"
    $a7="4ce8765e720c576f6f5a34ca380b3de5f0912e6e3cc5355542c363891e54594b"
    $a8="5e192e1b7f8a525566929005faadc03e6faf376bd68cff7fdc687533928726b1"
    $a9="3e5e3e723953551a2ba2e7c5584bcc4ce407414af1ab2569051e7c9bfa33164d"
    $a10="e3d2fb373661d01f65d4097daa6043b61b405578dc8711c348dc82b3e0315839"
    $a11="1b42f48aa4371867a7c51ae6f237f35626e02c12eefa592614e1b10af7769370"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="0c851fd986de48f9703a157327512d705e0aec5e339b53d99f4f3d55b02bd81a513e3ab059d20a348c993acd6591d347"
    $a2="7146d7c58cbf33a2c1ae20b887b2b879805ff93c7ccf23d0dfe7763239daa3519e94ae23513599865f1195046dd1496c"
    $a3="1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9"
    $a4="7c9f4caca7cada9652cc8248b8e5f8bd80db16d4a4dc0b794865f60cd4e2a4bac1806f782fb1e2f338bf5fa0658456a4"
    $a5="0c851fd986de48f9703a157327512d705e0aec5e339b53d99f4f3d55b02bd81a513e3ab059d20a348c993acd6591d347"
    $a6="6b7949e10c6c429a4dc39190d777e7dab950e249cb4d076da592574424f05e170d5b668cff909ded062326ac24e69934"
    $a7="0312ab38cafbaa6fffe82ab1aeafcce1d4c656c5fde60444232a374df23d6c364c4f33bb044ae258e25111227c9d57da"
    $a8="aa2075577b7f3e85c514cde5d5b99c080468b5da62bd2f63e8e1a655e73cbb7341f7aa5dda60b92877135b99149290ef"
    $a9="d1a95dab99bdfc5e1f48213027c463387c617881903985572d43433b4e4d8d21e0906abb58c2e4a633cc16abba1a9663"
    $a10="cfeb5fd3c737c80d05a8cc9d2336cd7315f296f2ac127a76abc8470d78c21a32fec48dadba84d760ef7543a4f74f5d83"
    $a11="5428b66b2021a5090995a9f4964f8f82fb34712d4a10f69f1bfff92f8534e3939d86c83b441fb83bb937055733b9e6d9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="8446c46ee03793ba6e5813ba0db4480008926dd1d19efe2c8eb92f9034da974d2171ae483f29ce3a79ed4fdd621ae1ed14fe12532af95ddd0728779ce5aa842d"
    $a2="dd2b17333501a85e6ca9664e11796985a8ba3e1ce0361f2a1120299211b74e230b20129111b1c718d7a92bd0e65dac6c3c3f2effc07dbe2952c7422a681bb682"
    $a3="697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"
    $a4="2dd6026b8a67945db1338abefffa88c1e8e20715333a19d40e28608edac39650c23a61f733ee4034c185ecec85872cba041030372f802bf3ddd86649c3c11b4e"
    $a5="8446c46ee03793ba6e5813ba0db4480008926dd1d19efe2c8eb92f9034da974d2171ae483f29ce3a79ed4fdd621ae1ed14fe12532af95ddd0728779ce5aa842d"
    $a6="b4e84779167f0e5ac21b2992681629a9e4294ec09d907332f14faf50faf8a54fe92062affc98299671e1ab19cc496e24980c4023c4b7d4b528bb4bfb3cf23d7c"
    $a7="4668897682ccd2b1ee0cae8dc55947291f819cc59ee126f5bd243b1852577414413aeed5780b5fb11090038715beed1b00714a15b31c8d9674fbdbdf7fd4191c"
    $a8="7016dbf5432d40bf7ff3af555346672df8c923cd4bc01263950f19abd9a40b75342fb052af7871014239a1cd948874485ba0f15ae6bcd86db2f8ccc8ff896083"
    $a9="37e275b9f5a7067372be037c5d010e04d3d3ab0df5aab129a9379d9b9c27ecef3f7fa7bffab6582c18323df04c9d0c53cb63fdd5dde484f4227eb60f184756fd"
    $a10="18d6dde43b20a09f2b16c82e99ed14fb22866de578e042737e69ae62f1272ebddfe910b3ebabedf1b68c53ed9fc778f7abe319cce6dd59076ab1c1a4bdc66222"
    $a11="7c8e9b49719fda980d594727bd9d3ce693349bba9b303a492726ed7107551879be951f959c55e11b6b1fbd24668f5ee83339da547c04ebc13b56df8b12a03cc0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_sitecore_corporation
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sitecore_corporation. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="Yg=="
    $a2="QXVkcmV5"
    $a3="YQ=="
    $a4="QmlsbA=="
    $a5="Yg=="
    $a6="RGVubnk="
    $a7="ZA=="
    $a8="TG9ubmll"
    $a9="bA=="
    $a10="TWlubmll"
    $a11="bQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

