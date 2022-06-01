/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="10c0a96806ba3909e06aee543721d424"
    $a1="10c0a96806ba3909e06aee543721d424"
    $a2="06e3d36fa30cea095545139854ad1fb9"
    $a3="06e3d36fa30cea095545139854ad1fb9"
    $a4="77e69c137812518e359196bb2f5e9bb9"
    $a5="4b493c01a534432d820bf225e3f6c29d"
    $a6="96f9963e25520a9011c82401920794f0"
    $a7="96f9963e25520a9011c82401920794f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d3c4f83bcf53415e44694106b5b00ff62a2dea62"
    $a1="d3c4f83bcf53415e44694106b5b00ff62a2dea62"
    $a2="2da0b68df8841752bb747a76780679bcd87c6215"
    $a3="2da0b68df8841752bb747a76780679bcd87c6215"
    $a4="a1872e333d0e52644f6125da2276530f7ebe5e77"
    $a5="8fd45370cdd18ea297298716d6cffb048ee662b4"
    $a6="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
    $a7="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="695878b49e5c6b7ab50e8fe214ec1b8b1499dba682161b658f8f57527fb72bfb1d1768eebad0f95e5a6dd9e181432f9d"
    $a1="695878b49e5c6b7ab50e8fe214ec1b8b1499dba682161b658f8f57527fb72bfb1d1768eebad0f95e5a6dd9e181432f9d"
    $a2="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a3="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a4="4cb32fe7431290f83d82c6699d98e45f824435896266cfa19d53479fda2235503ca178263b8d47e43e3a435dcc5a520b"
    $a5="50fd6502596b429a798e5bc2344b77781a00eac366bfaecd2eb0795423fe79aa4aaef05d0a0e61c127bb3956e83b784e"
    $a6="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
    $a7="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="11e2102bd17c2b108cd82ac199ff29dfc9efe64ea3ebb652957ab9f3"
    $a1="11e2102bd17c2b108cd82ac199ff29dfc9efe64ea3ebb652957ab9f3"
    $a2="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a3="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a4="a7860cb07d533157c51cb22c75cca370bc8a96dcfe6d17bfb39ab588"
    $a5="1313c0b3d86759d4ba1e8dad80c91963d876649017788eb264bfe0ea"
    $a6="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
    $a7="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a4476d0f368617d2d798387a92268c2af27e669c5f7f05439ecdbae8e8524bda8164f031e444c113393e22a80b516b848aaae23c972f32adb57963492461302b"
    $a1="a4476d0f368617d2d798387a92268c2af27e669c5f7f05439ecdbae8e8524bda8164f031e444c113393e22a80b516b848aaae23c972f32adb57963492461302b"
    $a2="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a3="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a4="061f982a2f8e4377539b82a36dbfbf716cadee5742a8d665ff066192456c47f094d4c5bb9a75acd31eda62ecac5d3b96f768480bd345fd628f585f1b3ab74383"
    $a5="a757a064f21d0a91a35bb63c9eeaa208a48079e9e21079e1475954504ad3bdb69554f06f51a59da9607d91b867d308eb560e494d8506819c5e22688cda839f5b"
    $a6="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
    $a7="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="12693b7ddc6b247f54b66dccfbd61e4899d1352da65076a9bd3358919b22923e"
    $a1="12693b7ddc6b247f54b66dccfbd61e4899d1352da65076a9bd3358919b22923e"
    $a2="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a3="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a4="298bab1136dcde8c0157190fa5374cbf36c33f79b13a7597da8027c5afe8dc31"
    $a5="fc1e777bb6efead7fa6e1f571a36311238044b39ea68850babebca7f694f30c6"
    $a6="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
    $a7="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfdd66d53c299fa19c480d084569dc3f7a8b5a023cea3686aa765760079aaee96e26082b48b5acf73646947942eddc13502b898ba74b27251ae0490a77c38def"
    $a1="bfdd66d53c299fa19c480d084569dc3f7a8b5a023cea3686aa765760079aaee96e26082b48b5acf73646947942eddc13502b898ba74b27251ae0490a77c38def"
    $a2="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a3="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a4="6877cbbd9a178b68edeb40f13fa0cb6d00d6e922a12f6da5831f0e2bbe00045c0296a89ddde0d1794481344e21570d9cb86bd64db920635bc880a0cecb7c6b9f"
    $a5="8b50d730c745edd0027afd3b23b52d6dc38d8841da714faf5033cd2446d19971b2943a6b3f407926fa3321296759cdce1dd31182189f1e6e481664498dad72c8"
    $a6="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
    $a7="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="05cd86ab7af5c5aee421b54cf2745cf049ec90e87a5cfad2bd55c662ec920271"
    $a1="05cd86ab7af5c5aee421b54cf2745cf049ec90e87a5cfad2bd55c662ec920271"
    $a2="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a3="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a4="beaea7fe492e01ffc908306e5a00f505281806dfd7777e7370c7b03946c0cf6e"
    $a5="05411fb85cfe468c455984021a6a07b6aa33d2822861d238361afe5868ceb7de"
    $a6="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
    $a7="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5096587e73490a4f32ec1e62a8e14c062fb6c0303a0fc6f4b0e06a7b"
    $a1="5096587e73490a4f32ec1e62a8e14c062fb6c0303a0fc6f4b0e06a7b"
    $a2="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a3="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a4="248350fc49c1493ada8146d0f415f8f6f4c6ccb7562e420946547f86"
    $a5="39ddca3b2c0fec73ee24155debf4c729c0a1631232fc26fc71b5bb45"
    $a6="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
    $a7="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="697cb364e493775b2f9707298f6c286ffb85d86ec3f5ec01328002253f1c32b9"
    $a1="697cb364e493775b2f9707298f6c286ffb85d86ec3f5ec01328002253f1c32b9"
    $a2="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a3="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a4="0af52ca89f39fb69499cff6948dc69129c3d6d41d0c0c9beebe74e951e1acb34"
    $a5="6e19fb7432b303886d004f79859abb79f1ae180ce62c8ba79a4845ab037258a7"
    $a6="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
    $a7="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="308c398ebb56f272e4bc316a45c1145fc374b5d15d0b64f78c6294b1a2d03370b5f3d8727210e821f8e9bf88b71714d7"
    $a1="308c398ebb56f272e4bc316a45c1145fc374b5d15d0b64f78c6294b1a2d03370b5f3d8727210e821f8e9bf88b71714d7"
    $a2="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a3="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a4="e5d15c7e25cddce4fb8cc889d39db219dc9a9bd4025517a83fcc56ebadeabbe6bad679ef86b4ff04a69388ff99a0bb0e"
    $a5="3db0d9634f834725ddf5752b8f756c3c48cfa64987236f68b42d66129cc3b7dfd12b0b50b446f18600ae4520406f4da8"
    $a6="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
    $a7="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="95d19497c55bafef486116a28077cf87d1c337aac464f852506405b69c2f257bd4670b487720fc68d41dc1adb4fa30ad51ca4522f1a3a4042ab9b43cbc627c63"
    $a1="95d19497c55bafef486116a28077cf87d1c337aac464f852506405b69c2f257bd4670b487720fc68d41dc1adb4fa30ad51ca4522f1a3a4042ab9b43cbc627c63"
    $a2="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a3="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a4="15a7d68e57985306ab5af5a3ced1db30f6f1132b77b47ab54c58ed402f727d360bd0f00e04c6c2890fa61a57f32fed64ba8b36784b6bb30f7dee5b948f1db822"
    $a5="929d421f4c84e50e23d949d1cce848a744df6e86dc6fe1b5f24095b27b3b4b702775938cbd891e00ed7d3d75fe453badc0c8cd5c13ec5dc458a7353c01085c07"
    $a6="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
    $a7="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_utstarcom
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for utstarcom. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ZGJhc2U="
    $a1="ZGJhc2U="
    $a2="ZmllbGQ="
    $a3="ZmllbGQ="
    $a4="Z3VydQ=="
    $a5="KjNub2d1cnU="
    $a6="c25tcA=="
    $a7="c25tcA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

