/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="0537fb40a68c18da59a35c2bfe1ca554"
    $a2="5a8a47cdb8441075fce04c161e91ac1d"
    $a3="0537fb40a68c18da59a35c2bfe1ca554"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="193b3437a94374579772f3f1a8c8f08381218bf9"
    $a2="617dd1823a9ca08eff23a935c272da10c988b5f4"
    $a3="193b3437a94374579772f3f1a8c8f08381218bf9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="2d6b69ebd8df1518c295aadb6c5eaff0b120b4d9d1eeb435cb9b4df80a3d2b4b22a4b820780f51271136e5b6790e7f52"
    $a2="99d9d91ba267eda91e4cd400fe2b30a405da8e7d9f9a260fe2e128ae2536bed5258b933a35d0c29dd2278fe56da112d4"
    $a3="2d6b69ebd8df1518c295aadb6c5eaff0b120b4d9d1eeb435cb9b4df80a3d2b4b22a4b820780f51271136e5b6790e7f52"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="e19deae1228dde507418d1f8e7b68f7763bcbf7ffdc52b55791c7dce"
    $a2="f1b54a4843d22631aba8fa60caf2e8dcb6a3ef9f613439db0b9ab6b2"
    $a3="e19deae1228dde507418d1f8e7b68f7763bcbf7ffdc52b55791c7dce"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="fe3b6358428a7d041bbf76e6088ca90133ba9cd34414e3ed8c53eff2bcb2a940164ac3541d4a71a2d566b68f01874aa53440d1a87e2d0433f8b07a898dcccfe7"
    $a2="515d4e81bc825cefa65f8a9cdef035f50b688f7169a2e6cdfbe0e6143e5f5f31919de61dfd323876f49987cb5d9f9f0935d0d70884096a80283776910e76540c"
    $a3="fe3b6358428a7d041bbf76e6088ca90133ba9cd34414e3ed8c53eff2bcb2a940164ac3541d4a71a2d566b68f01874aa53440d1a87e2d0433f8b07a898dcccfe7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="a15faf6f6c7e4c11d7956175f4a1c01edffff6e114684eee28c255a86a8888f8"
    $a2="43f98918052bdb9677a20185bfdc04f5bc3d2d9f2c686f1bdfbc399b5a4fda89"
    $a3="a15faf6f6c7e4c11d7956175f4a1c01edffff6e114684eee28c255a86a8888f8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="9849fb3db2c78c49af0d2eeee88c7f0a203e523fb303f47f531486c4a2bb658bdd8aa59cff04c9a18a5fe1f2b2b3c674607d3020868549e8435676add59298d3"
    $a2="892c51ab4cd4321cedf7488172499d158b1a43ba46e138e28c8f03cbc5029ec88069ee1b5084eaf7df7521068223d7ae8833993d3bfc52dd229ab1bb45029391"
    $a3="9849fb3db2c78c49af0d2eeee88c7f0a203e523fb303f47f531486c4a2bb658bdd8aa59cff04c9a18a5fe1f2b2b3c674607d3020868549e8435676add59298d3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="698e720f8746d03856ba1a51bcf5f576051e27a5dcb1008591086a30db1259f2"
    $a2="f169f69436b4384a360674f38ae8156a43ed0dda9807015cb0aac836c7ab5051"
    $a3="698e720f8746d03856ba1a51bcf5f576051e27a5dcb1008591086a30db1259f2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="6e87e82a698325c15d855224bf0a9df5dad636ecfb513e73421129ab"
    $a2="6308a4c5216491783a5382b1e26c795b0e2a42374b292eff64447c5c"
    $a3="6e87e82a698325c15d855224bf0a9df5dad636ecfb513e73421129ab"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="3efad2b03b031d2d7c8bb3b19f66eb66dfec0d70a09a8ead2f3a66bf77eac333"
    $a2="faef749b7f8d82a0c144e8f53fd815fc179f1cc40870f831046da2c89e2fc010"
    $a3="3efad2b03b031d2d7c8bb3b19f66eb66dfec0d70a09a8ead2f3a66bf77eac333"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="cf9d0665d7e0828c6b69ebeb68dc546b21d2eac58ddba1e6798617b5abada050932c63e88c5e80023825fb9c05f4b034"
    $a2="512ab230fd8feab08a9ffe4521de2b0b28dd973768d7887ff2c421ced7cb1b309be5a01fee57f1f588f204e0b8e75f2d"
    $a3="cf9d0665d7e0828c6b69ebeb68dc546b21d2eac58ddba1e6798617b5abada050932c63e88c5e80023825fb9c05f4b034"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="ad82bc8081f726e752f1478a301f4b8856660af1e97e67a069123070a88a770163134e8d2b53d74f2474c06687c2504181884ba307d41a753287945390509675"
    $a2="b9a260a5401fb3e4dcf171db05717188e2132dc786ff8bb20b2de7b6c6c4c00f870ddde06e8f6210b15ef2e615809bd0acc43cd71aefc4cc38043b06730d2ebd"
    $a3="ad82bc8081f726e752f1478a301f4b8856660af1e97e67a069123070a88a770163134e8d2b53d74f2474c06687c2504181884ba307d41a753287945390509675"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_radio_shack
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radio_shack. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="NzQ0"
    $a2="W01VTFRJUExFXQ=="
    $a3="NzQ0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

