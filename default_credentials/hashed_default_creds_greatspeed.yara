/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="79d76db88cc9aa2cb2d56a16bbce9691"
    $a2="07ded64f812afb8da181014a9d087728"
    $a3="a125ac4af9b3d9402e9dd77fa1ef07f9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="8700f6634e7d3ebe527fdd78b5771965801c1a1a"
    $a2="d92899c8cba68c81bf496197c4f0fdcb0dd44d26"
    $a3="51e864c36de9c9cf8f89e050c638b521d1e2d2fc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="50ae081353bcbc06e0ecaf595daa64e32ce2acaf87479e7d49520d2d84ea548228184133323be9ea99107fa11a1d89d7"
    $a2="70e37c7ea05439431632b6f111c55cbb14a08a072cdbea5d024eb41262a211c5247112b4664f706ab874d47b215e1dc0"
    $a3="8c5c201854e3216dc898df7d2dda108b7ddbf0253e22b87b8ee6f5fde7977c591700853d8e2d1781b3d95657b50cc1dc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="9969124bdd337f52779d9efdf430033acc1bf9ea5317766231f17f32"
    $a2="b79ccc933306b4be7d2f499aa20fcc2e63820217e1a5f0d4d7476977"
    $a3="a8615133ce0794b2fc0b03788fc9fdc3aeb967f0a0e2967b229ffb46"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="1f94d614dddafca41a5f1b1f658ff0118f24ab7da69fc93259620e142c57fcb0bd41aaf0f107f485595edf192a8e2e39d87530b479ae2efb062722a81ca8c221"
    $a2="dc47b055fbdeb77058fd58922e1393393b47ae884401e7203b235d8751bc6ebd25f2418501356e5a9f8d9033d185ce1f1b891eaf73626ad3a707b364266d658e"
    $a3="dcb73c855f5155c14434977cd31ee5850e784dd99ab136e4a7cd790639be3bb9f0b9f8e91403345c4805375f88fd6b0009fc1648995e03042a3f5386c41b6945"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="7577bf4f5683bf6cc6ce6324381b36449961897cc37140d2171d5953244fb6e5"
    $a2="dcf803280302c60456047893d5d1014bdedb3eab7bc5c920770ac00c9883a168"
    $a3="da677aac89d82d9f881ffdb6c64617e8e017bb7cfe42f7db826074b40bc5e9ae"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="9fe5dc8c515e81c1908def4dca74a718583886396f2df293d724ad51d6b97c023d3f0b92711fb6019182a592bd1e96c26e949f3e4fd909edec7b1f318af5b074"
    $a2="97ac4c2a060e714d81767a70edf1b86ed9c8df9c086df538883c26f0598d850e8ffb3ce15d966b5e6f9898c9729c8108c092c9c7577407e5e1a3af940828d15f"
    $a3="3f46d0082f347ccdb9d11064f0445a250ccf1d363a1a936d77d73b582b6a9c36392249d0c5cad3a38e35d532974dd2e1878cb02f7bc7dc009a518e6a3626ad00"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="f61c0cc3672ba67f4f0a566aea0c543aabf7eb9cfabe21429cb7942464b50749"
    $a2="f292b71f87f3b514e1d443926f047d06569387a14ab0934f660a3c38b1a758d0"
    $a3="2f44bb5eda7be228c0bd325a72d6346d535df86401277faa6b343480a3314479"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="f627ae1d9365ec55d05c8a1e2f2e45b5818dfe9bdec1001cc2f6e6ae"
    $a2="191a452050220815ecf53b385b21927c7ce4987503c003f50370d499"
    $a3="cb6d80bd85e45f831eddfcaa688b7e21a8ab8a25590da3473fb7f80a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="ce0c04ed9babd4291846a965007051f32a4f893f84ca786c0a6058fdda03d9fd"
    $a2="d57cd3911fea06ea5216199ebe00f719dfc32a7bf19923adeea5e1853d191c58"
    $a3="eb88efaec9471716f4f4c64206b6ee33c9e5f3763c6c27323b7e465ea4a17422"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="4a09385fe984297c208f535acc6c111ab845285a3231c3b48acf63eff4d99b799547c0c4f96295216bb24717f68e7a84"
    $a2="4f133e2a2a99c2f4f761f061678bd7ef64245d4d6f1452db9eb62e15bbc7f5e348fd972e8359ffb9e4229d2aad1a8787"
    $a3="60cdefb856092afceec6a1651603c87dfaf01b4220b2a600ab2be6c1c3bfe6e97d84f09759b1728ff19342f8b74e8845"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="4fb44c17e9834d982181a399627ea639e983f0e1fc7f78292993bdc5436d91553cce22b3b07b864b56ea4b7cff7d1d4d3c0077bff4cb1aaf1674a2904eb5af62"
    $a2="48d21c54186d08dd99513469a2eb87a2afcc3af0f25250ee7aa67802beb27dcd76c743e2c68d38d2fee41118629fdb943fbc13ae43ddcda32524caf9dd790755"
    $a3="98339d41c2f061548c030f0e986d5e17298ee3de722536721945618d8506a672df0c019a64c47f9413fc98d51da8542dee10668c97a97e7d372c44f039182001"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_greatspeed
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for greatspeed. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YnJvYWRiYW5k"
    $a2="bmV0YWRtaW4="
    $a3="bmltZGF0ZW4="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

