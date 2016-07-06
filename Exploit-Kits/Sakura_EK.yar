rule sakura_jar
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Sakura Exploit Kit Detection"
   hash0 = "a566ba2e3f260c90e01366e8b0d724eb"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "Rotok.classPK"
   $string1 = "nnnolg"
   $string2 = "X$Z'\\4^=aEbIdUmiprsxt}v<" wide
   $string3 = "()Ljava/util/Set;"
   $string4 = "(Ljava/lang/String;)V"
   $string5 = "Ljava/lang/Exception;"
   $string6 = "oooy32"
   $string7 = "Too.java"
   $string8 = "bbfwkd"
   $string9 = "Ljava/lang/Process;"
   $string10 = "getParameter"
   $string11 = "length"
   $string12 = "Simio.java"
   $string13 = "Ljavax/swing/JList;"
   $string14 = "-(Ljava/lang/String;)Ljava/lang/StringBuilder;"
   $string15 = "Ljava/io/InputStream;"
   $string16 = "vfnnnrof.exnnnroe"
   $string17 = "Olsnnfw"
condition:
   17 of them
}
rule sakura_jar2
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Sakura Exploit Kit Detection"
   hash0 = "d21b4e2056e5ef9f9432302f445bcbe1"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "getProperty"
   $string1 = "java/io/FileNotFoundException"
   $string2 = "LLolp;"
   $string3 = "cjhgreshhnuf "
   $string4 = "StackMapTable"
   $string5 = "onfwwa"
   $string6 = "(C)Ljava/lang/StringBuilder;"
   $string7 = "replace"
   $string8 = "LEsia$fffgss;"
   $string9 = "<clinit>"
   $string10 = "()Ljava/io/InputStream;"
   $string11 = "openConnection"
   $string12 = " gjhgreshhnijhgreshhrtSjhgreshhot.sjhgreshhihjhgreshht;)"
   $string13 = "Oi.class"
   $string14 = " rjhgreshhorjhgreshhre rajhgreshhv"
   $string15 = "java/lang/String"
   $string16 = "java/net/URL"
   $string17 = "Created-By: 1.7.0-b147 (Oracle Corporation)"
condition:
   17 of them
}
