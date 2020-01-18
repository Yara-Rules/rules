/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule bleedinglife2_adobe_2010_1297_exploit : EK PDF
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit Detection"
   hash0 = "8179a7f91965731daa16722bd95f0fcf"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "getSharedStyle"
   $string1 = "currentCount"
   $string2 = "String"
   $string3 = "setSelection"
   $string4 = "BOTTOM"
   $string5 = "classToInstancesDict"
   $string6 = "buttonDown"
   $string7 = "focusRect"
   $string8 = "pill11"
   $string9 = "TEXT_INPUT"
   $string10 = "restrict"
   $string11 = "defaultButtonEnabled"
   $string12 = "copyStylesToChild"
   $string13 = " xmlns:xmpMM"
   $string14 = "_editable"
   $string15 = "classToDefaultStylesDict"
   $string16 = "IMEConversionMode"
   $string17 = "Scene 1"
condition:
   17 of them
}
rule bleedinglife2_adobe_2010_2884_exploit : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit Detection"
   hash0 = "b22ac6bea520181947e7855cd317c9ac"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "_autoRepeat"
   $string1 = "embedFonts"
   $string2 = "KeyboardEvent"
   $string3 = "instanceStyles"
   $string4 = "InvalidationType"
   $string5 = "autoRepeat"
   $string6 = "getScaleX"
   $string7 = "RadioButton_selectedDownIcon"
   $string8 = "configUI"
   $string9 = "deactivate"
   $string10 = "fl.controls:Button"
   $string11 = "_mouseStateLocked"
   $string12 = "fl.core.ComponentShim"
   $string13 = "toString"
   $string14 = "_group"
   $string15 = "addRadioButton"
   $string16 = "inCallLaterPhase"
   $string17 = "oldMouseState"
condition:
   17 of them
}
rule bleedinglife2_jar2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit Detection"
   hash0 = "2bc0619f9a0c483f3fd6bce88148a7ab"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "META-INF/MANIFEST.MFPK"
   $string1 = "RequiredJavaComponent.classPK"
   $string2 = "META-INF/JAVA.SFm"
   $string3 = "RequiredJavaComponent.class"
   $string4 = "META-INF/MANIFEST.MF"
   $string5 = "META-INF/JAVA.DSAPK"
   $string6 = "META-INF/JAVA.SFPK"
   $string7 = "5EVTwkx"
   $string8 = "META-INF/JAVA.DSA3hb"
   $string9 = "y\\Dw -"
condition:
   9 of them
}
rule bleedinglife2_java_2010_0842_exploit : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit Detection"
   hash0 = "b14ee91a3da82f5acc78abd10078752e"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
   $string1 = "ToolsDemo.classPK"
   $string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
   $string3 = "Created-By: 1.6.0_22 (Sun Microsystems Inc.)"
   $string4 = "META-INF/PK"
   $string5 = "ToolsDemo.class"
   $string6 = "META-INF/services/PK"
   $string7 = "ToolsDemoSubClass.classPK"
   $string8 = "META-INF/MANIFEST.MFPK"
   $string9 = "ToolsDemoSubClass.classeN"
condition:
   9 of them
}
