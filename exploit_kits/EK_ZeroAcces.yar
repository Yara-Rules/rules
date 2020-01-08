rule zeroaccess_css : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "4944324bad3b020618444ee131dce3d0"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "close-mail{right:130px "
   $string1 = "ccc;box-shadow:0 0 5px 1px "
   $string2 = "757575;border-bottom:1px solid "
   $string3 = "777;height:1.8em;line-height:1.9em;display:block;float:left;padding:1px 15px;margin:0;text-shadow:-1"
   $string4 = "C4C4C4;}"
   $string5 = "999;-webkit-box-shadow:0 0 3px "
   $string6 = "header div.service-links ul{display:inline;margin:10px 0 0;}"
   $string7 = "t div h2.title{padding:0;margin:0;}.box5-condition-news h2.pane-title{display:block;margin:0 0 9px;p"
   $string8 = "footer div.comp-info p{color:"
   $string9 = "pcmi-listing-center .full-page-listing{width:490px;}"
   $string10 = "pcmi-content-top .photo img,"
   $string11 = "333;}div.tfw-header a var{display:inline-block;margin:0;line-height:20px;height:20px;width:120px;bac"
   $string12 = "ay:none;text-decoration:none;outline:none;padding:4px;text-align:center;font-size:9px;color:"
   $string13 = "333;}body.page-videoplayer div"
   $string14 = "373737;position:relative;}body.node-type-video div"
   $string15 = "pcmi-content-sidebara,.page-error-page "
   $string16 = "fff;text-decoration:none;}"
   $string17 = "qtabs-list li a,"
   $string18 = "cdn2.dailyrx.com"
condition:
   18 of them
}
rule zeroaccess_css2 : EK css
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "e300d6a36b9bfc3389f64021e78b1503"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "er div.panel-hide{display:block;position:absolute;z-index:200;margin-top:-1.5em;}div.panel-pane div."
   $string1 = "ve.gif) right center no-repeat;}div.ctools-ajaxing{float:left;width:18px;background:url(http://cdn3."
   $string2 = "cdn2.dailyrx.com"
   $string3 = "efefef;margin:5px 0 5px 0;}"
   $string4 = "node{margin:0;padding:0;}div.panel-pane div.feed a{float:right;}"
   $string5 = ":0 5px 0 0;float:left;}div.tweets-pulled-listing div.tweet-authorphoto img{max-height:40px;max-width"
   $string6 = "i a{color:"
   $string7 = ":bold;}div.tweets-pulled-listing .tweet-time a{color:silver;}div.tweets-pulled-listing  div.tweet-di"
   $string8 = "div.panel-pane div.admin-links{font-size:xx-small;margin-right:1em;}div.panel-pane div.admin-links l"
   $string9 = "div.tweets-pulled-listing ul{list-style:none;}div.tweets-pulled-listing div.tweet-authorphoto{margin"
   $string10 = "FFFFDD none repeat scroll 0 0;border:1px solid "
   $string11 = "vider{clear:left;border-bottom:1px solid "
condition:
   11 of them
}
rule zeroaccess_htm : EK html
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "0e7d72749b60c8f05d4ff40da7e0e937"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "screen.height:"
   $string1 = "</script></head><body onload"
   $string2 = "Fx0ZAQRKXUVgbh0qNDRJVxYwGg4tGh8aHQoAVQQSNyo0NElXFjAaDi0NFQYESl1FBBNnTFoSPiBmADwnPTQxPSdKWUUEE2UcGR0z"
   $string3 = "0);-10<b"
   $string4 = "function fl(){var a"
   $string5 = "0);else if(navigator.mimeTypes"
   $string6 = ");b.href"
   $string7 = "/presults.jsp"
   $string8 = "128.164.107.221"
   $string9 = ")[0].clientWidth"
   $string10 = "presults.jsp"
   $string11 = ":escape(c),e"
   $string12 = "navigator.plugins.length)navigator.plugins["
   $string13 = "window;d"
   $string14 = "gr(),j"
   $string15 = "VIEWPORT"
   $string16 = "FQV2D0ZAH1VGDxgZVg9COwYCAwkcTzAcBxscBFoKAAMHUFVuWF5EVVYVdVtUR18bA1QdAU8HQjgeUFYeAEZ4SBEcEk1FTxsdUlVA"
condition:
   16 of them
}
rule zeroaccess_js : EK js
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "a9f30483a197cfdc65b4a70b8eb738ab"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "Square ad tag  (tile"
   $string1 = "  adRandNum "
   $string2 = " cellspacing"
   $string3 = "\\n//-->\\n</script>"
   $string4 = "format"
   $string5 = "//-->' "
   $string6 = "2287974446"
   $string7 = "NoScrBeg "
   $string8 = "-- start adblade -->' "
   $string9 = "3427054556"
   $string10 = "        while (i >"
   $string11 = "return '<table width"
   $string12 = "</scr' "
   $string13 = " s.substring(0, i"
   $string14 = " /></a></noscript>' "
   $string15 = "    else { isEmail "
   $string16 = ").submit();"
   $string17 = " border"
   $string18 = "pub-8301011321395982"
condition:
   18 of them
}
rule zeroaccess_js2 : EK js
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "b5fda04856b98c254d33548cc1c1216c"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "ApiClientConfig"
   $string1 = "function/.test(pa.toString())"
   $string2 = "background-image:url(http:\\/\\/static.ak.fbcdn.net\\/rsrc.php\\/v2\\/y6\\/x\\/s816eWC-2sl.gif)}"
   $string3 = "Music.init"
   $string4 = "',header:'bool',recommendations:'bool',site:'hostname'},create_event_button:{},degrees:{href:'url'},"
   $string5 = "cca6477272fc5cb805f85a84f20fca1d"
   $string6 = "document.createElement('form');c.action"
   $string7 = "javascript:false"
   $string8 = "s.onMessage){j.error('An instance without whenReady or onMessage makes no sense');throw new Error('A"
   $string9 = "NaN;}else h"
   $string10 = "sprintf"
   $string11 = "window,j"
   $string12 = "o.getUserID(),da"
   $string13 = "FB.Runtime.getLoginStatus();if(b"
   $string14 = ")');k.toString"
   $string15 = "rovide('XFBML.Send',{Dimensions:{width:80,height:25}});"
   $string16 = "{log:i};e.exports"
   $string17 = "a;FB.api('/fql','GET',f,function(g){if(g.error){ES5(ES5('Object','keys',false,b),'forEach',true,func"
   $string18 = "true;}}var ia"
condition:
   18 of them
}
rule zeroaccess_js3 : EK js
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "5f13fdfb53a3e60e93d7d1d7bbecff4f"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "document.createDocumentFragment();img.src"
   $string1 = "typeOf(events)"
   $string2 = "var i,x,y,ARRcookies"
   $string3 = "callbacks.length;j<l;j"
   $string4 = "encodeURIComponent(value);if(options.domain)value"
   $string5 = "event,HG.components.get('windowEvent_'"
   $string6 = "'read'in Cookie){return Cookie.read(c_name);}"
   $string7 = "item;},get:function(name,def){return HG.components.exists(name)"
   $string8 = "){window.addEvent(windowEvents[i],function(){var callbacks"
   $string9 = "reunload:function(callback){HG.events.add('beforeunload',callback);},add:function(event,callback){HG"
   $string10 = "name){if(HG.components.exists(name)){delete HG.componentList[name];}}},util:{uuid:function(){return'"
   $string11 = "window.HG"
   $string12 = "x.replace(/"
   $string13 = "encodeURIComponent(this.attr[key]));}"
   $string14 = "options.domain;if(options.path)value"
   $string15 = "this.page_sid;this.attr.user_sid"
condition:
   15 of them
}
rule zeroaccess_js4 : EK js
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "ZeroAccess Exploit Kit Detection"
   hash0 = "268ae96254e423e9d670ebe172d1a444"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = ").join("
   $string1 = "JSON.stringify:function(o){if(o"
   $string2 = "){try{var a"
   $string3 = ");return $.jqotecache[i]"
   $string4 = "o.getUTCFullYear(),hours"
   $string5 = "seconds"
   $string6 = "')');};$.secureEvalJSON"
   $string7 = "isFinite(n);},secondsToTime:function(sec_numb){sec_numb"
   $string8 = "')');}else{throw new SyntaxError('Error parsing JSON, source is not valid.');}};$.quoteString"
   $string9 = "o[name];var ret"
   $string10 = "a[m].substr(2)"
   $string11 = ");if(d){return true;}}}catch(e){return false;}}"
   $string12 = "a.length;m<k;m"
   $string13 = "if(parentClasses.length"
   $string14 = "o.getUTCHours(),minutes"
   $string15 = "$.jqote(e,d,t),$$"
   $string16 = "q.test(x)){e"
   $string17 = "{};HGWidget.creator"
condition:
   17 of them
}
