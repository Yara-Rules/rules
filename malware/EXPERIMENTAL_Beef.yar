/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Pasquale Stirparo
	Date: 2015-10-08
	Identifier: src_ptheft
*/

/* Rule Set ----------------------------------------------------------------- */

rule src_ptheft_command : experimental {
	meta:
		description = "Auto-generated rule - file command.js"
		author = "Pasquale Stirparo"
		reference = "not set"
		date = "2015-10-08"
		hash = "49c0e5400068924ff87729d9e1fece19acbfbd628d085f8df47b21519051b7f3"
	strings:
		$s0 = "var lilogo = 'http://content.linkedin.com/etc/designs/linkedin/katy/global/clientlibs/img/logo.png';" fullword wide ascii /* score: '38.00' */
		$s1 = "dark=document.getElementById('darkenScreenObject'); " fullword wide ascii /* score: '21.00' */
		$s2 = "beef.execute(function() {" fullword wide ascii /* score: '21.00' */
		$s3 = "var logo  = 'http://www.youtube.com/yt/brand/media/image/yt-brand-standard-logo-630px.png';" fullword wide ascii /* score: '32.42' */
		$s4 = "description.text('Enter your Apple ID e-mail address and password');" fullword wide ascii /* score: '28.00' */
		$s5 = "sneakydiv.innerHTML= '<div id=\"edge\" '+edgeborder+'><div id=\"window_container\" '+windowborder+ '><div id=\"title_bar\" ' +ti" wide ascii /* score: '28.00' */
		$s6 = "var logo  = 'https://www.yammer.com/favicon.ico';" fullword wide ascii /* score: '27.42' */
		$s7 = "beef.net.send('<%= @command_url %>', <%= @command_id %>, 'answer='+answer);" fullword wide ascii /* score: '26.00' */
		$s8 = "var title = 'Session Timed Out <img src=\"' + lilogo + '\" align=right height=20 width=70 alt=\"LinkedIn\">';" fullword wide ascii /* score: '24.00' */
		$s9 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=20 width=70 alt=\"YouTube\">';" fullword wide ascii /* score: '24.00' */
		$s10 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=24 width=24 alt=\"Yammer\">';" fullword wide ascii /* score: '24.00' */
		$s11 = "var logobox = 'style=\"border:4px #84ACDD solid;border-radius:7px;height:45px;width:45px;background:#ffffff\"';" fullword wide ascii /* score: '21.00' */
		$s12 = "sneakydiv.innerHTML= '<br><img src=\\''+imgr+'\\' width=\\'80px\\' height\\'80px\\' /><h2>Your session has timed out!</h2><p>For" wide ascii /* score: '23.00' */
		$s13 = "inner.append(title, description, user,password);" fullword wide ascii /* score: '23.00' */
		$s14 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s15 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s16 = "answer = document.getElementById('uname').value+':'+document.getElementById('pass').value;" fullword wide ascii /* score: '22.00' */
		$s17 = "password.keydown(function(event) {" fullword wide ascii /* score: '21.01' */
	condition:
		13 of them
}
/*
	This Yara Rule is to be considered as "experimental"
	It reperesents a first attempt to detect BeEF hook function in memory
	It still requires further refinement 

*/

rule BeEF_browser_hooked : experimental  {
	meta:
		description = "Yara rule related to hook.js, BeEF Browser hooking capability"
		author = "Pasquale Stirparo"
		date = "2015-10-07"
		hash1 = "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"
	strings:
		$s0 = "mitb.poisonAnchor" wide ascii
		$s1 = "this.request(this.httpproto" wide ascii
		$s2 = "beef.logger.get_dom_identifier" wide ascii
		$s3 = "return (!!window.opera" wide ascii 
		$s4 = "history.pushState({ Be:\"EF\" }" wide ascii 
		$s5 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/10\\./)" wide ascii 
		$s6 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/11\\./)" wide ascii 
		$s7 = "window.navigator.userAgent.match(/Avant TriCore/)" wide ascii 
		$s8 = "window.navigator.userAgent.match(/Iceweasel" wide ascii 
		$s9 = "mitb.sniff(" wide ascii 
		$s10 = "Method XMLHttpRequest.open override" wide ascii 
		$s11 = ".browser.hasWebSocket" wide ascii 
		$s12 = ".mitb.poisonForm" wide ascii 
		$s13 = "resolved=require.resolve(file,cwd||" wide ascii 
		$s14 = "if (document.domain == domain.replace(/(\\r\\n|\\n|\\r)/gm" wide ascii 
		$s15 = "beef.net.request" wide ascii 
		$s16 = "uagent.search(engineOpera)" wide ascii 
		$s17 = "mitb.sniff" wide ascii
		$s18 = "beef.logger.start" wide ascii
	condition:
		all of them
}
