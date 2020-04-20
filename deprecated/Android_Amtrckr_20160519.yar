/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"
// More info: http://amtrckr.info/
// Last update: 2016/05/19 - 10:00:02


rule coudw: amtrckr
{
	meta:
		family = "coudw"

	condition:
		androguard.url(/s\.cloudsota\.com/)
}

rule z3core: amtrckr
{
	meta:
		family = "z3core"

	condition:
		androguard.url(/lexsmilefux\.link/)
}

rule gtalocker: amtrckr
{
	meta:
		family = "gtalocker"

	condition:
		androguard.url(/niktoegoneyznaet0kol\.pw/)
}

rule marcher: amtrckr
{
	meta:
		family = "marcher"

	condition:
		androguard.url(/104\.238\.176\.9/) or 
		androguard.url(/golioni\.tk/) or 
		androguard.url(/poloclubs\.tk/) or 
		androguard.url(/thejcb\.ru/) or 
		androguard.url(/shgt\.tk/) or 
		androguard.url(/pologt\.tk/) or 
		androguard.url(/108\.61\.211\.219/) or 
		androguard.url(/vipcoon\.com/) or 
		androguard.url(/firenzonne\.com/) or 
		androguard.url(/extgta\.tk/) or 
		androguard.url(/manaclubs\.tk/) or 
		androguard.url(/151\.248\.126\.183/) or 
		androguard.url(/188\.209\.49\.198/)
}

rule lenovo_reaper: amtrckr
{
	meta:
		family = "lenovo_reaper"

	condition:
		androguard.url(/uefsr\.lenovomm\.com/)
}

rule unknown_1: amtrckr
{
	meta:
		family = "unknown"

	condition:
		androguard.url(/222\.76\.213\.20/) or 
		androguard.url(/103\.38\.42\.236/) or 
		androguard.url(/103\.243\.181\.41/) or 
		androguard.url(/123\.1\.157\.4/)
}

rule jagonca: amtrckr
{
	meta:
		family = "jagonca"

	condition:
		androguard.url(/abra-k0dabra\.com/) or 
		androguard.url(/heibe-titten\.com/)
}

rule thoughtcrime: amtrckr
{
	meta:
		family = "thoughtcrime"

	condition:
		androguard.url(/losbalonazos\.com/) or 
		androguard.url(/www\.oguhtell\.ch/) or 
		androguard.url(/szaivert-numis\.at/) or 
		androguard.url(/edda-mally\.at/) or 
		androguard.url(/clubk-ginza\.net/)
}

rule slocker: amtrckr
{
	meta:
		family = "slocker"

	condition:
		androguard.url(/aerofigg\.org/)
}

rule infostealer: amtrckr
{
	meta:
		family = "infostealer"

	condition:
		androguard.url(/koko02\.ru/)
}

rule pornlocker: amtrckr
{
	meta:
		family = "pornlocker"

	condition:
		androguard.url(/playmarketcheck\.com/) or 
		androguard.url(/pornigy\.biz/)
}

rule droidian: amtrckr
{
	meta:
		family = "droidian"

	condition:
		androguard.url(/z0\.tkurd\.net/)
}

rule androrat: amtrckr
{
	meta:
		family = "androrat"

	condition:
		androguard.url(/toyman6699\.no-ip\.info/) or 
		androguard.url(/aerror\.no-ip\.biz/) or 
		androguard.url(/androrat\.servegame\.com/) or 
		androguard.url(/197\.35\.22\.37/) or 
		androguard.url(/androrat1\.no-ip\.biz/) or 
		androguard.url(/151\.72\.17\.61/) or 
		androguard.url(/qwerty1212\.ddns\.net/) or 
		androguard.url(/recycled\.no-ip\.org/) or 
		androguard.url(/gert44\.duckdns\.org/) or 
		androguard.url(/78\.169\.63\.163/) or 
		androguard.url(/hash0r\.no-ip\.biz/) or 
		androguard.url(/alpheron\.duckdns\.org/) or 
		androguard.url(/cricbot\.no-ip\.info/) or 
		androguard.url(/hazhar77\.no-ip\.biz/) or 
		androguard.url(/aleem\.top7@gmail\.com/) or 
		androguard.url(/murryapplicazione\.no-ip\.org/) or 
		androguard.url(/helloandroid\.no-ip\.org/) or 
		androguard.url(/79\.170\.54\.154/) or 
		androguard.url(/mohammad2002\.no-ip\.biz/) or 
		androguard.url(/1756mostacc\.ddns\.net/) or 
		androguard.url(/shakaky\.ddns\.net/) or 
		androguard.url(/asadhashmi\.ddns\.net/) or 
		androguard.url(/174\.127\.99\.232/) or 
		androguard.url(/109\.95\.56\.22/) or 
		androguard.url(/dagohack\.no-ip\.me/) or 
		androguard.url(/pruebasernesto\.ddns\.net/) or 
		androguard.url(/zola123\.no-ip\.biz/) or 
		androguard.url(/mikestar\.no-ip\.biz/) or 
		androguard.url(/132\.72\.81\.164/) or 
		androguard.url(/zongkahani\.no-ip\.biz/) or 
		androguard.url(/florian-pc\.ksueyuj0mtxpt6gn\.myfritz\.net/) or 
		androguard.url(/kontolanime\.no-ip\.biz/) or 
		androguard.url(/41\.143\.69\.230/) or 
		androguard.url(/gentel901\.no-ip\.org/) or 
		androguard.url(/anonimousdre180\.ddns\.net/) or 
		androguard.url(/sajadianh\.ddns\.net/) or 
		androguard.url(/195\.2\.239\.147/) or 
		androguard.url(/vipmustafa\.no-ip\.info/) or 
		androguard.url(/alihoseini\.no-ip\.biz/) or 
		androguard.url(/aymen1852\.ddns\.net/) or 
		androguard.url(/danialmostafaei\.no-ip\.biz/) or 
		androguard.url(/100\.1\.254\.38/) or 
		androguard.url(/sabbah\.duckdns\.org/) or 
		androguard.url(/89\.95\.11\.159/) or 
		androguard.url(/telegram-tools\.no-ip\.biz/) or 
		androguard.url(/myonline\.no-ip\.biz/) or 
		androguard.url(/84\.241\.6\.106/) or 
		androguard.url(/linonymousami\.no-ip\.org/) or 
		androguard.url(/alldebrid\.duckdns\.org/) or 
		androguard.url(/187\.180\.186\.181/) or 
		androguard.url(/411022356/) or 
		androguard.url(/93\.82\.129\.5/) or 
		androguard.url(/androjan\.ddns\.net/) or 
		androguard.url(/adelxxbx\.no-ip\.biz/) or 
		androguard.url(/r3cxw\.ddns\.net/) or 
		androguard.url(/matgio\.duckdns\.org/) or 
		androguard.url(/glaive24\.no-ip\.biz/) or 
		androguard.url(/redcode\.ddns\.net/) or 
		androguard.url(/151\.56\.227\.79/) or 
		androguard.url(/shahabhacker\.ddns\.net/) or 
		androguard.url(/186\.81\.50\.145/) or 
		androguard.url(/kasofe123123aa\.no-ip\.biz/) or 
		androguard.url(/tanha\.sit@gmail\.com/) or 
		androguard.url(/persir\.no-ip\.biz/) or 
		androguard.url(/moha55\.no-ip\.biz/) or 
		androguard.url(/androidupdate\.ddns\.net/) or 
		androguard.url(/charifo1310tok\.no-ip\.biz/) or 
		androguard.url(/securepurpose\.no-ip\.info/) or 
		androguard.url(/vpn0\.ddns\.net/) or 
		androguard.url(/usa20002015\.ddns\.net/) or 
		androguard.url(/duyguseliberkay\.no-ip\.biz/) or 
		androguard.url(/miltin2\.no-ip\.org/) or 
		androguard.url(/droidjack228\.ddns\.net/) or 
		androguard.url(/mjhooollltuuu\.no-ip\.biz/) or 
		androguard.url(/nexmopro830\.ddns\.net/) or 
		androguard.url(/rustyash\.no-ip\.biz/) or 
		androguard.url(/atsizinoglu\.duckdns\.org/) or 
		androguard.url(/goog2\.no-ip\.biz/) or 
		androguard.url(/testan\.ddns\.net/) or 
		androguard.url(/androrat\.zapto\.org/) or 
		androguard.url(/blackghostdc\.duckdns\.org/) or 
		androguard.url(/191\.239\.107\.56/) or 
		androguard.url(/kalinne\.ddns\.net/) or 
		androguard.url(/hackcam\.zapto\.org/) or 
		androguard.url(/andro0161\.no-ip\.info/) or 
		androguard.url(/replace\.duckdns\.org/) or 
		androguard.url(/46\.223\.99\.222/) or 
		androguard.url(/karasqlee9\.no-ip\.org/) or 
		androguard.url(/kalizinho\.no-ip\.org/) or 
		androguard.url(/141\.255\.144\.72/) or 
		androguard.url(/84\.101\.0\.49/) or 
		androguard.url(/msupdate\.myvnc\.com/) or 
		androguard.url(/zal75zk\.ddns\.net/) or 
		androguard.url(/nassahsliman\.ddns\.net/) or 
		androguard.url(/mohsenfaz\.ddns\.net/) or 
		androguard.url(/saiber-far68\.ddns\.net/) or 
		androguard.url(/106\.219\.57\.228/) or 
		androguard.url(/android\.no-ip\.org/) or 
		androguard.url(/161\.202\.108\.108/) or 
		androguard.url(/hamker\.ddns\.net/) or 
		androguard.url(/92\.243\.68\.167/) or 
		androguard.url(/vikas\.no-ip\.biz/) or 
		androguard.url(/68\.189\.1\.254/) or 
		androguard.url(/bmt96\.noip\.me/) or 
		androguard.url(/newxor2\.no-ip\.org/) or 
		androguard.url(/2\.190\.167\.83/) or 
		androguard.url(/hackme\.no-ip\.org/) or 
		androguard.url(/mohammedwasib\.ddns\.net/) or 
		androguard.url(/24\.172\.28\.155/) or 
		androguard.url(/120\.0\.0\.1/) or 
		androguard.url(/simbabweratte\.hopto\.org/) or 
		androguard.url(/androrat143\.no-ip\.biz/) or 
		androguard.url(/222\.168\.1\.2/) or 
		androguard.url(/189\.174\.125\.60/) or 
		androguard.url(/suckmordecock\.duckdns\.org/) or 
		androguard.url(/201\.124\.95\.7/) or 
		androguard.url(/svn-01\.ddns\.net/) or 
		androguard.url(/jNkey\.ddns\.net/) or 
		androguard.url(/131\.117\.235\.35/) or 
		androguard.url(/justarat\.noip\.me/) or 
		androguard.url(/dangerlove\.no-ip\.biz/) or 
		androguard.url(/bahoom\.no-ip\.biz/) or 
		androguard.url(/183\.82\.99\.133/) or 
		androguard.url(/hatam\.no-ip\.org/) or 
		androguard.url(/37\.239\.8\.89/) or 
		androguard.url(/c1\.no-ip\.biz/) or 
		androguard.url(/samy777\.no-ip\.biz/) or 
		androguard.url(/juanblackhak\.ddns\.net/) or 
		androguard.url(/sherlockholmes\.duckdns\.org/) or 
		androguard.url(/martin123456\.no-ip\.org/) or 
		androguard.url(/androratbtas\.no-ip\.info/) or 
		androguard.url(/servidor23\.ddns\.net/) or 
		androguard.url(/xyz2145\.ddns\.net/) or 
		androguard.url(/war10ck\.serveftp\.com/) or 
		androguard.url(/androrat1226\.ddns\.net/) or 
		androguard.url(/anonsa\.ddns\.net/) or 
		androguard.url(/dogecoinspeed\.zapto\.org/) or 
		androguard.url(/61\.131\.121\.195/) or 
		androguard.url(/invisibleghost\.no-ip\.biz/) or 
		androguard.url(/elgen1\.no-ip\.biz/) or 
		androguard.url(/habbo\.no-ip\.org/) or 
		androguard.url(/thekillers\.ddns\.net/) or 
		androguard.url(/94\.212\.118\.115/) or 
		androguard.url(/41\.38\.56\.81/) or 
		androguard.url(/misty255\.no-ip\.org/) or 
		androguard.url(/volnado\.sytes\.net/) or 
		androguard.url(/haiderhacer12\.no-ip\.biz/) or 
		androguard.url(/asosha4ed\.no-ip\.biz/) or 
		androguard.url(/losever2\.no-ip\.biz/) or 
		androguard.url(/80\.136\.103\.51/) or 
		androguard.url(/drrazikhan\.no-ip\.info/) or 
		androguard.url(/makarand\.no-ip\.org/) or 
		androguard.url(/isamdonita\.no-ip\.org/) or 
		androguard.url(/anagliz\.ddns\.net/)
}

rule sandrorat: amtrckr
{
	meta:
		family = "sandrorat"

	condition:
		androguard.url(/tak\.no-ip\.info/) or 
		androguard.url(/maskaralama\.ddns\.net/) or 
		androguard.url(/sondres1\.ddns\.net/) or 
		androguard.url(/toyman6699\.no-ip\.info/) or 
		androguard.url(/appmarket\.servehttp\.com/) or 
		androguard.url(/31\.210\.117\.132/) or 
		androguard.url(/freeann\.sytes\.net/) or 
		androguard.url(/changyu231\.ddns\.net/) or 
		androguard.url(/mohammed22468\.no-ip\.biz/) or 
		androguard.url(/oneriakosa\.ddns\.net/) or 
		androguard.url(/46\.186\.155\.219/) or 
		androguard.url(/jockerhackerxnxx\.ddns\.net/) or 
		androguard.url(/41\.251\.251\.7/) or 
		androguard.url(/megalol\.chickenkiller\.com/) or 
		androguard.url(/188\.166\.76\.144/) or 
		androguard.url(/injectman\.no-ip\.info/) or 
		androguard.url(/aasxzxdsc12324\.no-ip\.biz/) or 
		androguard.url(/magemankoktelam\.ddns\.net/) or 
		androguard.url(/alfazaai99\.ddns\.net/) or 
		androguard.url(/dantehack\.zapto\.org/) or 
		androguard.url(/droidjack1\.sytes\.net/) or 
		androguard.url(/th3expert\.3utilities\.com/) or 
		androguard.url(/mohamed46565656\.no-ip\.biz/) or 
		androguard.url(/chrisfo\.no-ip\.org/) or 
		androguard.url(/hazhar77\.no-ip\.biz/) or 
		androguard.url(/31\.146\.202\.169/) or 
		androguard.url(/njesra\.ddns\.net/) or 
		androguard.url(/yorkiepet\.ddns\.net/) or 
		androguard.url(/mrgnet\.ddns\.net/) or 
		androguard.url(/droy\.zapto\.org/) or 
		androguard.url(/93\.104\.213\.217/) or 
		androguard.url(/amarok58\.no-ip\.biz/) or 
		androguard.url(/server4update\.serveftp\.com/) or 
		androguard.url(/zaliminxx\.duckdns\.org/) or 
		androguard.url(/anonymo9s\.ddns\.net/) or 
		androguard.url(/htmp\.sytes\.net/) or 
		androguard.url(/khalid-2016\.noip\.me/) or 
		androguard.url(/mahasiswa\.no-ip\.biz/) or 
		androguard.url(/mamal9921\.ddns\.net/) or 
		androguard.url(/kaddress\.ddns\.net/) or 
		androguard.url(/sharmayash\.no-ip\.biz/) or 
		androguard.url(/RATForAndroid\.ddns\.net/) or 
		androguard.url(/shabbushah\.duckdns\.org/) or 
		androguard.url(/osammer0asmam3a\.ddns\.net/) or 
		androguard.url(/themayhen23\.no-ip\.org/) or 
		androguard.url(/wxf2009817\.f3322\.net/) or 
		androguard.url(/miioolinase\.ddns\.net/) or 
		androguard.url(/motoshi\.zapto\.org/) or 
		androguard.url(/88\.150\.149\.91/) or 
		androguard.url(/info\.bounceme\.net/) or 
		androguard.url(/samira\.no-ip\.biz/) or 
		androguard.url(/31\.210\.69\.156/) or 
		androguard.url(/93\.79\.212\.194/) or 
		androguard.url(/futurasky\.no-ip\.biz/) or 
		androguard.url(/rat\.capsulelab\.us/) or 
		androguard.url(/fruby\.zapto\.org/) or 
		androguard.url(/iraqn6777\.ddns\.net/) or 
		androguard.url(/samsung\.apps\.linkpc\.net/) or 
		androguard.url(/eldiablo\.no-ip\.biz/) or 
		androguard.url(/system32\.com/) or 
		androguard.url(/haker33sadekgafer\.no-ip\.biz/) or 
		androguard.url(/droidjack258\.bounceme\.net/) or 
		androguard.url(/cardangi\.no-ip\.org/) or 
		androguard.url(/fazoro66\.ddns\.net/) or 
		androguard.url(/androidalbums\.ddns\.net/) or 
		androguard.url(/tedy1993\.ddns\.net/) or 
		androguard.url(/109\.73\.68\.114/) or 
		androguard.url(/alaa-1982\.no-ip\.biz/) or 
		androguard.url(/facrbook\.redirectme\.net/) or 
		androguard.url(/androidan\.ddns\.net/) or 
		androguard.url(/learnxea\.duckdns\.org/) or 
		androguard.url(/audreysaradin\.no-ip\.org/) or 
		androguard.url(/178\.124\.182\.38/) or 
		androguard.url(/mobiles0ft\.no-ip\.org/) or 
		androguard.url(/cybercrysis\.ddns\.net/) or 
		androguard.url(/playstore\.ddns\.net/) or 
		androguard.url(/blind1234\.ddns\.net/) or 
		androguard.url(/chanks\.no-ip\.biz/) or 
		androguard.url(/lomo\.com/) or 
		androguard.url(/ayadd19\.no-ip\.org/) or 
		androguard.url(/bitoandroid\.no-ip\.info/) or 
		androguard.url(/androidtool\.ddns\.net/) or 
		androguard.url(/authd\.ddns\.net/) or 
		androguard.url(/carapuce-2015\.no-ip\.biz/) or 
		androguard.url(/aliyusef6\.no-ip\.biz/) or 
		androguard.url(/bannding\.ddns\.net/) or 
		androguard.url(/momen-swesi\.no-ip\.biz/) or 
		androguard.url(/wogusnb\.no-ip\.info/) or 
		androguard.url(/noussa\.no-ip\.biz/) or 
		androguard.url(/droidjackv5\.ddns\.net/) or 
		androguard.url(/alanbkey\.no-ip\.org/) or 
		androguard.url(/androidrat21\.ddns\.net/) or 
		androguard.url(/diceedicee\.ddns\.net/) or 
		androguard.url(/178\.20\.230\.44/) or 
		androguard.url(/strateg\.ddns\.net/) or 
		androguard.url(/hasn9999\.ddns\.net/) or 
		androguard.url(/anonymousip\.no-ip\.org/) or 
		androguard.url(/fucks\.ddns\.net/) or 
		androguard.url(/shahidsajan\.no-ip\.biz/) or 
		androguard.url(/spicymemes\.duckdns\.org/) or 
		androguard.url(/hackermoqtada\.no-ip\.biz/) or 
		androguard.url(/andro\.no-ip\.biz/) or 
		androguard.url(/goggle\.sytes\.net/) or 
		androguard.url(/anonymous666\.zapto\.org/) or 
		androguard.url(/dnsdynamic\.org/) or 
		androguard.url(/jomo\.zapto\.org/) or 
		androguard.url(/adobflash\.hopto\.org/) or 
		androguard.url(/iqram85spy\.ddns\.net/) or 
		androguard.url(/moussa-hak\.no-ip\.biz/) or 
		androguard.url(/williettinger\.cc/) or 
		androguard.url(/usa2222\.ddns\.net/) or 
		androguard.url(/22134520\.ddns\.net/) or 
		androguard.url(/android1\.ddns\.net/) or 
		androguard.url(/109\.122\.41\.237/) or 
		androguard.url(/droidjack\.hopto\.org/) or 
		androguard.url(/randsnaira\.dnsdynamic\.com/) or 
		androguard.url(/egytiger\.myftp\.org/) or 
		androguard.url(/hehe\.duckdns\.org/) or 
		androguard.url(/seven1\.ddns\.net/) or 
		androguard.url(/younix\.ddns\.net/) or 
		androguard.url(/huntergold\.no-ip\.biz/) or 
		androguard.url(/151\.246\.230\.21/) or 
		androguard.url(/xos1982\.ddns\.net/) or 
		androguard.url(/85\.136\.243\.80/) or 
		androguard.url(/yelp01\.f3322\.org/) or 
		androguard.url(/teolandia\.no-ip\.biz/) or 
		androguard.url(/jokerbabel\.no-ip\.biz/) or 
		androguard.url(/cccamd\.myftp\.biz/) or 
		androguard.url(/109\.165\.69\.25/) or 
		androguard.url(/googles\.servemp3\.com/) or 
		androguard.url(/vb\.blogsyte\.com/) or 
		androguard.url(/karrarhuseein82\.ddns\.net/) or 
		androguard.url(/applecenikosmos\.hldns\.ru/) or 
		androguard.url(/dadadadadaprivet\.ddns\.net/) or 
		androguard.url(/1349874791\.gnway\.cc/) or 
		androguard.url(/bapforall\.ddns\.net/) or 
		androguard.url(/mahamadmahmod\.ddns\.net/) or 
		androguard.url(/nademhack\.no-ip\.org/) or 
		androguard.url(/42\.236\.159\.93/) or 
		androguard.url(/myaw\.no-ip\.biz/) or 
		androguard.url(/msn-web\.ddnsking\.com/) or 
		androguard.url(/draagon\.ddns\.net/) or 
		androguard.url(/winlogen\.duckdns\.org/) or 
		androguard.url(/albash2222\.ddns\.net/) or 
		androguard.url(/82\.223\.31\.121/) or 
		androguard.url(/ahmed2012\.dynu\.com/) or 
		androguard.url(/188\.3\.13\.98/) or 
		androguard.url(/hardik\.no-ip\.info/) or 
		androguard.url(/asdqqq\.bounceme\.net/) or 
		androguard.url(/test\.no-ip\.org/) or 
		androguard.url(/housam\.linkpc\.net/) or 
		androguard.url(/evilcasper\.ddns\.net/) or 
		androguard.url(/kilasx\.ddns\.net/) or 
		androguard.url(/pars\.ddns\.net/) or 
		androguard.url(/noiphackk\.ddns\.net/) or 
		androguard.url(/hack1111\.noip\.me/) or 
		androguard.url(/hackhack2016\.no-ip\.info/) or 
		androguard.url(/haxor\.hopto\.org/) or 
		androguard.url(/zokor-zokor\.ddns\.net/) or 
		androguard.url(/xzoro2016\.no-ip\.info/) or 
		androguard.url(/81\.177\.33\.218/) or 
		androguard.url(/momo2015\.duckdns\.org/) or 
		androguard.url(/pimpdaddy\.myq-see\.com/) or 
		androguard.url(/scropion20078\.no-ip\.biz/) or 
		androguard.url(/106\.51\.163\.232/) or 
		androguard.url(/fuckyou\.duckdns\.org/) or 
		androguard.url(/zakifr\.no-ip\.biz/) or 
		androguard.url(/microsoft-office\.ddns\.net/) or 
		androguard.url(/2\.25\.171\.244/) or 
		androguard.url(/85\.202\.29\.79/) or 
		androguard.url(/mariorossi2013\.homepc\.it/) or 
		androguard.url(/hackcam\.zapto\.org/) or 
		androguard.url(/mokhter222029\.ddns\.net/) or 
		androguard.url(/win32\.ddns\.net/) or 
		androguard.url(/ggwasgeht\.ddns\.net/) or 
		androguard.url(/dexonic\.duckdns\.org/) or 
		androguard.url(/coxiamigo\.myq-see\.com/) or 
		androguard.url(/hamidoranis\.no-ip\.biz/) or 
		androguard.url(/ospr\.publicvm\.com/) or 
		androguard.url(/karasqlee9\.no-ip\.org/) or 
		androguard.url(/hax\.no-ip\.info/) or 
		androguard.url(/haa7aah\.no-ip\.biz/) or 
		androguard.url(/omar\.no-ip\.biz/) or 
		androguard.url(/yuosaf1993\.ddns\.net/) or 
		androguard.url(/88\.164\.37\.97/) or 
		androguard.url(/88\.247\.226\.120/) or 
		androguard.url(/indusv00\.duckdns\.org/) or 
		androguard.url(/andver18\.no-ip\.biz/) or 
		androguard.url(/unknownuser\.no-ip\.biz/) or 
		androguard.url(/nassahsliman\.ddns\.net/) or 
		androguard.url(/gcafegood\.noip\.me/) or 
		androguard.url(/rockrock\.ddns\.net/) or 
		androguard.url(/188\.24\.119\.27/) or 
		androguard.url(/93\.157\.235\.248/) or 
		androguard.url(/komplevit-rat\.ddns\.net/) or 
		androguard.url(/pianotiles2\.ddns\.net/) or 
		androguard.url(/tobytori18\.myftp\.org/) or 
		androguard.url(/105\.106\.49\.154/) or 
		androguard.url(/moonmar10\.no-ip\.biz/) or 
		androguard.url(/100009755836320\.no-ip\.biz/) or 
		androguard.url(/villevalo\.chickenkiller\.com/) or 
		androguard.url(/samoomalik\.no-ip\.biz/) or 
		androguard.url(/foxfeline\.no-ip\.org/) or 
		androguard.url(/kskdt\.ddns\.net/) or 
		androguard.url(/fati43030\.no-ip\.biz/) or 
		androguard.url(/shop10\.ddns\.net/) or 
		androguard.url(/fairylow\.no-ip\.biz/) or 
		androguard.url(/a\.tomx\.xyz/) or 
		androguard.url(/r90\.no-ip\.biz/) or 
		androguard.url(/46\.45\.207\.81/) or 
		androguard.url(/warrirrs\.no-ip\.org/) or 
		androguard.url(/azert123\.ddns\.net/) or 
		androguard.url(/soso\.noip\.us/) or 
		androguard.url(/sniperyakub\.ddns\.net/) or 
		androguard.url(/baby\.webhop\.me/) or 
		androguard.url(/zero228\.ddns\.net/) or 
		androguard.url(/reddemon\.ddns\.net/) or 
		androguard.url(/viagra\.jumpingcrab\.com/) or 
		androguard.url(/domira\.ddns\.net/) or 
		androguard.url(/alkingahmed555\.ddns\.net/) or 
		androguard.url(/mahdi3141\.ddns\.net/) or 
		androguard.url(/somenormalguy\.duckdns\.org/) or 
		androguard.url(/shoo2018\.no-ip\.org/) or 
		androguard.url(/goldeneagle1112\.ddns\.net/) or 
		androguard.url(/hardstyleraver\.no-ip\.org/) or 
		androguard.url(/79\.141\.163\.20/) or 
		androguard.url(/mezoo32\.no-ip\.biz/) or 
		androguard.url(/islam2020libya\.no-ip\.biz/) or 
		androguard.url(/kingdom\.no-ip\.biz/) or 
		androguard.url(/x300x300xx\.no-ip\.org/) or 
		androguard.url(/puplicdsl\.ddns\.net/) or 
		androguard.url(/teda11\.zapto\.org/) or 
		androguard.url(/testsss\.ddns\.net/) or 
		androguard.url(/185\.32\.221\.23/) or 
		androguard.url(/topmax\.myq-see\.com/) or 
		androguard.url(/sarasisi\.no-ip\.org/) or 
		androguard.url(/dodee97dodee\.ddns\.net/) or 
		androguard.url(/kararkarar0780\.ddns\.net/) or 
		androguard.url(/darweshfis\.no-ip\.org/) or 
		androguard.url(/jastn\.ddns\.net/) or 
		androguard.url(/flashplayerxx\.no-ip\.org/) or 
		androguard.url(/thaer\.no-ip\.biz/) or 
		androguard.url(/elisou19\.ddns\.net/) or 
		androguard.url(/dkms\.ddns\.net/) or 
		androguard.url(/aaaa\.com/) or 
		androguard.url(/liquidixen\.ddns\.net/) or 
		androguard.url(/moep004\.no-ip\.org/) or 
		androguard.url(/aaaaaaaaaabbbbb\.hopto\.org/) or 
		androguard.url(/rok13198666\.no-ip\.biz/) or 
		androguard.url(/1337ace\.ddns\.net/) or 
		androguard.url(/droidjack33\.no-ip\.biz/) or 
		androguard.url(/abdouoahmed\.ddns\.net/) or 
		androguard.url(/bambi\.no-ip\.biz/) or 
		androguard.url(/e777kx47\.ddns\.net/) or 
		androguard.url(/shanks\.no-ip\.biz/) or 
		androguard.url(/black1990\.ddns\.net/) or 
		androguard.url(/brave-hacker\.no-ip\.org/) or 
		androguard.url(/ala6a\.no-ip\.biz/) or 
		androguard.url(/sarahwygan\.no-ip\.biz/) or 
		androguard.url(/khantac\.ddns\.net/) or 
		androguard.url(/107\.151\.193\.126/) or 
		androguard.url(/madov-matrix25\.no-ip\.org/) or 
		androguard.url(/93\.185\.151\.217/) or 
		androguard.url(/203\.189\.232\.237/) or 
		androguard.url(/zxczxczxc\.ddns\.net/) or 
		androguard.url(/07726657423zaion\.no-ip\.biz/) or 
		androguard.url(/amran-pc\.no-ip\.biz/) or 
		androguard.url(/myfrenid2x\.zapto\.org/) or 
		androguard.url(/winserver\.dlinkddns\.com/) or 
		androguard.url(/mzgerges\.no-ip\.biz/) or 
		androguard.url(/cjbks0u0\.no-ip\.org/) or 
		androguard.url(/silenthunter3021\.no-ip\.org/) or 
		androguard.url(/engrid\.no-ip\.biz/) or 
		androguard.url(/137\.0\.0\.1/) or 
		androguard.url(/snopi\.no-ip\.biz/) or 
		androguard.url(/hhamokcha\.ddns\.net/) or 
		androguard.url(/clashdroid\.no-ip\.biz/) or 
		androguard.url(/jkgytgasjg12\.serveftp\.com/) or 
		androguard.url(/owsen\.ddns\.net/) or 
		androguard.url(/thegangsterrap\.noip\.me/) or 
		androguard.url(/81\.4\.104\.129/) or 
		androguard.url(/droid\.deutsche-db-bank\.ru/) or 
		androguard.url(/gold5000\.ddns\.net/) or 
		androguard.url(/hassanabd1233\.ddns\.net/) or 
		androguard.url(/love2014\.ddns\.net/) or 
		androguard.url(/bassamzeyad\.ddns\.net/) or 
		androguard.url(/denishul\.hldns\.ru/) or 
		androguard.url(/hacker-81\.no-ip\.biz/) or 
		androguard.url(/noipjajaja\.ddns\.net/) or 
		androguard.url(/41\.38\.56\.81/) or 
		androguard.url(/tataline\.hopto\.org/) or 
		androguard.url(/abedjaradat1177\.no-ip\.org/) or 
		androguard.url(/voda\.no-ip\.org/) or 
		androguard.url(/mohamednjrat111\.no-ip\.biz/) or 
		androguard.url(/hakeerali2\.ddns\.net/) or 
		androguard.url(/5\.189\.137\.186/) or 
		androguard.url(/79\.137\.223\.139/) or 
		androguard.url(/makarand\.no-ip\.org/) or 
		androguard.url(/mehost\.ddns\.net/) or 
		androguard.url(/xmohcine\.ddns\.net/) or 
		androguard.url(/alabama192837\.no-ip\.org/)
}

rule ibanking: amtrckr
{
	meta:
		family = "ibanking"

	condition:
		androguard.url(/www\.irmihan\.ir/) or 
		androguard.url(/emberaer\.com/)
}
