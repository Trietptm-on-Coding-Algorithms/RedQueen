#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import random
import sys
import os
import datetime
from twython import Twython, TwythonError
from TwitterApiKeys import app_key, app_secret, oauth_token, oauth_token_secret
from operator import itemgetter
from pyfiglet import Figlet

#Some Vars

fuck = 0

waithour = 0

currentdate = datetime.datetime.now()

path = "./Tmp/"

TmpDay = str(path) + "Total Api .Call" 

TmpDay2 = str(path) + "Update Status .Call"

TmpMeal = str(path) + "Search Terms .Used"

Session = str(path) + "Current .Session"

noresult = str(path) + "No .Result"

idsaved = str(path) + "Tweets .Sent"

restabit = 0

twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)

Keywords = ["alice bob","un rootkit","linus torvalds","pirate box","template injection","ieee-security.org","internet archive","hacks archive","netcat","rsa securid","windows worm","mac worm","linux worm","lionsec","whonix","sudo ","shmoocon","ethereum","bootkit","backdooring","selling credentials","surveillance platform","Dns reflection amplification","CVE-2016","StressLinux","tomsrtbt","Tiny SliTaz","RIMiRadio","Nuclinux","NASLite","Linux Router Project","HVLinux","HAL91","Freesco","floppyfw","Coyote Linux","xPUD","VectorLinux","Toutankinux","Feather Linux","Embedded Debian","Chromium OS","BunsenLabs","antiX","Zorin OS","Zeroshell","Zenwalk","Zentyal","YunoHost","Ylmf OS","crypto entropy","Xubuntu","Xandros","Xange linux","WinLinux","VidaLinux","Ulteo","TurboLinux","Trustix","Trisquel","Trinux","TopologiLinux","Tiny Core Linux","SteamOS","SolusOS","SME Server","SliTaz GNU","Slax linux","Sabayon Linux","Rxart","ROSA linux","Puppy Linux","PrimTux","rom hack","Platypux","PinguyOS","Pardus","Parabola GNU","NuTyX","NUbuntu","Netrunner OS","Musix GNU","Maemo","MEPIS","Lunar Linux","Lubuntu","Linux Mint","Linux From Scratch","Linux xp","LinuxConsole","play on linux","linux wine","linux ps2","Linutop OS","Linspire","Kubuntu","Kororaa","Knoppix","Kanotix","KaOS linux","Kali linux","Kaella","IPCop","Hybryde Linux","HandyLinux","GoboLinux","Goblinx","Gnoppix","gNewSense","GeeXboX","Funtoo","Frugalware","Freespire","Freesco","Free-EOS","Foresight Linux","Flonix","fli4l","Elive","elementary OS","EduLinux","Edubuntu","DoudouLinux","Dreamlinux","Dragora GNU","DidJiX","Demudi Linux","Damn Vulnerable Linux","Damn Small Linux","Cubuntu","CrunchBang","Coyote Linux","Chakra","CentOS","Castle Linux","Calculate Linux","Caixa Mágica","CAELinux","BLAG 140","Bodhi Linux","BasicLinux","Baltix","BackTrack","Aurox","Aurox Live","Augustux","ASRI Edu","Asianux","Ark Linux","ArchBang","Aptosid","APODIO","Peanut Linux","CLinuxOS","PCLinuxOS","Mageia","Mandriva","Manjaro","openSUSE","Arch Linux","SUSE","Slackware","fedora","SSNs","gentoo","LSASS","bettercap","chiffrement","xml injection","method handles","alphabay","Java message service","netsec","server down","net neutrality","freebsd","debian","script-based","bugtrack","atilla.org","HackQuest.com","h@x0r","slyfx","cyberarmy","mod-x.co.uk","alph4net.free.fr","cyberjihad","globalsecuritymag.fr","Instant-Hack","dothazard.com","intrusio.fr","Tobozo","n-pn.fr","Ensimag hacking team","febel.fr","zataz","chan irc hack","forum de hack","hackateam.com","0x0ff.info","nuit du hack","hackademics","Honeynet","hackers convention","hacker contest","hacking contest","United Hackers Army","CTFTIME","EXPLOIT EXERCISES","pwn0.com","pwn0bots","REVERSING.KR","MICROCORRUPTION","SMASHTHESTACK","netgarage.org","pwnable.kr","OVERTHEWIRE","CTF365","hackerearth.com","seclists.org","the-hackfest.com","ctftime.org","itknowledgeexchange","hackingchinese.com","hacking-lab.com","insomnihack.ch","amanhardikar.com","dragonhacks.io","bases-hacking.org","www.trythis0ne.com","hackbbs.org","pen-testing.sans.org","codeforamerica.org","onecoincloud.eu","wechall.net","holidayhackchallenge.com","tunnelsup.com","root-me.org","canyouhack.it","2600","canyouhack.us","SlaveHack","Ethical Hacker Network","HellBound Hackers","devops","webgoat","Vicnum","The Butterfly Security Project","Security Shepherd","Mutillidae","McAfee HacMe","InsecureWebApp","igoat","Google Gruyere","Game of Hacks","exploitme","DVWA","Untrusted input","broken crypto","server side","Client Side Injection","Runtime Manipulation","Jailbreak Detection","third party libraries","Extension Vulnerabilities","DVIA","bWAPP","OWASP Bricks","EnigmaGroup","Moth","BodgeIt Store","keygen","haxor","Hackxor","HackThis!!","SlaveHack","Try2Hack","Highly Efficient Low Level Code","cloud hack","Hack Yourself First","Micro Contest","LOST Chall","Newbie Contest","Rankk","Hacker.org","Mibs Challenges","Hack This Site","Net Force","BrainQuest","InfoMirmo","Yashira","W3Challs","Root Me","Le Big Challenge","alphanet","Fatetek Challenges","Mod x","Hax.Tor","Bright Shadows","Dare Your Mind","RingZero Team","Mudge","Boris Floricic","Anakata","Richard Stallman","Dmitry Sklyarov","Roman Seleznev","Oxblood Ruffin","Leonard Rose","DilDog","Kevin Poulsen","homebrew","Knight Lightning","Dennis Moran","Robert Tappan Morris","Hector Monsegur","Gary Mckinnon","Fyodor hacker","Lord Digital","hagbard","Joybubbles","geohot","Acidus","Guccifer","nag screen","Bruce Fancher","Nahshon Even-Chaim","John Draper","Captain Crunch","RBCP","Loyd Blankenship","The Mentor","Mendax","Tflow","ioerror","Kayla","Phiber Optik","internet underground","linux underground","mac underground","Xbox Underground","YIPL","UGNazi","The Unknowns hack","Teso","TeslaTeam","RedHack","RedHack","PHIRM","NCPH","milw0rm","Masters of Deception","Mazafaka","Legion of Doom","Lizard Squad,","Level Seven","L0pht","Honker Union","Hackweiser","goatsec","globalHell","Equation Group","Global kOS","DawgPound","DERP","Decocidio","CyberVor","Dark0de","Cult of the Dead Cow","Croatian Revolution Hackers","Cicada 3301,","Chaos Computer Club","FinnSec Security","414s","Group5","netscape","pwnie awards","security researcher","BHUSA","pgp","encrypted mail","secure mail server","vBulletin","Apache Tomcat","Coldfusion","ASP.NET","Retina Report","Nessus Scan Report","SnortSnarf","mirc","LOGREP","Apache::Status","SQLiteManager","Tobias Oetiker","sets mode","wwwstat","Generated by phpSystem","mysql dump","phpWebMail","gnatsweb.pl","webedit","inurl:/","cgi-bin","Citrix","CVE","alice bot","sea hacker","chatter bot","automagically","Syrian Electronic Army","LulzSec","gray hat","Distributed denial of service","Denial of service","compiler","hook cheat","TWEAK cheat","trainer cheat","entropy","DAEMON","CRLF","COMM MODE","CANONICAL","Ethical Hacking","Skidz","ascii art","blue hat ","defaced","Dictionary Attack","doxing","DOX","FUD","Fully undetectable","grey hat","IP Grabbing","backorifice","LOIC anonymous","Rainbow Table","rat trojan","Remote Administration Tool","ring3","ring2","ring0","viri","warez","vps","worm malware","turing test","sysadmin","SaaS","stack buffer overflow","CA cert","Hardware vulnerability","physical backdoor","Vuln:","Vuln","adblocker","Exploit framework","crypto party","ssh","Passphrase","Linux Distro","RFC","Hardcoded","hackintosh","Os X","P2P","cloud-based","Oracle java","IT guy","Encrypted Chat","VmWare","cyber police","AdGholas","malvertising","hadopi","cnil","golang","hacked by","piratage","Postgresql","Julian Assange","DNC","GNU","QRLJacking","kevin mitnick","csrf exploit","session hijack","darkweb",".onion","wikileaks","wlan","Wireless Local Area Network","wardriving","Wireless Access Point","wep","cyber security","Wpa2","blackhat","Shellcode","vpn","Virtual Machine","sandboxing","crypto currency","Full Disclosure","Tunneling","Gps spoofing","untrusted Certificate","ransomware","Trojan Horse","Transport Layer Security","Triple DES","Assembly language","Real hack","real programmmer","RFC","crack me","hack me","true hacker","security traffic Analysis","Tracking Cookie","tampered data","bluetooth crack","data breach","script kiddie","brute force","Symmetric Key","Surrogate Access","Raspberry pi","Arduino","Steganography","Spyware","mail bombing","jailbreak","YesCard","Skimming","Phreaking","cracking","malloc","data Sensitivity","Python exploit","ruby hack","security kernel","C++ exploit","reverse Engineering","Security Engineering","turbo pascal","ssl","hacking tool","php vulnerability","hackervoice","worms variant","DNS","Scatternet","cheval de troie","javascript exploit","Sandboxing","Rootkit","Bash script","windbg","rogue device","ollydbg","assembler code","ip spoofing","Rijndael","apache vulnerability","darkdao","repository","shodan","scammers","critical vulnerability","code injection","ICBM address","RFID security","paiement sans contact","RFID protocol","Radio Frequency Identification","Gbd ida","private key","pseudorandom","Proxy Agent","tor network","vpn open source","memory corruption","proxy list","proxychain","la quadrature du net","heap exploitation","stack cookies","Fuzzing","integer overflow","hackathon","api key","1337","Social-Engeneering Toolkit","port scanner","bluetooth protocol","bluetooth security","nmap","port scanning","Payload","Framework","port knocking","wireless attack","log files","router vulnerability","packet sniffer","phpmyadmin hack","open source","phbb hack","password attack","penetration technique","browser exploit","warberrypi ","wordpress exploit","binary memory","byod","router exploit","Cookie stuffing","Windows stack overflow","shell exploit","message digest","Cryptosystem","reverse shell","MitM","hardware keylogger","malicious code","hack team","mygot","myg0t","data intercept","ipcam hack","meterpreter","segfault","pastejacking","network takeover","Sphear phishing","key logger","key escrow","Kerberos","flood attack","infinite loop","depassement de tampon","irc hack","ipsec","exec","system intrusion","ipv6","ipv4","Fake update","packet injection","bruteforcer","android vulnerability","linux vulnerability","ios vulnerability","artificial intelligence","windows vulnerability","main loop","hello world","audit tool","armitage","grep","disk encryption","frequency hopping","forward cipher","shitware","Firefox vulnerability","bypass firewall","file encryption","ssl tls","extranet","domaine name permutation","ftp security","fingerprint tool","rssi","visual analysis tool","end to end encryption","robots.txt","encrypted network","tinfoleak","infosec","encoding","voip security","EOF","electronic signature","egress filtering","eavesdropping","DEADBEEF","konami code","dmz","wireless scanner","decrypt","@th3j3st3r","wireless hack","data security","data integrity","network mapper","data encryption standard","data dump","incident response tool","defcon","cyber attack","web spider","cryptology","hash function","cryptographic","cryptanalysis","command injection","tool assisted speedrun","credential","cover coding","xref","key generation","network exploitation","network attack","local pentest","COMSEC","CVS","common vulnerabilities","internet of things","misconfiguration","collision hash","internet of shit","cloud computing","clear text","Xor","checksum","bytes","joomla vulnerability","sqli","data leak","users passwords","blackbox hack","IRC network","Critical patch","playstation jailbreak","banner grabbing","xbox jailbreak","backdoor infosec","hexadecimal","privacy windows","authentication token","authentication protocol","audit framework","open source security tool","file signature","BSides","antispyware","chelsea manning","QR code infosec","anonymous","advanced persistent threats","pirate bay","advanced encryption standard","admin account","add-on security","ad hoc network","hacked site","defaced","bypass login","cryptography","phishing infosec","honeypot","hacking","ddos","malware","rfid","patch flaw","SocialEngineering","0day","cross site scripting","cyber security","install backdoor","forensic","blind sql injection","local file inclusion","privilege escalation","hacker attack","request forgery","metasploit","password","sql injection","privilege elevation","drupal vulnerability","chinese hacker","penetration testing","header injection","pentest","man in the middle","man in the browser","remote access","java security","buffer overflow","keylog","nuke script","darknet","russian hacker","remote exploit","israel hack","ransomware","trojan","botnet","snowden","nsa","blackhat","whitehat","hacktivist","printer exploit"]

random.shuffle(Keywords)

Following = ['CUSecTech', 'InfoSecHotSpot', 'IndieRadioPlay', 'TopMaths', 'ergn_yldrm', 'MegalopolisToys', 'ISC2_Las_Vegas', 'jeffreycady', 'XenDesktop', 'BugBountyZone', 'sciendus', 'Dambermont', 'ghwizuuy', 'hackmiami', 'smirnovvahtang', 'uncl3dumby', 'theStump3r', 'SecureAuth', 'StagesInfograph', '9gnews365', 'secmo0on', 'alexheid', 'XenApp', 'vleescha1', 'CMDSP', 'abouham92597469', 'NetNeutralityTp', 'puja_mano', 'AliSniffer', 'DrupalTopNews', 'ChromeExtenNews', 'sebastien_i', 'Techworm_in', 'argevise', 'windows10apps4r', 'primeroinfotek', 'HAKTUTS', 'ciderpunx', 'kfalconspb', 'whitehatsec', 'furiousinfosec', 'Trencube_GD', 'CtrlSec', 'hacking_report', 'n0psl', 'CryptoKeeUK', '0xDUDE', 'crowd42', '_HarmO_', 'CNNum', 'OxHaK', 'Paddy2Paris', 'RevueduDigital', 'androidapps4rea', 'cryptoland', 'CombustibleAsso', 'geeknik', 'HansAmeel', 'cryptoishard', 'YoouKube', 'jouermoinscher', 'moixsec', 'cyberwar', 'danielbarger67', 'SecurityNewsbot', 'cityofcrows', 'SysAdm_Podcast', 'shafpatel', 'k4linux', 'Refuse_To_Fight', 'x_adn', 'Duffray14', 'AbdelahAbidi', 'pranyny', 'razlivintz', 'unmanarc', 'wallarm', 'foxooAnglet', 'foxoo64', 'brainhackerzz', 'duo_labs', 'zenterasystems', 'jilles_com', 'partyveta760', 'ComixToonFr', 'doaa90429042', 'bestvpnz', 'aebay', 'suigyodo', 'parismonitoring', 'menattitude', 'BretPh0t0n', 'ChariseWidmer', 'racheljamespi', 'ZeNewsLink', 'Omerta_Infosec', '_plesna', 'LawsonChaseJobs', 'fredericpoullet', 'RogersFR', 'jesuiscandice7', 'jeanneG50', 'CryptoXSL', 'maccimum', 'foxtrotfourwbm', 'fido_66', 'AGveille', 'InfoManip', 'HiroProtag', 'jhosley', 'Netmonker', 'tetaneutralnet', 'DefiLocacite', 'MTCyberStaffing', 'thecap59', 'Max1meN1colella', 'CharlesCohle', 'BrianInBoulder', 'ArsneDAndrsy', 'BullFR', 'Five_Star_Tech', 'pourconvaincre', 'Be_HMan', 'click2livefr', 'ElydeTravieso', 'n0rssec', '_fixme', 'infographisteF', 'zephilou', 'puneeth_sword', 'CheapestLock', 'Eprocom', 'LocksmithNearMe', 'YoshiDesBois', 'databreachlaws', 'LDarcam', '_CLX', 'dreadlokeur', '_sinn3r', 'operat0r', 'Moutonnoireu', 'MatToufoutu', 'mubix', 'abcdelasecurite', 'meikk', 'MadDelphi', 'ec_mtl', 'unixist', 'EricSeversonSec', 'slaivyn', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'cabusar', 'julien_c', 'moswaa', 'lycia_galland', 'YrB1rd', 'DogecoinFR', 'corkami', 'Barbayellow', 'Spiceworks', 'dt_secuinfo', 'Yaagneshwaran', 'btreguier', 'TheStupidmonKey', 'follc', '2xyo', 'crazyjunkie1', 'LeCapsLock', 'gizmhail', 'piscessignature', 'JamiesonBecker', '_SaxX_', 'isgroupsrl', 'NuitInfo2K13', 'yenos', 'SecurityTube', 'Gameroverdoses', 'Brihx_', 'silvakreuz', 'DamaneDz', '_bratik', 'vprly', 'didierdeth', 'sudophantom', 'xxradar', 'Techno_Trick', 'malphx', 'wixiweb', 'ChrisGeekWorld', 'AmauryBlaha', 'LRCyber', 'FranckAtDell', 'netrusion', 'ubuntuparty', 'grokFD', 'CISOtech', 'NotifyrInc', 'marcotietz', 'accident', 'darthvadersaber', 'VForNICT', 'ID_Booster', 'yw720', 'AgenceWebEffect', 'JeanLoopUltime', 'guideoss', 'Security_FAQs', 'Oursfriteorchid', 'Gr3gland', 'caaptusss', 'ygini', 'videolikeart', 'Veracode', 'CyberExaminer', 'hackademics_', 'razopbaltaga', 'eric_kavanagh', 'Ikoula', 'LeBlogDuHacker', 'rexperski', 'MathieuAnard', 'ced117', 'Panoptinet', 'BuzzRogers', 'ITSecurityWatch', 'PatchMob', 'officialmcafee', 'hnshah', 'AnonLegionTV', 'sh1rleysm1th', 'soocurious', 'PremiereFR', 'mob4hire', 'ericosx', 'yesecurity', 'DLSPCDoctor', 'tyrus_', 'gritsicon', 'trollMasque', 'AmauryPi', 'OpenForceMaroc', 'CybersimpleSec', 'PorterHick', 'AllTechieNews', 'revvome', 'livbrunet', 'aeris22', 'InfoSecMash', 'gigicristiani', 'stephanekoch', 'leduc_louis', 'ilhamnoorhabibi', 'servermanagedit', 'GTAFRANCE', '1humanvoice', 'stmanfr', 'Current_Tech', 'PEGE_french', 'Kuzbari', 'iisp_hk', 'Facebook_Agent', 'ZeroSkewl', 'chuckdauer', 'Itsuugo', 'Florianothnin', 'neeuQdeR', 'HYCONIQ', 'disk_91', 'ZOOM_BOX_r', 'Rimiologist', 'Matrixinfologic', 'GeneralSeven', 'preventiasvcs', 'atmon3r', 'filowme', 'FcsFcsbasif', 'catalyst', 'Spawnhack', 'globalwifiIntl', 'CajunTechie', 'ConstructionFOI', 'k8em0', 'Flavioebiel', 'FlacoDev', 'Fibo', 'wisemedia_', 'floweb', 'adistafrance', 'AnonBig', 'tacticalflex', 'Katezlipoka', 'MathieuZeugma', 'SophiAntipolis', 'matalaz', 'edehusffis', 'patricksarrea', 'SnapAndShine', 'cryptomars', 'OpPinkPower', 'DidierStevens', 'patatatrax', 'AJMoloney', 'cheetahsoul', 'vxheavenorg', 'defconparties', 'gvalc1', 'clemence_robin', 'XeroFR', 'noncetonic', 'bonjour_madame', 'LeWebSelonEdrek', 'robajackson', 'greenee_gr', 'zahiramyas', 'nation_cyber', 'Rio_Beauty_', 'Sadnachar', 'SecRich', 'unbalancedparen', 'Fyyre', 'VirusExperts', 'Applophile', 'Aziz_Satar', 'SecretDefense', 'Hi_T_ch', 'wireheadlance', 'define__tosh__', 'hamsterjoueur', 'PUREMEDIAHDTV', 'secdocs', 'code010101', 'LagunISA', '_theNextdoor_', 'lefredodulub', 'i4ppleTouch', 'imatin_net', 'KiadySam', 'toiletteintime', 'espeule', '1er_degres', 'BSoie', 'Pintochuks', 'selphiewall479', 'ApScience', 'suivi_avec_lisa', 'TiffenJackson', 'SecretGossips', 'sarahMcCartney2', 'wheatley_core', 'PatSebastien']

Friends = ['pondeboard1', 'ceb0t', 'theStump3r', 'uncl3dumby', 'gr3yr0n1n', 'poa_nyc', 'Demos74dx', 'sebastien_i', 'HAKTUTS', 'R00tkitSMM', 'pondeboard', 'AcidRampage', 'IncursioSubter', 'BSeeing', 'evleaks', 'InfoSec_BT', 'HIDGlobal', 'kjhiggins', 'vkamluk', 'codelancer', 'ciderpunx', 'HugoPoi', 'kfalconspb', 'lconstantin', 'coolhardwareLA', 'fsirjean', 'h0x0d', 'RCCyberofficiel', 'Tech_NurseUS', 'whitehatsec', 'oej', 'Trencube_GD', 'cissp_googling', '_pronto_', 'CtrlSec', 'ModusMundi', 'SwiftOnSecurity', 'RichRogersIoT', 'jonathansampson', 'Luiz0x29A', 'StephenHawking8', 'dpmilroy', 'usa_satcom', 'hack3rsca', 'PELISSIERTHALES', 'g00dies4', 'rpsanch', 'furiousinfosec', 'Om_dai33', 'wulfsec', 'securiteIT', 'pavornoc', 'hacking_report', 'primeroinfotek', 'L4Y5_G43Y', 'PaulM', 'seclyst', 'cmpxchg16', 'iainthomson', 'e_modular', '_jtj1333', 'n0psl', 'blaked_84', 'tb2091', 'dfirfpi', 'manonbinet001', 'webmathilde', '0xDUDE', 'nn81', 'CryptoKeeUK', 'n1nj4sec', 'ydklijnsma', 'scanlime', '0x6D6172696F', 'nono2357', 'derekarnold', 'hasherezade', '_HarmO_', 'OxHaK', 'CWICKET', 'linuxaudit', 'Space__Between', 'lordofthelake', 'Hired_FR', 'Laughing_Mantis', 'InfoSecHotSpot', 'geeknik', 'CharlesCohle', 'BretPh0t0n', 'jilles_com', 'duo_labs', 'unmanarc', 'x_adn', 'k4linux', 'shafpatel', 'SysAdm_Podcast', 'Everette', 'DadiCharles', 'danielbarger67', 'quequero', 'SecurityNewsbot', 'cityofcrows', 'Dinosn', 'ibmxforce', 'thepacketrat', 'cryptoishard', 'DEYCrypt', 'attritionorg', 'mzbat', 'da_667', 'krypt3ia', 'Z0vsky', 'BSSI_Conseil', 'SecMash', 'corexpert', 'maldevel', 'pof', 'FFD8FFDB', 'Snowden', 'lexsi', 'bestvpnz', 'EnfanceGachee', 'samykamkar', 'pevma', 'kafeine', 'k0ntax1s', 'gN3mes1s', 'GawkerPhaseZero', 'FreedomHackerr', 'sec_reactions', '0xAX', 'nolimitsecu', 'bascule', 'm3g9tr0n', 'nbs_system', 'sn0wm4k3r', 'jivedev', 'd_olex', 'indiecom', 'BlueCoat', 'Tif0x', 'UnGarage', 'HomeSen', 'CTF365', 'Securityartwork', 'accessnow', 'ZeljkaZorz', 'mortensl', 'ThomasNigro', 'Sidragon1', 'garage4hackers', 'hanno', 'p4r4n0id_il', 'AsymTimeTweeter', 'Omerta_Infosec', 'nopsec', 'cyberguerre', 'Protocole_ZATAZ', 'Grain_a_moudre', 'BIUK_Tech', 'TMZvx', '_plesna', 'PhysicalDrive0', 'rodneyjoffe', 'ithurricanept', 'sec0ps', 'comex', 'deepimpactio', 'ClechLoic', 'AGveille', 'amzben', 'FIC_fr', 'EricSeversonSec', 'MalwarePorn', 'Odieuxconnard', 'unixist', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'pwcrack', 'PhilHagen', 'Falkvinge', 'IPv4Countdown', 'lycia_galland', 'wirehack7', 'linux_motd', 'lamagicien', 'ubuntumongol', '_cypherpunks_', 'TekDefense', 'LeakSourceInfo', 'moswaa', 'OsandaMalith', 'Lope_miauw', 'dt_secuinfo', 'morganhotonnier', 'Relf_PP', 'abcderza', 'Barbayellow', 'corkami', 'KitPloit', 'ec_mtl', 'bugs_collector', 'BleepinComputer', 'Tinolle1955', 'valdesjo77', 'xombra', 'julien_c', 'Spiceworks', 'snipeyhead', 'YrB1rd', 'Trojan7Sec', 'Yaagneshwaran', 'ZATAZWEBTV', 'f8fiv', 'Netmonker', 'epelboin', '0xmchow', 'angealbertini', 'Incapsula_com', 'SurfWatchLabs', 'Exploit4Arab', 'hackerstorm', '2xyo', 'JamiesonBecker', 'NuitInfo2K13', '_SaxX_', 'piscessignature', 'crazyjunkie1', 'SecurityTube', 'comptoirsecu', '_saadk', 'penpyt', 'yenos', 'Intrinsec', 'udgover', 'jujusete', 'poulpita', 'suffert', 'clementd', '_CLX', '_bratik', 'tomchop_', 'vprly', 'mboelen', 'martijn_grooten', 'aristote', 'gandinoc', 'silvakreuz', 'ifontarensky', 'cedricpernet', 'y0m', 'knowckers', 'lakiw', 'didierdeth', 'paulsparrows', 'sudophantom', 'arbornetworks', 'AzzoutY', 'cabusar', 'Xartrick', 'netrusion', 'AmauryBlaha', 'Techno_Trick', 'wixiweb', 'hackhours', 'netbiosX', 'Daniel15', 'Routerpwn', 'asl', 'jeetjaiswal22', 'shoxxdj', 'FranckAtDell', 'ubuntuparty', 'jpgaulier', 'adulau', 'fredraynal', 'shu_tom', 'Cyberprotect', 'LRCyber', 'cymbiozrp', 'bitcoinprice', 'lafibreinfo', 'dreadlokeur', 'YoouKube', 'NotifyrInc', 'olfashdeb', 'MiltonSecurity', 'quota_atypique', 'TNWmicrosoft', 'LLO64', 'davromaniak', 'ID_Booster', 'VForNICT', 'klorydryk', 'vam0810', 'SecurityWeek', 'secludedITaid', 'montrehack', 'cvebot', 'chetfaliszek', 'NeckbeardHacker', 'hipsterhacker', 'AgenceWebEffect', 'marcotietz', 'erwan_lr', 'guideoss', 'sonar_guy', 'notsosecure', 'FlipFlop8bit', 'MalwareAnalyzer', 'yw720', 'SebBLAISOT', 'Cubox_', 'Ninja_S3curity', 'maximemdotnet', 'lea_linux', 'securitypr', '0xUID', 'MargaretZelle', 'Gr3gland', 'steveklabnik', 'iooner', 'caaptusss', 'tuxfreehost', 'ygini', 'Mind4Digital', 'ADNcomm', 'Veracode', 'hackademics_', 'xhark', 'TopHatSec', '0xSeldszar', 'PLXSERT', 'eric_kavanagh', 'IT_securitynews', 'devttyS0', 'Parisot_Nicolas', 'dclauzel', 'SCMagazine', 'JoceStraub', 'HackerfreeUrss', 'dascritch', 'aabaglo', 'ITConnect_fr', 'razopbaltaga', 'cargamax', 'MyOmBox', 'Wobility', 'evdokimovds', 'dookie2000ca', 'nuke_99', 'isgroupsrl', '_fwix_', 'LeBlogDuHacker', 'Ikoula', 'PortableWebId', 'OfficialGirish', 'httphacker', 'ripemeeting', 'ymitsos', 'Solarus0', 'Zestryon', 'ko_pp', 'etribart', 'TomsGuideFR', 'k3170Makan', 'jeeynet', 'qualys', 'KdmsTeam', 'frsilicon', 'astro_luca', 'rexperski', 'spiwit', 'nuclearleb', 'mcherifi', 'laVeilleTechno', 'framasoft', 'NyuSan42', 'nextinpact', 'PirateOrg', 'MathieuAnard', 'blesta', 'IPv6Lab', 'billatnapier', 'starbuck3000', 'jmplanche', 'pbeyssac', 'Keltounet', 'cwolfhugel', 'ZeCoffre', 'Dave_Maynor', 'durand_g', 'TMorocco', 'CyberExaminer', 'PatchMob', 'Nathanael_Mtd', '1nf0s3cpt', 'ospero_', 'ced117', 'LinuxActus', 'Panoptinet', 'schoolofprivacy', 'TrustedSec', 'maccimum', 'hadhoke', 'Jordane_T', 'novogeek', 'ChimeraSecurity', 'officialmcafee', 'GolumModerne', 'milw0rms', 'AsmussenBrandon', 'arnolem', 'Goofy_fr', 'AnonLegionTV', 'infoworld', 'soocurious', 'atarii', 'SebydeBV', 'JacquesBriet', 'ITSecurityWatch', 'SecurityFact', 'dorkitude', 'CISecurity', 'bishopfox', 'jeremieberduck', 'ericosx', 'dimitribest', 'levie', 'andreaglorioso', 'tyrus_', 'DLSPCDoctor', 'guiguiabloc', 'AlainClapaud', 'yesecurity', 'trollMasque', 'planetprobs', 'vincib', 'LeCapsLock', 'kafeinnet', 'Irrodeus', 'jbfavre', 'guestblog', 'rboulle', 'Fr33Tux', 'SecurityHumor', 'creoseclabs', 'm0rphd', 'argevise', 'gritsicon', 'veorq', 'Abdelmalek__', 'OpenForceMaroc', 'hashbreaker', 'AlexandreThbau1', 'MacPlus', 'yrougy', 'MaldicoreAlerts', 'AmauryPi', 'TrendMicroFR', 'sirchamallow', 'ACKFlags', 'jameslyne', 'LaNMaSteR53', 'AllTechieNews', 'garfieldair', 'PorterHick', 'arstechnica', 'sendio', 'CipherLaw', 'Golem_13', 'livbrunet', 'RealMyop', 'KenBogard', 'KarimDebbache', 'SmoothMcGroove', 'AlDeviant', 'Canardpcredac', 'SebRuchet', 'F_Descraques', 'Unul_Officiel', 'Poischich', 'drlakav', 'genma', 'lastlineinc', 'Cryptomeorg', 'CybersimpleSec', 'DarkReading', 'tqbf', 'gyust', 'KanorUbu', 'walane_', 'jedisct1', 'hadopiland', 'all_exploit_db', 'brutelogic_br', 'lechat87', 'gigicristiani', 'aeris22', 'terminalfix', 'ChristophePINO', 'ihackedwhat', 'InfoSecMash', 'bayartb', 'ErrataRob', 'DefuseSec', 'jcsirot', 'christiaan008', 'gopigoppu', 'lawmanjapan', 'RichardJWood', 'darthvadersaber', 'BryanAlexander', 'leduc_louis', 'distriforce', 'democraticaudit', 'PaulChaloner', 'kentbye', 'HacknowledgeC', 'servermanagedit', 'Coders4africa', 'securitycast', 'macbid', 'tomsguide', 'DrInfoSec', '1humanvoice', 'fsf', 'volodia', 'clusif', 'gbillois', 'theliaecommerce', 'JoshMock', 'MarConnexion', 'stmanfr', 'archiloque', 'ggreenwald', 'libdemwasjailed', 'inthecloud247', 'BlogsofWarIntel', 'pewem_formation', 'zdnetfr', 'Current_Tech', 'ilhamnoorhabibi', 'PEGE_french', 'Lu1sma', 'msftsecurity', 'ashish771', 'brutenews', 'iPhoneTweak_fr', 'my_kiwi', 'SilvaForestis', 'PierreTran', 'Kuzbari', 'r0bertmart1nez', 'yttr1um', 'hrousselot', 'crashsystems', 'benlandis', 'netsecu', 'securityaffairs', 'Stormbyte', 'iisp_hk', 'zonedinteret', 'Facebook_Agent', 'confidentiels', 'CryptoFact', 'chuckdauer', 'vriesjm', '_antoinel_', 'dhanji', '_reflets_', 'Anon_Online', 'MailpileTeam', 'Itsuugo', 'mdecrevoisier', 'freeboxv6', 'garwboy', 'StackCrypto', 'ChanologyFr', '_gwae', 'ashk4n', 'nzkoz', 'Florianothnin', 'neeuQdeR', 'UsulduFutur', 'BullGuard', 'samehfayed', 'olesovhcom', 'dragondaymovie', 'Itforma', 'HYCONIQ', 'axcheron', 'blakkheim', 'pressecitron', 'ChrisGeekWorld', 'episod', 'thalie30', 'disk_91', 'idfpartipirate', 'PPAlsace', 'FlorenceYevo', 'gdbassett', 'VulnSites', 'Secunia', 'iteanu', 'sciendus', 'esrtweet', '6l_x', 'MduqN', 'Skhaen', 'daveaitel', 'ZeroSkewl', 'Rimiologist', 'ekse0x', 'ZOOM_BOX_r', 'aanval', 'fhsales', 'Ruslan_helsinky', 'OpLastResort', 'fcouchet', 'GTAXLnetIRC', 'TheAdb38', 'DeloitteUS', 'GeneralSeven', 'AustenAllred', 'AlliaCERT', 'Double_L83', 'scoopit', 'Dylan_irzi11', 'fr0gSecurity', 'atmon3r', '0x736C316E6B', 'Hask_Sec', 'Zer0Security', 'xssedcom', 'php_net', 'phpizer', 'JpEncausse', 'M4ke_Developp', 'nkgl', 'preventiasvcs', 'SwiftwayNet', 'c4software', 'who0', 'gandi_net', 'H_Miser', 'nikcub', 'gcouprie', 'MindDeep', 'MdM_France', 'SpritesMods', 'NakedSecurity', 'GDataFrance', 'conciseonline', 'filowme', 'regislutter', 'CelebsBreaking', 'globalwifiIntl', 't2_fi', 'catalyst', 'x6herbius', 'cryptocatapp', 'arahal_online', 'mtigas', 'ALLsecuritySoft', 'lisachenko', 'renaudaubin', 'wamdamdam', '01net', 'secuobsrevuefr', 'DataSecuB', 'drambaldini', 'secu_insight', 'cyber_securite', 'smeablog', 'DecryptedMatrix', 'eCoreTechnoS', 'topcodersonline', 'Sec_Cyber', 'thegaryhawkins', 'CajunTechie', 'Othrys', 'jeromesegura', 'RazorEQX', 'Xylit0l', 'c_APT_ure', 'it4sec', 'ConstructionFOI', 'Official_SEA16', 'OpGabon', 'SecuraBit', 'esheesle', 'brutelogic', 'taziden', 'sam_et_max', 'iMilnb', 'Clubic', 'greenee_gr', 'fo0_', 'nathanLfuller', 'carwinb', 'puellavulnerata', 'samphippen', 'ntisec', 'dummys1337', 'flanvel', 'SUPINFO', 'Epitech', 'Erebuss', 'infobytesec', 'garybernhardt', 'mab_', 'wisemedia_', 'LagunISA', 'wiretapped', 'verge', 'crowd42', 'virusbtn', 'FlacoDev', 'SunFoundation', 'TheNextWeb', 'guillaumeQD', 'IBMSecurity', 'code010101', 'gvalc1', 'adistafrance', 'LeWebSelonEdrek', 'tacticalflex', 'imatin_net', 'espeule', 'Applophile', 'nation_cyber', 'zahiramyas', 'alexheid', 'SecMailLists', 'mob4hire', 'AnonBig', 'FloCorvisier', 'MathieuZeugma', 'Katezlipoka', 'w_levin', 'climagic', 'PartiPirate', 'InfosecNewsBot', 'nedos', 'jerezim', 'katylevinson', 'ThVillepreux', 'PBerhouet', 'dbbimages', 'irqed', 'BLeQuerrec', 'patricksarrea', 'pierre_alonso', 'Flameche', 'AndreaMann', 'SciencePorn', 'mvario1', 'AbbyMartin', 'TheGoodWordMe', 'chroniclesu', 'DoubleJake', 'Kilgoar', 'TylerBass', 'FievetJuliette', 'Reuters', 'mrjmad', 'Sebdraven', 'SophiAntipolis', 'LaFranceapeur', 'papygeek', 'gordonzaula', 'neufbox4', 'plugfr', 'BenoitMio', '_Kitetoa_', 'Numendil', 'laquadrature', 'kheops2713', 'Slatefr', 'benjaltf4_', 'Fibo', 'codesscripts', 'zorelbarbier', 'Be_HMan', 'FranceAnonym', 'SpartacusK99', 'Free_Center', 'TrucAstuce', 'schignard', 'ciremya', 'MatVHacKnowledg', 'FreenewsActu', 'XSSed_fr', 'planetubuntu', 'S_surveillance', 'cyphercat_eu', 'Hack_Gyver', 'ncaproni', 'MISCRedac', 'Cyber_Veille', 'journalduhack', 'bidouillecamp', 'Apprenti_Sage', 'Oxygen_IT', 'FIC_Obs', 'orovellotti', 'cyberdefenseFR', 'l1formaticien', 'Reseauxtelecoms', 'neuromancien', 'actuvirus', 'cryptomars', 'amaelle_g', 'Hybird', 'Monitoring_fr', 'Zythom', 'InfosReseaux', 'speude', 'lavachelibre', 'dezorda', 'Bugbusters_fr', '3615internets', 'planetedomo', 'Mayeu', 'HeliosRaspberry', 'CiscoFrance', 'anonfrench', 'IvanLeFou', 'NosOignons', 'OSSIRFrance', 'patatatrax', 'EFF', 's7ephen', 'kaspersky', '2600', 'cheetahsoul', 'OpPinkPower', 'AJMoloney', 'ecrans', 'anonhive', 'julien_geekinc', 'Anonymous_SA', 'USAnonymous', 'e_kaspersky', 'FSecure', 'ClipperChip', 'ax0n', 'hevnsnt', 'Aratta', 'yolocrypto', 'waleedassar', 'postmodern_mod3', 'kochetkov_v', 'pwntester', 'bartblaze', 'TheDanRobinson', 'unpacker', 'r_netsec', 'AnonymousPress', 'priyanshu_itech', 'kinugawamasato', 'mozwebsec', 'zonehorg', 'beefproject', 'YourAnonNews', 'boblord', 'vikram_nz', 'PublicAnonNews', 'kkotowicz', 'hackersftw', '0xerror', 'fancy__04', 'l33tdawg', 'node5', '0xjudd', '_mr_me_', 'sickness416', 'googleio', 'infosecmafia', 'p0sixninja', 'isa56k', 'TheWhiteHatTeam', 'inj3ct0r', 'snowfl0w', 'SocEngineerInc', 'jdcrunchman', 'DiptiD10', 'ehackingdotnet', 'jack_daniel', 'BrandonPrry', 'TurkeyAnonymous', 'MarkWuergler', 'pranesh', 'eddieschwartz', 'mozilla', 'deCespedes', 'M0nk3H', 'tpbdotorg', 'IPredatorVPN', 'smarimc', 'Thomas_Drake1', 'opindia_revenge', 'Malwarebytes', 'EHackerNews', 'HNBulletin', 'dietersar', 'CCrowMontance', 'r3shl4k1sh', 'DanielEllsberg', 'PMOIndia', 'SecurityPhresh', 'vxheavenorg', 'kgosztola', 'TheHackersNews', 'jeromesaiz', 'Trem_r', 'netsabes', 'Flaoua', 'DannyDeVito', 'p0sixn1nja', 'twitfics', 'wzzx', 'DustySTS', 'Lincoln_Corelan', 'SecureTips', 'InfoSecRumors', 'matthew_d_green', 'agl__', 'elwoz', 'apiary', '0xabad1dea', 'dangoodin001', 'kpoulsen', 'ethicalhack3r', 'SecBarbie', 'dguido', 'marcusjcarey', 'jadedsecurity', 'petitpetitam', 'hackeracademy', 'moreauchevrolet', 'Jean_Leymarie', 'tricaud', 'Nipponconnexion', 'OtakuGameWear', 'schneierblog', 'g4l4drim', '0x73686168696e', 'securityvibesfr', 'window', 'sm0k_', 'pentesteur', 'AlainAspect', 'chandraxray', 'AstronomyNow', 'Astro_Society', 'SpitzerScope', 'NASAspitzer', 'NASAWebb', 'NASAFermi', 'SpaceflightNow', 'NASAStennis', 'sciam', 'WISE_Mission', 'NASA_Images', 'NatGeo', 'NASAblueshift', 'universetoday', 'NASAJPL_Edu', 'NASA_Orion', 'TrinhXuanThuan', 'Infographie_Sup', 'MartinAndler', 'pierenry', 'Bruno_LAT', 'RichardDawkins', 'guardianscience', 'TheSkepticMag', 'TomFeilden', 'gemgemloulou', 'AdamRutherford', 'Baddiel', 'DrAliceRoberts', 'ProfWoodward', 'SarcasticRover', 'robajackson', 'MarsCuriosity', 'BBCBreaking', 'shanemuk', 'Schroedinger99', 'AtheneDonald', 'imrankhan', 'danieldennett', 'paulwrblanchard', 'MartinPeterFARR', 'DPFink', 'sapinker', 'chrisquigg', 'minutephysics', 'AdamFrank4', 'SpaceX', 'astrolisa', 'Erik_Seidel', 'simonecelia', 'PhilLaak', 'TEDchris', 'colsonwhitehead', 'plutokiller', 'dvergano', 'carlzimmer', 'j_timmer', 'edyong209', 'Laelaps', 'bmossop', 'maiasz', 'ericmjohnson', 'WillmJames', 'BadAstronomer', 'billprady', 'reneehlozek', 'PolycrystalhD', 'BoraZ', 'sethmnookin', 'albionlawrence', 'RisaWechsler', 'seanmcarroll', 'imaginaryfndn', 'PhysicsNews', 'DiggScience', 'bigthink', 'PopSci', 'AIP_Publishing', 'NSF', 'NewsfromScience', 'BBCScienceNews', 'PhysicsWorld', 'ScienceNews', 'physorg_com', 'TED_TALKS', 'TreeHugger', 'physorg_space', 'physorg_tech', 'NASAGoddard', 'CERN_FR', 'neiltyson', 'ProfBrianCox', 'SethShostak', 'b0yle', 'NASAJPL', 'worldofscitech', 'michiokaku', 'OliverSacks', 'AMNH', 'JannaLevin', 'bgreene', 'AssoDocUp', 'MyScienceWork', 'ParisDiderot', 'molmodelblog', 'neilfws', 'pjacock', 'dalloliogm', 'yokofakun', 'mrosenbaum711', 'joshwhedon', 'BrentSpiner', 'moonfrye', 'greggrunberg', 'Schwarzenegger', 'RealRonHoward', 'arnettwill', 'AmandaSeyfried', 'JasonReitman', 'DohertyShannen', 'JohnStamos', 'frankiemuniz', 'TheRealNimoy', 'EyeOfJackieChan', 'dhewlett', 'ZacharyLevi', 'MillaJovovich', 'JohnCleese', 'BambolaBambina', 'CERN', 'CNES', 'Inserm', 'NASA', 'USGS', 'NatureNews', 'Planck', 'IN2P3_CNRS', 'Inria', 'INC_CNRS', 'tgeadonis', 'inp_cnrs', 'AlainFuchs', 'CNRSImages', 'FabriceImperial', 'CNRS', 'laurentguyot', 'consult_detect', 'NewsBreaker', 'ISS_Research', 'nicolaschapuis', 'PolarisTweets', 'uncondamne', 'veytristan', 'gplesse', 'MattBellamy', 'LeParisien_Tech', 'Pontifex_fr', 'DenisCourtine', 'PascalDronne', 'NSegaunes', 'LeParisien_Buzz', 'NoemieBuffault', 'LesInconnus', 'FBIBoston', 'Pascallegitimus', 'lucabalo', 'isabellemathieu', 'FlorentLadeyn', 'NaoelleTopChef', 'quentintopchef', 'julienduFFe', 'natrevenu', 'yannforeix', 'defrag', 'rybolov', 'securid', 'stacythayer', 'tcrweb', 'Techdulla', 'TimTheFoolMan', 'treguly', 'YanceySlide', 'golfhackerdave', 'liquidmatrix', 'jonmcclintock', 'infosecpodcast', 'HypedupCat', 'Hak5', 'georgevhulme', 'gcluley', 'gattaca', 'g0ne', 'EACCES', 'digininja', 'devilok', 'd4ncingd4n', 'CSOonline', 'anthonymckay', 'abaranov', 'aaronbush', '_LOCKS', 'security_pimp', 'teksquisite', 'blpnt', 'alpharia', 'jgarcia62', '_MC_', 'InfoSec208', 'SPoint', 'i0n1c', 'torproject', 'room362', 'nicowaisman', 'VirusExperts', 'DavidHarleyBlog', 'follc', 'episeclab', 'manhack', 'pollux7', 'y0ug', 'Hallewell', 'SteveGoldsby', 'polarifon', 'malwarecityFR', 'Webroot', 'Infosanity', 'BitDefenderAPAC', 'VirusExpert', 'securitypro2009', 'blackd0t', 'securityfocus', 'DanaTamir', 'securitywatch', 'securitynetwork', 'PrivacySecurity', 'securitystuff', 'myCSO', 'RSAsecurity', 'SecurityExtra', 'WebSecurityNews', 'web_security', 'SCmagazineUK', 'TechProABG', 'malwareforensix', 'stephanekoch', 'daleapearson', 'CyberSploit', 'veryblackhat', 'opexxx', 'Hakin9', 'EvilFingers', 'isaudit', 'SpiderLabs', 'securegear', 'gdssecurity', 'ioerror', 'yaunbug', 'dstmx', 'zentaknet', 'wireheadlance', 'TenableSecurity', 'secdocs', 'proactivedefend', 'racheljamespi', 'xxradar', 'aebay', 'vincentzimmer', 'xanda', 'MarioVilas', 'sting3r2013', 'SecRich', 'deanpierce', 'HaDeSss', 'Jolly', 'searchio', 'thomas_wilhelm', 'gollmann', 'HackerTheDude', 'ADMobilForensic', 'SecurityStream', 'gadievron', 'tomaszmiklas', 'irongeek_adc', '_____C', 'operat0r', 'carne', 'fmavituna', 'PandaSecurityFR', 'freaklabs', 'alphaskade', 'hgruber97', 'noncetonic', 'AVGFree', 'k0st', 'kargig', 'lgentil', 'andreasdotorg', 'redragonvn', 'theharmonyguy', 'NoSuchCon', 'b10w', '0security', 'Z3r0Point', 'bortzmeyer', 'ahoog42', 'gianluca_string', 'eLearnSecurity', 'k4l4m4r1s', 'issuemakerslab', 'matalaz', 'ForcepointLabs', 'iExploitXinapse', 'itespressofr', 'ehmc5', 'practicalexplt', 'Pentesting', 'avkolmakov', 'manicode', 'HITBSecConf', 'sensepost', 'TeamSHATTER', 'n00bznet', 'thegrugq', 'judy_novak', 'TaPiOn', 'revskills', 'randomdross', 'malphx', 'OpenMalware', 'syngress', '2gg', 'GNUCITIZEN', 'chrissullo', 'michael_howard', 'c7five', 'pdp', 'securosis', 'Shadowserver', 'BlackHatHQ', 'securityincite', 'bsdaemon', 'Secn00b', 'dyngnosis', 'mwtracker', 'BorjaMerino', 'packetlife', 'toolcrypt', 'hackmiami', 'OWASP_France', 'jkouns', 'Mario_Vilas', 'zate', '_supernothing', 'aszy', 'lestutosdenico', 'espreto', '_sinn3r', 'aloria', 'Fyyre', 'SymantecFR', 'aircrackng', 'hackerschoice', 'MuscleNerd', 'smalm', 'OxbloodRuffin', 'subliminalhack', 'bannedit0', 'armitagehacker', 'RealGeneKim', 'mxatone', 'Snort', 'rebelk0de', 'hackingexposed', 'virustotalnews', 'InfiltrateCon', 'aramosf', 'msfdev', 'ChadChoron', 'n0secure', 'ITRCSD', 'CyberDefender', 'ArxSys', 'lulzb0at', 'crypt0ad', 'Stonesoft_FR', 'LordRNA', 'WindowsSCOPE', 'yo9fah', 'michelgerard', 'NAXSI_WAF', 'v14dz', 'x0rz', 'tbmdow', 'kasperskyfrance', 'Agarri_FR', 'ISSA_France', 'Jhaddix', 'Heurs', 'PlanetCreator', 'infernosec', 'rexploit', 'ConfCon', 'securityshell', 'bonjour_madame', 'minusvirus', 'emiliengirault', 'dvrasp', 'virtualabs', 'rfidiot', 'ttttth', 'msuiche', 'Ivanlef0u', 'Korben', 'hackersorg', 'shell_storm', 'WTFuzz', 'MoonSols', 'newsoft', 'vnsec', 'in_reverse', 'hackerfantastic', 'mtrancer', 'datacenter', 'stelauconseil', 'CNIL', 'exploitdb', 'BillBrenner70', 'lagrottedubarbu', 'HackingDave', 'VUPEN', 'siddartha', 'bluetouff', 'sstic', 'ToolsWatch', 'emmasauzedde', 'lseror', 'bearkasey', 'xme', 'helpnetsecurity', 'hackinthebox', 'Transiphone', 'hackaday', 'TheSuggmeister', 'Herve_Schauer', 'humanhacker', 'it_audit', 'Jipe_', 'FredLB', '0vercl0k', 'secbydefault', 'kerouanton', 'dragosr', 'endrazine', 'HBGary', 'pentestit', 'madpowah', 'serphacker', 'security4all', 'SecuObs', 'vloquet', 'joegrand', 'matrosov', 'DIALNODE', 'brucon', 'corelanc0d3r', 'RSnake', '0xcharlie', 'taviso', '41414141', 't0ka7a', 'thedarktangent', 'mubix', 'jonoberheide', 'spacerog', 'ChrisJohnRiley', 'securityninja', 'threatpost', 'nasko', 'mwrlabs', 'justdionysus', 'iHackwing', 'DJLahbug', 'cyber_security', 'hardhackorg', 'e2del', 'a41con', 'msftsecresponse', 'sans_isc', 'egyp7', 'antic0de', 'mikko', '_MDL_', 'mdowd', 'carnal0wnage', 'jeremiahg', 'xorlgr', 'cesarcer', 'BlackHatEvents', 'MatToufoutu', 'csec', 'selectrealsec', 'CERTXMCO', 'SecuritySamurai', 'razlivintz', 'etcpasswd', 'The_Sec_Pub', 'meikk', 'securityweekly', 'alexsotirov', 'DidierStevens', 'beist', 'stalkr_', 'dakami', 'halvarflake', 'dinodaizovi', 'silviocesare', 'stephenfewer', 'barnaby_jack', 'andremoulu', 'thierryzoller', 'PwnieAwards', 'reversemode', 'kalilinux', 'gynvael', 'pusscat', 'abcdelasecurite', 'johnjean', 'ninjanetworks', 'sotto_', 'SecretDefense', 'FFW', 'commonexploits', 'x86ed', 'zsecunix', 'hack_lu', 'Majin_Boo', 'BadShad0w', 'FlUxIuS', 'valuphone', 'free_man_', 'teamcymru', 'ihackstuff', 'secureideas', 'sansforensics', 'benoitbeaulieu', 'LaFermeDuWeb', 'TwitPic', 'noaheverett', 'lostinsecurity', 'democracynow', 'dougburks', 'zephilou', 'kevinmitnick', 'defcon', 'SecurityBSides', 'haxorthematrix', 'rmogull', 'unbalancedparen', 'perfectvendetta', 'siccsudo', 'Nan0Sh3ll', 'newroot', 'ClsHackBlog', '27c3', 'c3streaming', 'SOURCEConf', 'eugeneteo', 'moxie', 'dlitchfield', 'thezdi', 'scarybeasts', 'ryanaraine', 'kernelpool', 'esizkur', 'richinseattle', 'WeldPond', 'k8em0', 'jduck', 'ultramegaman', 'tsohlacol', 'HeatherLeson', 'myrcurial', 'nudehaberdasher', 'drraid', 'Agarik', 'Aziz_Satar', 'hackinparis', 'sdwilkerson', 'Satyendrat', 'LawyerLiz', 'UnderNews_fr', 'deobfuscated', 'HacKarl', 'StopMalvertisin', 'djrbliss', 'TinKode', 'HappyRuche', 'rssil', 'sysdream', 'acissi', 'migrainehacker', 'xsploitedsec', 'sucurisecurity', 'bonjourvoisine', 'Sorcier_FXK', 'mikekemp', 'jaysonstreet', 'roman_soft', 'xavbox', 'HackBBS', 'securitytwits', 'Hi_T_ch', 'DarK_Kiev', 'lbstephane', 'hugofortier', 'bl4sty', 'kaiyou466', 'Thireus', 'Paul_da_Silva', 'fbaligant', '_metalslug_', 'ochsff', 'fjserna', 'JonathanSalwan', 'ericfreyss', 'julianor', 'j00ru', '0xGrimmlin', 'define__tosh__', 'hesconference', 'Calculonproject', 'ZenkSecurity', 'Moutonnoireu', 'newsycombinator', 'securityh4x', 'corbierio', 'Security_Sifu', 'str0ke', 'owasp', 'milw0rm', 'gsogsecur', 'USCERT_gov', 'packet_storm', 'CoreSecurity', 'CiscoSecurity', 'ECCOUNCIL', 'securityweb', 'debian_security', 'ubuntu_security', 'SocialMediaSec', 'offsectraining', 'JournalDuPirate', 'ThisIsHNN', 'nmap', 'metasploit', 'orangebusiness', 'tixlegeek', 'rapid7', 'defconparties', 'ProjectHoneynet', 'NoWatch', '1ns0mn1h4ck', 'zataz', 'r00tbsd', 'hackerzvoice', 'JournalDuGeek', 'Senat_Direct', 'franceculture', 'MetroFrJustice', 'MrAntoineDaniel', 'tanguy', '_clot_', 'Reuno', 'chiptune', 'nicolasfolliot', 'johnmartz', 'lifehacker', 'Vfalkrr', 'AurelieThuot', 'PinkPaink', 'jnkboy', 'ManardUV', 'AsherVo', 'Stephan_Kot', 'thatgamecompany', 'Dedodante', 'RomainSegaud', 'TheMarkTwain', 'Maitre_Eolas', 'jmechner', 'SeinfeldToday', '5eucheu', 'FRANCHEMENT_', 'SuricateVideo', 'alainjuppe', 'antoine64', 'ydca_nico', 'aleksou', 'docslumpy', 'jeremy345', 'TRYWAN', 'UrielnoSekai', 'Mister_AlAmine', 'KrSWOoD', 'hamsterjoueur', 'JyanMaruku', 'insertcoinFR', 'MisterAdyboo', 'MrBouclesDor', 'Gorkab', '____Wolf____', 'Ben_MORIN', 'lestortuesninja', 'neocalimero', 'Sadnachar', 'KazHiraiCEO', 'Bethesda_fr', 'ChrisToullec', 'Juliette1108', 'RisingStarGames', 'LtPaterson', 'VGLeaks', 'SonySantaMonica', 'l87Nico', 'Yatuu', 'cbalestra', 'yosp', 'twfeed', 'ludaudrey', 'RpointB', 'danielbozec', 'LiveScience', 'Rue89', 'ScienceChannel', 'ScienceDaily', 'ubergizmofr', 'Gizmodo', 'Virgini2Clausad', 'fabriceeboue', 'ThibBracci', 'labeauf', 'waterkids', 'MisterMcFlee', 'FranckLassagne', 'GraiggyLand', 'Galagan_', 'BenCesari', '_RaHaN_', 'Tris_Acatrinei', 'Valent1Bouttiau', 'Julien_Bouillet', 'UncleTex', 'Suchablog', 'laboitecom', 'coverflow_prod', 'TeamTerrasse', 'IGmagazine', 'Wael3rd', 'Rogedelaaa', 'starcowparis', 'liloudalas', 'emanu124', 'xfrankblue', 'K0RSIK0', 'UlycesEditions', 'Djoulo', 'cabanong', 'laureleuwers', 'clemence_robin', 'suriondt', '_Supertroll', 'Neveu_Tiphaine', '_theNextdoor_', 'tomnever', 'DavidChoel', 'Elmedoc', 'Delzarissa', 'Nolife_Online', 'NicolAspatoule', 'Frederic_Molas', 'Marcuszeboulet', 'PlayStation', 'RockstarGames', 'Naughty_Dog', 'notch', 'pirmax', 'miklD75', 'ClorindeB', 'NathalieAndr', 'ODB_Officiel', 'LeGoldenShow', 'HIDEO_KOJIMA_EN', 'damiensaez', 'DIEUDONNEMBALA', 'FQXi', 'PerleDuBac', 'SatoshiKon_bot', 'shin14270', 'tsamere', 'Bouletcorp', 'CasselCecile', 'RaynaudJulie', 'LionnelAstier', 'swinefever', 'normanlovett1', 'SteveKeys66', 'DannyJohnJules', 'LeoDiCaprio', 'wikileaks', 'TORDFC', 'RedDwarfHQ', 'DalaiLama', 'Al_Hannigan', 'AnthonySHead', 'SteveMartinToGo', 'bobsaget', 'gwenstefani', 'JohnMCochran', 'ActuallyNPH', 'CobieSmulders', 'alydenisof', 'jasonsegel', 'kavanaghanthony', 'RafMezrahi', 'BellemareOut', 'BellemarePieR', 'rataud', 'piresrobert7', 'beigbedersays', 'IamJackyBlack', 'oizo3000', 'ericetramzy', 'yannlaffont', 'michel_denisot', 'VincentDesagnat', 'PaulMcCartney', 'Pascal__Vincent', 'JimCarrey', 'simonastierHC', 'manulevyoff', 'GillesLellouche', 'axellelaffont', 'xaviercouture', 'emougeotte', 'bernardpivot1', 'sgtpembry', 'Xavier75', 'NicolasBedos1', 'Chabat_News', 'stephaneguillon', 'farrugiadom', 'francoisrollin', 'kyank', 'levrailambert', 'lolobababa', 'jimalkhalili', 'alexnassar', 'suivi_avec_lisa', 'Suzuka_Nolife', 'DavidHasselhoff', 'CCfunkandsoul', 'CaptainAJRimmer', 'DougRDNaylor', 'bobbyllew', 'katherineravard', 'ReizaRamon', 'kaorinchan', 'NolifeOfficiel', 'floweb', 'Thugeek', 'LoloBaffie', 'charlottesavary', 'SebRaynal', 'GirlButGeek', 'bjork', 'YOUNMICHAEL', 'hartza_info', 'ApScience', 'ApertureSciCEO', 'wheatley_core', 'ApertureSciPR', 'lilyallen', 'koreus', 'MichaelYoun']

banlist = ['',' books ','#books','-anonymous','falling in reverse','the best ways','I liked a @Youtube video',' rio ','#rio',"l'exploit",'free>','free:','free!','free!"','daily','what is ','we do not forget','we do not forgive','donate 2','#winemaker','winemaker','stand up 4','meadows','innovation','click here>','click here:','click here','out now','stop by the','weekend','championship','marriage','granite','#groundzero','9/11','heart attack:','#SAFCSquad','Be part of the','Donate for','Donate to','Donate via','mini heart attack','heart attack','heroin','look hot','gluten','fuck off','thank u ','how on earth','Scoops,','soundcloud',' stoned ',' Snoop ','thanks for','embracing','liveleak','killed','UKBizCircle','fuck ',' vibes ','smoking','come see','my book','thnks to','thanks to','portfolio','vagina',' soul ','church','#pafc','pls share','watch how','album','so excited to','so excited about','#tip','canonical mission',' gym ','how dare you','diamond','is out!','gary jhonson','skimming the','skimming through','weather',' winds ','heavy rain','did you know','did you know ','did you know?','secret war','harambe','team rocket','tatoo',' pool ','grammar',' spurs ','linkedin.com','Teaches us','download this','#jobsearch','#jobs','pasadenadaisy.com','accepting submissions','the yellow dog project','CVE program','#CVE Program','concours',' RT ','#kingpin','coming soon','vine.co','want to see private shots of the girls you know from facebook','John Curran','ethnographic','submit here:','micro-fiction','une playlist @YouTube','urologists','howtoquitworking','quit working','#entrepreneur','flash fiction','sold out','inb4','americans','watch out for','university','@Kingpin_Picks','what does the future of ','t forget to ','#ebook','ebook','footer text','cheese','#cheese','taco','#taco','thezoereport','to extend the life',':"please make a contribution','wrisbands','lifestyle','cheat sheet','green arrow','transforming field service:','holydays','holyday','visit our new','#scoop','#scoops','paper.li','i added a video to','Keep You Privacy','GTA','web hosting firm','reasearcher hides','#Health','probiotic','some salted','Telegram explains','rot in hell','smoothie','#fishing','#fish','fish','fishing','vandals','lmaoo','skimming the pool','bbc.in','skimmer','black skimmer','Olympics','learn about','Richard brain','christians','big week','superman','lovecraft','bowie','canonical evidence','enroll in our','interested in ','can boost','bourdieu','can help you be more','embracing','common','#teen','teen','t miss our','t miss your','why your','#scotland','watch:','from being hacked','sec network','cartel','middle man','food violation','#business','Lmao','giveaway','gambling','american flag','miss our','alabama','lawyers','blood shortage','breaking:','the song','middle school','sabmiller','tv network','most common','lures','#management','fdp',' mdr ',' fdp ','simple tricks','new blog','ground floor','#entreprise','football','bradley maning','chelsea chainsow','did you hear?','chicago',' tips ',' tip ','10 ways','3 ways','5 ways','4 ways','clothe','shopping','creature','6 steps','3 steps','4 steps','5 steps','malcolm in the middle','special offer','special photo','rtsi t','white girl','black ppl','white ppl','black people','White people','antisemit','Great blog','les noirs','les arabes','les noir','illuminati','you later','earnings',' earning','weekly','whore','foxnews','loyalists','swallow','trending','top three','top ten','top five','party',' story ',' story','my favorite',' vine','vine ','lmao','alison armitage','#cops2016','brooklyn',' msm ','Jeremy corbyn',' leader ','radical',' rape ','live-action','trailer','summer','film','most value','getting the most','get the most','Louis eavesdropping','vine','sans qu','get it now','is out now','learn more','smell','smells','kiss','the key to ','potes','haine','pote',' wear ','sweatpants','mph','baseball','niggas','beach','the key is to','wealth','economy','businesses','shareeconomy','for a chance','enter now','song','baby','murder','savage','Bomb','improve','marketers','Marketing','career','your business','trends','trend','please rt','pls retweet','pls rt','please rt','RqiM','#ccot','#tcot','that women','this women','that guy','this guy','fool','world ends','want to know the latest','find out now','#getmorelead','10 key','7 key','5 key','3 key','lead generation','rugby','featuring','organization','emploi','up to you','wisdom framework','deal','ginger','MLM','===>','management','#loyality','#MLM','browser/os','#music','housemusic','techhouse','icemoon','guidance','meet your','Meet our','suicide','loam','fuck you','bitch','internet friends','internet slang','the latest','nigger','nigga','broad gauge','felties','glow in the dark','scrapbooking','helixstudios','solidarity',' activist','sweatshop','help grow','Digital buyer','trump','baise','top stories','skid game','arrieta','leading off:','baby hat','newborn','Rt for','dining table','retweet','vibrators','rainbow round','skid row','malliardreport','breaking news','scoop:','spider art','subscribe:','subscribe to our','GOT7','Join us','explosive device','fuzzing feeling','future of our people','sex','pute','penis','sports','toilet valve','toilet water','sfxns','smoke','ptdr','VosMecsQui','cheveux','learn more:','tanning','long trajet','rainbow-filled','Hillary','Hartunes','mystery','Aspirin','growing','please share','rainbow dash','Truth coffee','top 5','rainbow glass','jet lag','jet-lag','clinton campaign','buzzfeed','microbial','growth','are you prepared','nautical','biopsies','reverse vending','Tokyo ghoul','Galang','kingarmani','Trump','rugby','I liked a @Youtube video from','White man','WHITEPAPER','white girl','Whitepaper','growing','to help you','spider thread',' Marketing ','check this out','check out this','mimicking ghosts','fundamental tactics',' FREE ','Richard Armitage','@EdgeofSports','Tips','tips','Increase','growth','free ','Growth','Join Free ','vulnerability of women','cornwall','Forensic Mystery','Learn how','Healthcare','Security Epidemic','ASMSG','microbiome','flood of refugees','Donald Trump','spider couples','Follow us','Sida','carotte','moche','slow motion','fake tweets','meuf','Market Research']

banppl = ['LESFEMININES','BSteekFC','SunderlandAFC','PrinzNiyi','geekygabriela15','Juliissaaaa_','PilgrimPetey','beholdthymother','_TheMunSession_','chris_peruggia','NexCentCit','Jvxon','spbetting1','truerpoems','High_','amadijuana','Kingpin_Picks','deadcool','musicaltrees','thezoereport','olicityloyalty','Pete_Spence','europeanhistry','Parkdean','DailyStockPlays','DJW_Macbeth','Queen_HoneyPot','braylannnE','CastroTrapMoney','YoungTiba','AusWyche','mmasekgoam','Polygon','SiriusNews_com','Diez_30et1Diez','Gunzblazing_MV','WWE','1dasviness','sciendus','mrk1_','kennyjnners','ShitJokes','BsbLifeStyle_','Talib944','MattBellassai','charlieputh','FreddyAmazin','FurBearers','RedFumz','Carbonite','rugbycomau','DaybreakHelp','FindPsychics','FrancisMastroMj','StartupProduct','MyCloudstar','tonni_olsen','aliciacrisp1','AdeosunA1','fxckmodel','crochet_rr','FaustianDemon','MalliardReport','AllyBenoliel','biiiiitchy_69','richchigga','sexualgifs_','neymarjr','sofarrsogud','thesecret','Swaaann_','DJ_Korsakoff','Poetryinsunsets','alexielsi','MonMecNePeutPas','cvrentin','RailMinIndia']

bandouble = []

apicall = 0

updatecall = 0

totalcall = 0

totalupdatecall = 0

allok = 0

checkM = 0

searchlimit = 0

retweetlist = []

newkeywords = []

QueueList = []

#Some Defs

def flushtmp():

	goflush = 0

        Fig = Figlet(font='rev')
        print Fig.renderText('flushtmp()')

	time.sleep(1)
	if os.path.exists(Session):

		file = open(Session,"r")
		datefile = file.read()
		date_object = datetime.datetime.strptime(str(datefile), '%Y-%m-%d %H:%M:%S.%f')
		Laps = (currentdate - date_object)

		print Laps

		try:
			if (currentdate - date_object).total_seconds() > 86400:
				goflush = 1
		except Exception as e:
			print e 
			print
		        Fig = Figlet(font='cybermedium')
		        print Fig.renderText('No need to flush')
			print

		if goflush == 1:


			print
			print "=="
			Fig = Figlet(font='basic')
			print Fig.renderText('Flushing Temps Files')
			print "=="
			print
			
			file.close()
			time.sleep(3)

			os.remove(Session)


		        if os.path.exists(TmpDay):
		            os.remove(TmpDay)


		        if os.path.exists(TmpDay2):
		            os.remove(TmpDay2)


       			if os.path.exists(TmpMeal):
        		    os.remove(TmpMeal)

        	        print
	                print
                	print "=="
                	Fig = Figlet(font='basic')
                	print Fig.renderText('Saving current date')
                	print currentdate
                	print "=="
                	print
                	print
                	time.sleep(5)
                	file = open(Session,"w")
                	file.write(str(currentdate))
                	file.close()



                        Fig = Figlet(font='cybermedium')
                        print Fig.renderText('Done Flushing')
			time.sleep(2)
			file = open("Tmp/Flushed","a+")
			file.write("function worked")
			file.close
		else:
			lfts = 86400 - Laps.seconds

			print
			print 
			print "=="
                        Fig = Figlet(font='basic')
                        print Fig.renderText('Starting from Last Session')
			print
			print "Numbers of seconds since the first api call :",Laps.seconds
			print "%i Seconds left until Twitter flushs apicalls :" % lfts
			print "=="
			print
			print
			print
			time.sleep(5)

	else:
		print
		print
		print "=="
                Fig = Figlet(font='basic')
                print Fig.renderText('New Session Started')
		print currentdate
		print "=="
		print
		print
		time.sleep(5)
		file = open(Session,"w")
		file.write(str(currentdate))
		file.close()


def checkmenu(wordlist):
        Fig = Figlet(font='rev')
        print Fig.renderText('CheckMenu()')
	print
	time.sleep(1)
	try:
		global newkeywords
		global checkM
		oldlen = len(wordlist)
		file = open(TmpMeal,"r")
                lines = file.read().splitlines()
		print
		print "=="
		lenmatch = len(set(lines) & set(wordlist))
		while lenmatch >0:
			print "Found %i occurences :" % lenmatch
			set(lines) & set(wordlist)
			print
			print
			time.sleep(1)
			print "Removing from search list ..."
			wordlist = list(set(wordlist) - set(lines))
			print
			time.sleep(1)
			print
			print "New lenght of searchlist : " + str(len(wordlist)) + " (Was " + str(oldlen) + " )"
			print "=="
			print
			time.sleep(1)
			lenmatch = len(set(lines) & set(wordlist))
		file.close()
		newkeywords = wordlist
		print
		print "=="
                Fig = Figlet(font='basic')
                print Fig.renderText('Search terms already used removed successfully')
		print "=="
		checkM = 1
		time.sleep(1)
	except:
		print "=="
                Fig = Figlet(font='basic')
                print Fig.renderText('No previous searchs found for today')
		print "=="
		time.sleep(1)


def lastmeal(lastsearch):

                Fig = Figlet(font='rev')
                print Fig.renderText('LastSearch()')
		time.sleep(1)
                try:
                        file = open(TmpMeal,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Last Search Terms)"
                        print "Creating tmp file"
                        print "=="
                        file = open(TmpMeal,"w")
                        file.write("")
                        file.close()

                file = open(TmpMeal,"a")
		for words in lastsearch:
			file.write(words + "\n")
			print "Marking " + words + " as old . "
		file.close()
		time.sleep(1)


def SaveTotalCall(call,update):
                print
                print
                print
                print
                print
		Fig = Figlet(font='rev')
                print Fig.renderText('SaveTotalCall()')
		print
		time.sleep(1)
		global totalcall
		global updatecall
		global totalupdatecall

		try:
			file = open(TmpDay,"r")
			file.close()
		except:
			print "=="
			print "File does not exist (Total)"
			print "Creating tmp file"
			print "=="
			file = open(TmpDay,"w")
			file.write("0")
			file.close()

		file = open(TmpDay,"a+")
		lines = file.read().splitlines()
		lenfile = len(lines)
		lastitem = lines[lenfile -1]
		print "=="
		print "Last Total saved : ",lastitem
		newitem = int(lastitem) + int(call)
		totalcall = newitem
		finalitem = str(newitem) + "\n"
		print "Saving new Total : ",finalitem
		print "=="
		file.write(finalitem)
		file.close()
		time.sleep(1)
                try:
                        file2 = open(TmpDay2,"r")
                        file2.close()
                except:
			print "=="
                        print "File does not exist (Update)"
                        print "Creating tmp file"
			print "=="
                        file2 = open(TmpDay2,"w")
                        file2.write("0")
                        file2.close()

                file2 = open(TmpDay2,"a+")
                lines2 = file2.read().splitlines()
                lenfile2 = len(lines2)
                lastitem2 = lines2[lenfile2 -1]
		print "=="
                print "Last Update Total saved : ",lastitem2
                newitem2 = int(lastitem2) + int(update)
                totalupdatecall = newitem2
                finalitem2 = str(newitem2) + "\n"
                print "Saving new Update Total : ",finalitem2
		print "=="
                file2.write(finalitem2)
                file2.close()
                Fig = Figlet(font='basic')
                print Fig.renderText('Done Saving Calls')

                time.sleep(1)
                print
                print
                print
                print


def Retweet():

 	global apicall
	global updatecall
	global totalupdatecall
	global restabit
	global twitter
	global fuck
	global waithour

        Fig = Figlet(font='rev')
        print Fig.renderText('Retweet()')
	time.sleep(2)
        if allok == 1:
		print
		print
		print
		print
		print

	        tri = sorted(retweetlist,key=lambda line: int(line.split("-")[0]),reverse=True)
	
        	QueueList = tri

		nbrRtwt =  2223 - int(totalupdatecall)
		print
		print "=="
		print "I Think i m able to retweet %d items in list ." %nbrRtwt
		print
		time.sleep(2)

		if nbrRtwt == 0:
                        Fig = Figlet(font='basic')
                        print Fig.renderText('Cant Retweet All Of Them ..')
			print Fig.renderText('Trying to guess how many tweets can still be send .')
			time.sleep(2)
			tmpcall = int(totalupdatecall)
			mx = 2223
			res = 0
			guess = 0
			while res != 1:
				tmpcall = tmpcall - 1
				guess = guess + 1
				res = mx - tmpcall
			else:
				print "I think im able to retweet " + guess + "tweets at least ."
				nbrRtwt = guess
				time.sleep(2)
#			sys.exit()

		if nbrRtwt > len(QueueList):
			nbrRtwt = len(QueueList)
                	Fig = Figlet(font='basic')
                	print Fig.renderText('resizing to list size"')
			time.sleep(2)
			print
		print "=="
		print
		tmpcount = 0
		for item in QueueList[:nbrRtwt]:

				limits()

				FinalItem = item.split("-")[1]
		                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        		        print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
       		        	Fig = Figlet(font='cybermedium')
                		print Fig.renderText('Retweeting')
        		        print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        	       	 	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

				print
				print "**"
				print "Retweeting : ",FinalItem
				print "Score : ",item.split("-")[0]
				tmpcount = tmpcount + 1
				time.sleep(2)
				try:

		                	twitter.retweet(id = FinalItem)
		                        Fig = Figlet(font='basic')
					print
					print

		                        print Fig.renderText('Done !"')
					print
					print
					print "Tweets left to send %i / %i " % (tmpcount,nbrRtwt)
					print "**"
					print
					print "*=*=*=*=*=*=*=*=*=*"
		                        Fig = Figlet(font='basic')
        		                print Fig.renderText('Saving Tweet ID')
					print "*=*=*=*=*=*=*=*=*=*"
					Saveid(FinalItem)
					time.sleep(2)
					apicall = apicall +1
					updatecall = updatecall + 1
					if fuck > 0:
						fuck = fuck - 1

				except Exception as e:
				                        Fig = Figlet(font='bell')
                        				print Fig.renderText('Twython Error')

							print e
							if "Twitter API returned a 403 (Forbidden), User is over daily status update limit." in e:
									print "Oups ..too many requests for today (From Retweet function)"
									SaveTotalCall(apicall,updatecall)
									lastmeal(Keywords[:rndwords])
									fuck = fuck + 1
									if fuck == 1 or fuck == 2:
										waithour = 1
										limits()

									if fuck == 3:
										print
										print
										Fig = Figlet(font='cybermedium')
                                        					print Fig.renderText('The Lanister sends their regards ..')
										sys.exit()
									else:
										restabit = 1
										limits()
							if "Twitter API returned a 429 (Too Many Requests), Rate limit exceeded" in e:
									restabit = 1
									limits()
							if "Twitter API returned a 403 (Forbidden), You have already retweeted this tweet." in e:
									print "Already Retweet trying next one"
									apicall = apicall + 1
									Saveid(FinalItem)
							if "(110, 'ETIMEDOUT')" in e:
									print " Mysterious Timeout ..."
									twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
									restabit = 1
									limits()

									#time.sleep(1)
def tweetlist(point,id):


        Fig = Figlet(font='rev')
        print Fig.renderText('Tweetlist()')
        ammo = str(point) + "-" + str(id)
        retweetlist.append(ammo)
#	time.sleep(1)
	print "=="
        Fig = Figlet(font='epic')
        print Fig.renderText('Loaded into Queue !')
	print "=="
	print
	#time.sleep(1)




def limits():
        Fig = Figlet(font='rev')
        print Fig.renderText('Limits()')

#	time.sleep(1)
	global apicall
	global updatecall
	global totalupdatecall
	global totalcall
	global twitter
	global searchlimit
	global restabit
	global waithour


	if waithour == 1:

                print
                print
                print
                print
                print
                print

                print "****************************************"
                print "****************************************"
                print
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ARE REACHED !!')
                print ""
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving current Search Terms')

                lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='basic')
                print Fig.renderText('Resetting current apicalls')

                updatecall = 0
                apicall = 0
                searchlimit = 0
                restabit = 0
		waithour = 0
                Fig = Figlet(font='epic')
                print Fig.renderText('Login Out')
                print
                Fig = Figlet(font='basic')
                print Fig.renderText('Waiting 30 minutes')

                for i in xrange(1800,0,-1):
                        time.sleep(1)
                        sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
                        sys.stdout.flush()

                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waking up ..')
                time.sleep(1)
                print ""
                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
                print

                print

	if restabit == 1:
		print
                print
                print
                print
                print
                print

                print "****************************************"
                print "****************************************"
                print
	        Fig = Figlet(font='epic')
	        print Fig.renderText('CURRENT LIMITS ALMOST REACHED')
                print ""
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving current Search Terms')

		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='basic')
                print Fig.renderText('Resetting current apicalls')

                updatecall = 0
                apicall = 0
                searchlimit = 0
		restabit = 0
                Fig = Figlet(font='epic')
                print Fig.renderText('Login Out')
		print
                Fig = Figlet(font='basic')
                print Fig.renderText('Waiting 15 minutes')

                for i in xrange(900,0,-1):
                        time.sleep(1)
                        sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
                        sys.stdout.flush()

                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waking up ..')
		time.sleep(1)
                print ""
                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
                print

		print

	if searchlimit == 1:
                print
                print
                print
                print
                print
                print
		
                print "****************************************"
                print "****************************************"
                print
                Fig = Figlet(font='epic')
                print Fig.renderText('SEARCH LIMITS ALMOST REACHED')
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='basic')
                print Fig.renderText('Resetting current apicalls')
                updatecall = 0
                apicall = 0
		searchlimit = 0

                Fig = Figlet(font='epic')
                print Fig.renderText('Login Out')
		print
                Fig = Figlet(font='basic')
                print Fig.renderText('Waiting 15 minutes')

                for i in xrange(900,0,-1):
                        time.sleep(1)
                        sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
                        sys.stdout.flush()

                Fig = Figlet(font='doh')
                print Fig.renderText('Waking up ..')
                print ""
                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
                print
                print "****************************************"
                print "****************************************"
                print
                print
                print
                print
                print
                print


	if apicall >= 165:
		print
                print
                print
                print
                print
                print

		print "****************************************"
		print "****************************************"
		print
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ALMOST REACHED')
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='basic')
                print Fig.renderText('Resetting current apicalls')
		updatecall = 0
                apicall = 0

                Fig = Figlet(font='epic')
                print Fig.renderText('Login Out')
		print
                Fig = Figlet(font='basic')
                print Fig.renderText('Waiting 15 minutes')

		
		for i in xrange(900,0,-1):
    			time.sleep(1)
			sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
			sys.stdout.flush()

                Fig = Figlet(font='doh')
                print Fig.renderText('Waking up ..')
		print ""
		twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
                print
                print "****************************************"
                print "****************************************"
                print
                print
                print
                print
                print
                print


	if totalcall > 6666:
                print
                print
                print
                print
                print

                print "****************************************"
                print "****************************************"
                print

                print
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ALMOST REACHED (total)')
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='basic')
                print Fig.renderText('Resetting current apicalls')
		sys.exit()

	if totalupdatecall > 2223:

                print
                print
                print
                print
                print
                print "****************************************"
                print "****************************************"
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ALMOST REACHED (update)')
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='basic')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='basic')
                print Fig.renderText('Resetting current apicalls')
 
 		sys.exit()

        print
        print "==================="
#       print "Current Apicall = ",apicall
#       print "Total call = ",totalcall
#       print "="
#       print "Current Update call =",updatecall
#        print "Total Update call = ",totalupdatecall
        Fig = Figlet(font='doh')
        print Fig.renderText('Ok')
        print "==================="
        #time.sleep(1)




def Ban(tweet,sender,id):

	global Banned
        Fig = Figlet(font='rev')
        print Fig.renderText('Ban()')
	print
	print "*=*=*=*=*=*=*=*=*=*"
	print "Checking if this Tweet contains any forbidden terms:"
	print

	for forbid in banlist:
		if forbid.lower() in tweet.lower():

			print
	                Fig = Figlet(font='cybermedium')
	                print Fig.renderText('This tweet contains banned words :')
			print
			print tweet
			print
			print "** %s **" % forbid
			print
			print Fig.renderText('Going To Trash ...')
			print "*=*=*=*=*=*=*=*=*=*"
			print
			Banned = 1
			#time.sleep(1)

        for forbid in banppl:
                if forbid in sender:

                        print
	                Fig = Figlet(font='cybermedium')
	                print Fig.renderText('This tweet is from a banned user :')
                        print
                        print tweet
                        print
			print "** %s **",forbid
			print
                        print Fig.renderText('Going To Trash')
                        print "*=*=*=*=*=*=*=*=*=*"
                        print
                        Banned = 1
                        #time.sleep(2)

        for forbid in bandouble:
                if forbid in tweet:

                        print
                        Fig = Figlet(font='cybermedium')
                        print Fig.renderText('This tweet is Identical to a Previous tweet :')
                        print
                        print tweet
                        print
			Saveid(id)
                        print
                        print Fig.renderText('Going To Trash')
                        print "*=*=*=*=*=*=*=*=*=*"
                        print
                        Banned = 1
                        #time.sleep(2)


	for item in bandouble:

	    if Banned == 0:
		pos = 0
		lng = len(item)
		half = lng / 2
		next = half + pos
		sample = item[pos:half]
	        maxpos = pos + len(sample)

		while maxpos < lng:


			if sample in tweet:
				print
	                        Fig = Figlet(font='cybermedium')
        	                print Fig.renderText('Some parts are Identicals to a Previous Tweet :')
	                        print tweet
	                        print
	                        Saveid(id)
	                        print
	                        print Fig.renderText('Going To Trash')
	                        print "*=*=*=*=*=*=*=*=*=*"


				print
				maxpos = lng
				Banned = 1
			else:
				pos = pos + 1
			        next = half + pos
			        sample = item[pos:next]
			        maxpos = pos + len(sample)



	if Banned == 0:

                Fig = Figlet(font='speed')
                print Fig.renderText('Good To Go !!')
	        print "*=*=*=*=*=*=*=*=*=*"
		print
		#time.sleep(1)


def Saveid(id):

                Fig = Figlet(font='rev')
                print Fig.renderText('Saveid()')
		print
#		time.sleep(1)

                try:
                        file = open(idsaved,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Id Saved)"
                        print "Creating file"
                        print "=="
                        file = open(idsaved,"w")
                        file.write("")
                        file.close()

                file = open(idsaved,"a")
                file.write("\n"+str(id))
		file.close()

		print
		print
		print "*=*=*=*=*=*=*=*=*=*"
		print "Id :",id
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Saved')
		print "*=*=*=*=*=*=*=*=*=*"
		print
		print
		time.sleep(1)


def Idlist(id):

		global alreadysend

                Fig = Figlet(font='rev')
                print Fig.renderText('Idlist()')
#		time.sleep(1)

		alreadysend = 0

                try:
                        file = open(idsaved,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Id Saved)"
                        print "Creating file"
                        print "=="
                        file = open(idsaved,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(idsaved, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

		with open(idsaved, "w") as f:
		    f.writelines('\n'.join(clean_lines))


		file = open(idsaved,"r+")
                lines = file.read().splitlines()

		for saved in lines:

		   if saved != "\n" or saved != "":
		   	if str(saved) in str(id):

					print
					print "*=*=*=*=*=*=*=*=*=*"
                                        print "Id from file :",saved
                                        print "tweet id :",id
					print "*=*=*=*=*=*=*=*=*=*"
					print
				
					alreadysend = 1
					#time.sleep(2)


		if alreadysend == 0:

			print
			print "*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
                	Fig = Figlet(font='basic')
                	print Fig.renderText('Unknown Tweet ID')

			print "*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
			print
			#time.sleep(1)




def Scoring(tweet,search):

	global apicall
	global totalcall
	global updatecall
	global totalupdatecall
	global Banned
	global bandouble
	global alreadysend

	Score = 0
	Banned = 0
	alreadysend = 0
	now = datetime.datetime.now()

	print
	print
	print
      	Fig = Figlet(font='rev')
        print Fig.renderText('Scoring()')
	print
	#time.sleep(1)

	print
	print
	print
        print "*************************************************************************************" 
        Fig = Figlet(font='basic')
        print Fig.renderText('Starting Scoring function')
	print ""



	if 'retweet_count' in tweet and tweet['retweet_count'] != 0:

			print "##"
			print "This tweet has been retweeted %i times " % tweet['retweet_count']
			print "##"

			Score = Score + 1
			if tweet['retweet_count'] > 3 and tweet['retweet_count'] <= 5:
				Score  = Score + 3
                        if tweet['retweet_count'] > 5 and tweet['retweet_count'] <= 10:
                                Score  = Score + 4
                        if tweet['retweet_count'] > 10 and tweet['retweet_count'] <= 15:
                                Score  = Score + 6
                        if tweet['retweet_count'] > 15 and tweet['retweet_count'] <= 20:
                                Score  = Score + 8
                        if tweet['retweet_count'] > 20 and tweet['retweet_count'] <= 25:
                                Score  = Score + 10
                        if tweet['retweet_count'] > 25 and tweet['retweet_count'] <= 30:
                                Score  = Score + 11
                        if tweet['retweet_count'] > 30 and tweet['retweet_count'] <= 35:
                                Score  = Score + 12
                        if tweet['retweet_count'] > 35 and tweet['retweet_count'] <= 40:
                                Score  = Score + 13
                        if tweet['retweet_count'] > 40 and tweet['retweet_count'] <= 45:
                                Score  = Score + 14
                        if tweet['retweet_count'] > 45 and tweet['retweet_count'] <= 50:
                                Score  = Score + 15
                        if tweet['retweet_count'] > 50 and tweet['retweet_count'] <= 55:
                                Score  = Score + 16
                        if tweet['retweet_count'] > 55 and tweet['retweet_count'] <= 60:
                                Score  = Score + 17
                        if tweet['retweet_count'] > 60 and tweet['retweet_count'] <= 65:
                                Score  = Score + 18
                        if tweet['retweet_count'] > 65 and tweet['retweet_count'] <= 70:
                                Score  = Score + 19
                        if tweet['retweet_count'] > 70 and tweet['retweet_count'] <= 75:
                                Score  = Score + 20
                        if tweet['retweet_count'] > 75 and tweet['retweet_count'] <= 80:
                                Score  = Score + 21
                        if tweet['retweet_count'] > 80 and tweet['retweet_count'] <= 85:
                                Score  = Score + 22
                        if tweet['retweet_count'] > 85 and tweet['retweet_count'] <= 90:
                                Score  = Score + 23
                        if tweet['retweet_count'] > 90:
                                Score  = Score + 23 + 3





        if 'entities' in tweet:
		print


		if 'urls' in tweet['entities'] and len(tweet['entities']['urls']) > 0:
			print "##"
			print "This tweet contains a link : ",tweet['entities']['urls'][-1]['expanded_url']
			print "##"
			Score = Score + 1
                if 'hashtags' in tweet['entities'] and len(tweet['entities']['hashtags']) > 0:
			print "##"
                        print "This tweet contains Hashtag : ",tweet['entities']['hashtags'][-1]['text']
			print "##"
                        Score = Score + 1


                if 'media' in tweet['entities'] and len(tweet['entities']['media']) > 0:
			print "##"
                        print "This tweet contains Media : ",tweet['entities']['media'][-1]['media_url']
			print "##"
                        Score = Score + 1

                if tweet['favorite_count'] > 0:

			print "##"
                        print "This tweet has been fav : ",tweet['favorite_count']
			print "##"
			Score = Score + 1
			fav = tweet['favorite_count']
			if fav > 1 and fav < 5:
                        	Score = Score + 1
			if fav > 5 and fav < 10:
				Score = Score + 2
			if fav > 10 and fav < 15:
				Score = Score + 3
                        if fav > 15 and fav < 20:
                                Score = Score + 4
                        if fav > 20 and fav < 25:
                                Score = Score + 5
                        if fav > 25 and fav < 30:
                                Score = Score + 6
                        if fav > 30 and fav < 35:
                                Score = Score + 7
                        if fav > 35 and fav < 40:
                                Score = Score + 8
                        if fav > 40 and fav < 45:
                                Score = Score + 9
                        if fav > 45 and fav < 50:
                                Score = Score + 10 
                        if fav > 50 and fav < 55:
                                Score = Score + 11
                        if fav > 55 and fav < 60:
                                Score = Score + 12
                        if fav > 60 and fav < 65:
                                Score = Score + 13
                        if fav > 65 and fav < 70:
                                Score = Score + 14
                        if fav > 70 and fav < 75:
                                Score = Score + 15
                        if fav > 75 and fav < 80:
                                Score = Score + 16
                        if fav > 80 and fav < 85:
                                Score = Score + 17
                        if fav > 85 and fav < 90:
                                Score = Score + 18
                        if fav > 90 and fav < 95:
                                Score = Score + 19 
                        if fav > 95 and fav < 100:
                                Score = Score + 20
                        if fav > 100 and fav < 105:
                                Score = Score + 21
                        if fav > 105 and fav < 110:
                                Score = Score + 22
                        if fav >= 123:
                                Score = Score + 23 + 3






                if 'followers_count' in tweet['user'] and tweet['user']['followers_count'] > 0:
			print "##"
                        print "Source followers count  : ",tweet['user']['followers_count']
			print "##"
                        if tweet['user']['followers_count'] > 100 and tweet['user']['followers_count'] < 200:
                                Score  = Score + 1
                        if tweet['user']['followers_count'] > 200 and tweet['user']['followers_count'] < 300:
                                Score  = Score + 2
                        if tweet['user']['followers_count'] > 300 and tweet['user']['followers_count'] < 400:
                                Score  = Score + 3
                        if tweet['user']['followers_count'] > 400  and tweet['user']['followers_count'] < 500:
                                Score  = Score + 4
                        if tweet['user']['followers_count'] > 500 and tweet['user']['followers_count'] < 600:
                                Score  = Score + 5
                        if tweet['user']['followers_count'] > 600 and tweet['user']['followers_count'] < 700:
                                Score  = Score + 6
                        if tweet['user']['followers_count'] > 700 and tweet['user']['followers_count'] < 800:
                                Score  = Score + 7
                        if tweet['user']['followers_count'] > 800 and tweet['user']['followers_count'] < 900:
                                Score  = Score + 8
                        if tweet['user']['followers_count'] > 900 and tweet['user']['followers_count'] < 1000:
                                Score  = Score + 9
                        if tweet['user']['followers_count'] > 1000 and tweet['user']['followers_count'] < 1500:
                                Score  = Score + 10
                        if tweet['user']['followers_count'] > 1500 and tweet['user']['followers_count'] < 2000:
                                Score  = Score + 11
                        if tweet['user']['followers_count'] > 2000 and tweet['user']['followers_count'] < 2500:
                                Score  = Score + 12
                        if tweet['user']['followers_count'] > 2500 and tweet['user']['followers_count'] < 3000:
                                Score  = Score + 13
                        if tweet['user']['followers_count'] > 3000 and tweet['user']['followers_count'] < 3500:
                                Score  = Score + 14
                        if tweet['user']['followers_count'] > 3500 and tweet['user']['followers_count'] < 4000:
                                Score  = Score + 15
                        if tweet['user']['followers_count'] > 4000 and tweet['user']['followers_count'] < 4500:
                                Score  = Score + 16
                        if tweet['user']['followers_count'] > 4500 and tweet['user']['followers_count'] < 5000:
                                Score  = Score + 17
                        if tweet['user']['followers_count'] > 5000 and tweet['user']['followers_count'] < 6000:
                                Score  = Score + 18
                        if tweet['user']['followers_count'] > 6000 and tweet['user']['followers_count'] < 7000:
                                Score  = Score + 19
                        if tweet['user']['followers_count'] > 7000 and tweet['user']['followers_count'] < 8000:
                                Score  = Score + 20
                        if tweet['user']['followers_count'] > 8000 and tweet['user']['followers_count'] < 9000:
                                Score  = Score + 21
                        if tweet['user']['followers_count'] > 9000 and tweet['user']['followers_count'] < 10000:
                                Score  = Score + 22
                        if tweet['user']['followers_count'] > 10000:
                                Score  = Score + 23

                if 'user_mentions' in tweet['entities'] and len(tweet['entities']['user_mentions']) > 0:
                        print "##"
                        print "This tweet is mentioning someone : ",tweet['entities']['user_mentions'][-1]['screen_name']
                        print "##"
                        Score = Score + 1



			print 

                if 'verified' in tweet['entities'] and len(tweet['entities']['verified']) == "True":
			print "##"
                        print "This tweet has been sent by a verified user : ",tweet['entities']['verified']
			print "##"
                        Score = Score + 5


                if 'screen_name' in tweet['user'] :
			coop = tweet['user']['screen_name']
			print
			print "##"
			print "This tweet is from ",coop
			print "##"
			print

			if coop in Following:
				print "##"
	                        print "This tweet is from a known user : ",tweet['user']['screen_name']
				print "##"
        	                Score = Score + 23

			if coop in Friends:
				print "##"
				print "This tweet is from a friend : ",tweet['user']['screen_name']
				print "##"

				Score = Score + 23


	TwtTime = tweet['created_at']
        TwtTime = TwtTime.replace(" +0000 "," ")
        Timed = datetime.datetime.strptime(TwtTime,'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
	TimeFinal = datetime.datetime.strptime(Timed,'%Y-%m-%d %H:%M:%S')
	hourtweet = now - TimeFinal
	print
	print "This tweet was send at : ",TwtTime
	print

	if hourtweet.seconds < 3600:
		Score = Score + 2 + 3 + 2 + 3
		print "Less than an hour ago ."
		print "Score = + 10"
		print

	if hourtweet.seconds > 3600 and hourtweet.seconds <= 7200:
		Score = Score + 2 + 3 + 2 + 2
		print "An hour ago ."
		print "Score = + 9"

        if hourtweet.seconds > 7200 and hourtweet.seconds <= 10800:
                Score = Score + 2 + 3 + 2 + 1
                print "Two hours ago ."
		print "Score = + 8"

        if hourtweet.seconds > 10800 and hourtweet.seconds <= 14400:
                Score = Score + 2 + 3 + 2 
                print "Three hours ago ."
		print "Score = + 7"

        if hourtweet.seconds > 14400 and hourtweet.seconds <= 18000:
                Score = Score + 2 + 3 + 1
                print "Four hours ago ."
		print "Score = + 6"

        if hourtweet.seconds > 18000 and hourtweet.seconds <= 21600:
                Score = Score + 2 + 3
                print "Five hours ago ."
		print "Score = + 5"

        if hourtweet.seconds > 21600 and hourtweet.seconds <= 25200:
                Score = Score + 2 + 2
                print "Six hours ago ."
		print "Score = + 4"

        if hourtweet.seconds > 25200 and hourtweet.seconds <= 28800:
		Score = Score + 2 + 1
                print "Seven hours ago ."
		print "Score = + 3"

        if hourtweet.seconds > 28800 and hourtweet.seconds <= 32400:
                Score = Score + 2
                print "Eight hours ago ."
                print "Score = + 2"

        if hourtweet.seconds > 32400 and hourtweet.seconds <= 36000:
                Score = Score + 1
                print "Nine hours ago ."
                print "Score = + 1"
        if hourtweet.seconds > 36000 and hourtweet.seconds <= 39600:
                print "Ten hours ago ."
                print "Score = + 0"

        if hourtweet.seconds > 39600 and hourtweet.seconds <= 43200:
                Score = Score - 1
                print "Eleven hours ago ."
                print "Score = - 1"

	if hourtweet.seconds > 43200 and hourtweet.seconds <= 46800:
		print "Twelve hours ago ."
		Score = Score - 2
                print "Score = - 2"


        if hourtweet.seconds > 46800 and hourtweet.seconds <= 50400:
                Score = Score - 3
                print "Thirteen hours ago ."
                print "Score = - 3"


        if hourtweet.seconds > 50400 and hourtweet.seconds <= 54000:
                Score = Score - 4
                print "Fourteen hours ago ."
                print "Score = - 4"


        if hourtweet.seconds > 54000 and hourtweet.seconds <= 57600:
                Score = Score - 5
                print "Fiveteen hours ago ."
                print "Score = - 5"



        if hourtweet.seconds > 57600 and hourtweet.seconds <= 61200:
                Score = Score - 6
                print "Sixteen hours ago ."
                print "Score = - 6"


        if hourtweet.seconds > 61200 and hourtweet.seconds <= 64800:
                Score = Score - 7
                print "Seventeen hours ago ."
                print "Score = - 7"


        if hourtweet.seconds > 68400 and hourtweet.seconds <= 72000:
                Score = Score - 8
                print "Eighteen hours ago ."
                print "Score = - 8"


        if hourtweet.seconds > 72000 and hourtweet.seconds <= 75600:
                Score = Score - 9
                print "Nineteen hours ago ."
                print "Score = - 9"


        if hourtweet.seconds > 75600 and hourtweet.seconds <= 79200:
                Score = Score - 10
                print "Twenty hours ago ."
                print "Score = - 10"

        if hourtweet.seconds > 79200 and hourtweet.seconds <= 82800:
                Score = Score - 11
                print "Twenty one hours ago ."
                print "Score = - 11"

        if hourtweet.seconds > 82800 and hourtweet.seconds <= 86400:
                print "Twenty two hours ago ."
		Score = Score - 12
                print "Score = - 12"

        if hourtweet.seconds > 86400 and hourtweet.seconds <= 90000:
                Score = Score - 13
                print "Twenty three hours ago ."
                print "Score = - 13"

        if hourtweet.seconds > 90000 and hourtweet.seconds <= 93600:
                print "Twenty four hours ago ."
                Score = Score - 14
                print "Score = - 14"

        if hourtweet.seconds > 93600 and hourtweet.seconds <= 97200:
                print "One Day ago ."
		Score = Score - 15
                print "Score = - 15"

        if hourtweet.seconds > 97200 and hourtweet.seconds <= 100800:
                Score = Score - 16
                print "One day and an hour ago."
                print "Score = - 16"

        if hourtweet.seconds > 100800 and hourtweet.seconds <= 104400:
                Score = Score  - 17
                print "One day and two hours ago ."
                print "Score = - 17"

        if hourtweet.seconds > 104400 and hourtweet.seconds <= 108000:
                Score = Score - 18
                print "One day and three hours ago ."
                print "Score = - 18"

        if hourtweet.seconds > 108000 and hourtweet.seconds <= 111600:
                Score = Score - 19
                print "One day and four hours ago ."
                print "Score = - 19"

        if hourtweet.seconds > 111600 and hourtweet.seconds <= 115200:
                Score = Score - 20
                print "One day and five hours ago ."
                print "Score = - 9"

        if hourtweet.seconds > 115200 and hourtweet.seconds <= 118800:
                print "One day and six hours ago ."
                Score = Score - 21
                print "Score = - 21"

        if hourtweet.seconds > 118800 and hourtweet.seconds <= 122400:
                Score = Score - 22
                print "One day and seven hours ago ."
                print "Score = - 22"

        if hourtweet.seconds > 122400 and hourtweet.seconds <= 126000:
                print "One day and eight hours ago ."
                Score = Score - 23
                print "Score = - 23"

        if hourtweet.seconds > 126000 and hourtweet.seconds <= 129600:
                print "One day and nine hours ago ."
                Score = Score - 24
                print "Score = - 24"

        if hourtweet.seconds > 129600 and hourtweet.seconds <= 133200:
                Score = Score - 25
                print "One day and ten hours ago ."
                print "Score = - 25"

        if hourtweet.seconds > 133200 and hourtweet.seconds <= 136800:
                print "One day and eleven hours ago ."
                Score = Score - 26
                print "Score = - 26"

        if hourtweet.seconds > 136800 and hourtweet.seconds <= 140400:
                print "One Day and twelve hours ago ."
                Score = Score - 27
                print "Score = - 27"

        if hourtweet.seconds > 140400 and hourtweet.seconds <= 144000:
                Score = Score - 28
                print "One Day and thirteen hours ago ."
                print "Score = - 28"

        if hourtweet.seconds > 144000 and hourtweet.seconds <= 147600:
                print "One Day and fourteen hours ago ."
                Score = Score - 29
                print "Score = - 29"

        if hourtweet.seconds > 147600 and hourtweet.seconds <= 151200:
                Score = Score - 30
                print "One Day and Fiveteen hours ago ."
                print "Score = - 30"

        if hourtweet.seconds > 151200 and hourtweet.seconds <= 154800:
                Score = Score - 31
                print "One Day and Sixteen hours ago."
                print "Score = - 31"

        if hourtweet.seconds > 154800 and hourtweet.seconds <= 158400:
                Score = Score - 32
                print "One Day and Seventeen hours ago ."
                print "Score = - 32"

        if hourtweet.seconds > 158400 and hourtweet.seconds <= 162000:
                Score = Score - 33
                print "One Day and Eighteen hours ago ."
                print "Score = - 33"

        if hourtweet.seconds > 162000 and hourtweet.seconds <= 165600:
                Score = Score - 34
                print "One Day and Nineteen hours ago ."
                print "Score = - 34"

        if hourtweet.seconds > 165600 and hourtweet.seconds <= 169200:
                Score = Score - 35
                print "One Day and Twenty hours ago ."
                print "Score = - 35"

        if hourtweet.seconds > 169200 and hourtweet.seconds <= 172800:
                print "One Day and Twenty one hours ago ."
                Score = Score - 36
                print "Score = - 36"

        if hourtweet.seconds > 172800 and hourtweet.seconds <= 176400:
                Score = Score - 37
                print "One Day and Twenty two hours ago ."
                print "Score = - 37"

        if hourtweet.seconds > 176400 and hourtweet.seconds <= 180000:
                print "One Day and Twenty four hours ago ."
                Score = Score - 38
                print "Score = - 38"

        if hourtweet.seconds > 180000 and hourtweet.seconds <= 183600:
                Score = Score - 39
                print "Two Day ago ."
                print "Score = - 39"

        if hourtweet.seconds > 183600 and hourtweet.seconds <= 187200:
                Score = Score - 40
                print "Two Day and one hours ago."
                print "Score = - 40"

        if hourtweet.seconds > 187200 and hourtweet.seconds <= 190800:
                Score = Score - 41
                print "Two Day and two hours ago ."
                print "Score = - 41"

        if hourtweet.seconds > 190800 and hourtweet.seconds <= 194400:
                Score = Score - 42
                print "Two Day and three hours ago ."
                print "Score = - 42"

        if hourtweet.seconds > 194400 and hourtweet.seconds <= 198000:
                Score = Score - 43
                print "Two Day and four hours ago ."
                print "Score = - 43"

        if hourtweet.seconds > 198000 and hourtweet.seconds <= 201600:
                Score = Score - 44
                print "Two Day and five hours ago ."
                print "Score = - 44"

        if hourtweet.seconds > 201600 and hourtweet.seconds <= 205200:
                print "Two Day and six hours ago ."
                Score = Score - 45
                print "Score = - 45"

        if hourtweet.seconds > 205200 and hourtweet.seconds <= 208800:
                Score = Score - 46
                print "Two Day and seven hours ago ."
                print "Score = - 46"

        if hourtweet.seconds > 208800 and hourtweet.seconds <= 212400:
                print "Two Day and eight hours ago ."
                Score = Score - 47
                print "Score = - 47"

        if hourtweet.seconds > 212400 and hourtweet.seconds <= 216000:
                Score = Score - 48
                print "Two Day and nine hours ago ."
                print "Score = - 48"

        if hourtweet.seconds > 216000 and hourtweet.seconds <= 219600:
                Score = Score - 49
                print "Two Day and ten hours ago ."
                print "Score = - 49"

        if hourtweet.seconds > 219600 and hourtweet.seconds <= 223200:
                print "Two Day and eleven hours ago ."
                Score = Score - 50
                print "Score = - 50"

        if hourtweet.seconds > 223200 and hourtweet.seconds <= 226800:
                Score = Score - 51
                print "Two Day and twelve hours ago ."
                print "Score = - 51"

        if hourtweet.seconds > 226800:
                print "More than Two Day and Twelve hours."
                Score = Score - 123
                print "Score = - 123"





	if tweet['lang'] == "en" or tweet['lang'] == "fr" or tweet['lang'] == "en-gb":

		Idlist(tweet['id'])

		if alreadysend == 0:

			Ban(tweet['text'],tweet['user']['screen_name'],tweet['id'])

			if Banned == 0:
				if Score >= 24 :
					print
					print
					print
					print "######################################"
                			Fig = Figlet(font='basic')
                			print Fig.renderText('Adding to Retweet List')
					print
					print "Nbr of tweets in queue :",len(retweetlist)
					print "Tweet Score : ",Score
					print "Tweet ID :", tweet['id']
					print "Current ApiCall Count :",apicall
	                                print "Total Number Of Calls :",totalcall
					print "Current Update Status Count :",updatecall
					print "Total Number Of Update Calls :",totalupdatecall
					print "Search Call left :",search
					print "Tweet :", tweet['text']
					print "######################################"
					print ""
					print
					print
					print
					time.sleep(1)
					bandouble.append(tweet['text'])
					tweetlist(Score,tweet['id'])
				else:
					print ""
                                        Fig = Figlet(font='epic')
                                        print Fig.renderText("But ..")
                                        print "================================================================================"
                                        Fig = Figlet(font='cybermedium')
                                        print Fig.renderText("Score")
                                        print "================================================================================"
					print tweet['text']
					print "================================================================================"
					print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
					print "This tweet does not match the requirement to be retweeted. (Score)"
					print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
					print "================================================================================"
					print ""
		
					time.sleep(1)
			else:
	                                print ""
                                        Fig = Figlet(font='epic')
                                        print Fig.renderText("Verdict:")
	                                print "================================================================================"
        	                        Fig = Figlet(font='cybermedium')
                	                print Fig.renderText("Banned")
                                        print "================================================================================"
                                        print tweet['text']

	                                print "================================================================================"
	                                print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
	                                print "This tweet does not match the requirement to be retweeted."
	                                print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
	                                print "================================================================================"
	                                print ""
					time.sleep(1)
		else:
			                print ""
                                	Fig = Figlet(font='epic')
                                	print Fig.renderText("But ..")
                                        print "================================================================================"
                                        Fig = Figlet(font='cybermedium')
                                        print Fig.renderText("Already sent !")
                                        print "================================================================================"
                                        print tweet['text']

                                        print "==================================="
                                        print ":( :( :( :( :( :( :( :( :( :( :( :("
                                        print "This tweet has been already sent .."
                                        print ":( :( :( :( :( :( :( :( :( :( :( :("
                                        print "==================================="
                                        print ""
					alreadysend = 0
                                        time.sleep(1)



	else:
				print
                                Fig = Figlet(font='epic')
                                print Fig.renderText("but ..")
                                print "================================================================================"
				Fig = Figlet(font='cybermedium')
				print Fig.renderText("Language")
                                print "================================================================================"
                                print tweet['text']

				print "================================================================================"
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
                                print "This tweet does not match the requirement needed to be retweeted."
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
				print "================================================================================"
                                print ""
				time.sleep(1)

#        #time.sleep(1)


	print
	print






def searchTst(word):
	global apicall
	global updatecall
	global twitter
	global restabit
        Fig = Figlet(font='rev')
        print Fig.renderText('SearchTst()')
	#time.sleep(1)
	ratechk = 0

	try :
                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
        	rate = twitter.get_application_rate_limit_status()
	        search = rate['resources']['search']['/search/tweets']['remaining']

		apicall = apicall + 3
		ratechk = 1

        except Exception as e:

		print "mysterious error"
		print
		print e
                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
		apicall = apicall + 1
		restabit = 1
		limits()

	if ratechk == 1:

                rate = twitter.get_application_rate_limit_status()
                search = rate['resources']['search']['/search/tweets']['remaining']

		apicall = apicall + 2

		if search != ["2"]:
		        print
		        print
		        print
		        print
		        print
		        print
		        print

			print
			print "##########################################"
			print "**"
                	Fig = Figlet(font='doom')
                	print Fig.renderText('Starting search function')
			print "**"
	                print "##########################################"

			print
			print "=/\/\/\/\/\/\/\/\/\/\/\="
                	Fig = Figlet(font='basic')
                	print Fig.renderText('Calling Limit function')
			print "=/\/\/\/\/\/\/\/\/\/\/\="
	
			limits()
			try:
		        	searchresults = twitter.search(q=word, count = 200)
				print "##########################################"
                		Fig = Figlet(font='colossal')
                		print Fig.renderText('Results Found !')
				print ""
				apicall = apicall + 1
				#time.sleep(1)
		
		        except :
						apicall = apicall + 1
						print
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		                                print "Error Sorry im trying next one"
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
						print
		
			try:
				print
				print "=="
				print "Loading tweets for " + word
				twitter.send_direct_message(user_id="292453904", text="Chargement des tweets pour " + str(word))
				print ""
				#time.sleep(1)
                		Fig = Figlet(font='basic')
                		print Fig.renderText('Status Sent !')
				print "=="
				print ""
				time.sleep(1)
				
				apicall = apicall +1
				updatecall = updatecall +1
				print ""
	
			except:
						apicall = apicall + 1
	                                        print
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	                                        print "Error Sorry trying next one"
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	                                        print
						#time.sleep(1)
			print
			print
	                print "##########################################"
			print "**"
                	Fig = Figlet(font='doom')
                	print Fig.renderText('Search function Terminated')
			print "**"
			print "##########################################"
		
		        print
		        print
		        print
		        print
		        print
		        print
		        print
	
			if len(searchresults["statuses"]) > 3 :
	
			        for item in searchresults["statuses"]:
		
					Scoring(item,search)
			else:
				print "****************************************"
				print
                		Fig = Figlet(font='caligraphy')
                		print Fig.renderText('No Result')
				print
				print

				print "????????????????????????????"
				print "Sorry not enough results for : ",word
				print "Maybe you should consider changing it "
				print "????????????????????????????"
				print
				print
				print
				print "****************************************"
                		Fig = Figlet(font='basic')
                		print Fig.renderText('Saving unwanted search to no.result')
				time.sleep(3)
		                try:
        		                file = open(noresult,"r")
                		        file.close()
               			except:
		                        print "=="
		                        print "File does not exist (No Results)"
		                        print "Creating file"
		                        print "=="
		                        file = open(noresult,"w")
		                        file.write("")
		                        file.close()

                                file = open(noresult,"a")
                                file.write(str(word) + "\n")
                                file.close()
	
		else:
	                print
			searchlimit = 1
			limits()



#Some Code

print "=/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText('Calling Flush function')
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
flushtmp()
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText('Calling Search function')
print "=/\/\/\/\/\/\/\/\/\/\/\/\="

Minwords = len(Keywords)/40
Maxwords = len(Keywords)/20
rndwords = random.randint(Minwords,Maxwords)

print
print "**"
Fig = Figlet(font='calgphy2')
print Fig.renderText("Today's Menu :")
print
print Keywords[:rndwords]
print
print "Total search terms : ",rndwords
print
print "**"
print
time.sleep(5)
print
print
print
print
print "=/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='cybermedium')
print Fig.renderText("Check Last Menu started")
print "=/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\="
print
print
print

checkmenu(Keywords)

if checkM == 1:
	Keywords = newkeywords
	print
	print
	print "**"
	print
	print "=="
	Fig = Figlet(font='basic')
	print Fig.renderText("New Menu for today !")
	print "=="
	print
	print
	print Keywords[:rndwords]
	print
	print "Total search terms : ",rndwords
	print
	print
	print "**"
	print
	time.sleep(5)

for key in Keywords[:rndwords]:
	searchTst(key)
	

print
print
print
print "=/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText("All Done !")
print "=/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\="
print

print "=/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText("Calling Retweet function")
print "=/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\="
print
print
print
print
print
print
print
print

allok = 1

Retweet()
print 
print
print
print
print
print
print
#time.sleep(1)
print
print
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText("Retweet function stopped")
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
print
#time.sleep(1)
print "=/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText("Calling Saving call function")
print "=/\/\/\/\/\/\/\/\/\="
print
#time.sleep(1)
SaveTotalCall(apicall,updatecall)
print 
print
print
print
print
print
print
print
print "=/\/\/\/\/\/\/\/\/\/="
Fig = Figlet(font='basic')
print Fig.renderText("Calling Save Search Terms Function")
print "=/\/\/\/\/\/\/\/\/\/="
print 
print
print
print
#time.sleep(1)
lastmeal(Keywords[:rndwords])
print
print "##############################################################################################################"
print "##############################################################################################################"
Fig = Figlet(font='doh')
print Fig.renderText("The End")
print "##############################################################################################################"
print "##############################################################################################################"
print 
print
print
print
#################################################TheEnd#############################################################
#time.sleep(1)
