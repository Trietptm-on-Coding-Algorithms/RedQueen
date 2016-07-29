#!/usr/bin/python
import time
import random
import sys
import os
import datetime
from twython import Twython, TwythonError
from TwitterApiKeys import app_key, app_secret, oauth_token, oauth_token_secret
from operator import itemgetter


#Some Vars

day = datetime.date.today()
path = "./Tmp/"
TmpDay = str(path) + "total-" + str(day)
TmpDay2 = str(path) + "update-" + str(day)
TmpMeal = str(path) + "meal-" + str(day)
noresult = str(path) + "no.result"
idsaved = str(path) + "id.saved"

restabit = 0
0
twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)

Keywords = ["ack","angry fruit salad","automagically","Syrian Electronic Army","LulzSec","gray hat","Distributed denial of service","Denial of service","compiler","Clone phishing","TWEAK","PSEUDOPRIME","DAEMON","CRLF","COMM MODE","CANONICAL","Ethical Hacking","Skid","ANSI Bomb","blue hat","defaced","Dictionary Attack","doxing","DOX","FUD","Fully undetectable","grey hat","IP Grabbing","HOIC tool","LOIC tool","Rainbow Table","rat trojan","Remote Administration Tool","ring3","ring2","ring0","viri","warez","vps","worm malware","turing test","sysadmin","SaaS","stack buffer overflow","CA cert","Hardware vulnerability","physical backdoor","Vuln:","Vuln","adblocker","Exploit framework","crypto party","ssh","Passphrase","Linux Distro","RFC","Hardcoded","hackintosh","Os X","P2P","cloud-based","Oracle java","IT guy","Encrypted Chat","VmWare","cyber police","AdGholas","malvertising","hadopi","cnil","golang","hacked by","piratage","Postgresql","Julian Assange","DNC","GNU","QRLJacking","kevin mitnick","csrf exploit","session splicing","darkweb",".onion","wikileaks","wlan","Wireless Local Area Network","wardriving","Wireless Access Point","wep","cyber security","Wpa2","blackhat","Shellcode","vpn","Virtual Machine","sandboxing","crypto currency","Full Disclosure","Tunneling","Gps spoofing","untrusted Certificate","ransomware","Trojan Horse","Transport Layer Security","Triple DES","Assembly language","Remote desktop protocole","Traffic Encryption Key","security traffic Analysis","Tracking Cookie","tampered data","bluetooth flaw","data breach","script kiddie","brute force","Symmetric Key","Surrogate Access","Raspberry pi","Arduino","Steganography","Spyware","mail bombing","jailbreak","YesCard","Skimming","Phreaking","cracking","malloc","data Sensitivity","Python exploit","Ruby Exploit","security kernel","C++ exploit","reverse Engineering","Security Engineering","Perl Exploit","ssl","hacking tool","php vulnerability","Secure Hash Algorithm","DNS","Scatternet","Cult of the dead cow","javascript exploit","Sandboxing","Rootkit","Bash script","windbg","rogue device","ollydbg","winsdam","ip spoofing","Rijndael","apache vulnerability","darkdao","repository","shodan","scammers","critical vulnerability","code injection","Icedbg","RFID vulnerability","RFID flaw","Radio Frequency Identification","Gbd ida","private key","pseudorandom","Proxy Agent","tor network","vpn open source","memory corruption","proxy list","proxychain","data execution prevention","heap exploitation","bypass stack cookies","Fuzzing","integer overflow","hackathon","api key","1337","Social-Engeneering Toolkit","port scanner","bluetooth vulnerability","bluetooth flaw","nmap","mass port scanning","Payload","Framework","port knocking","wireless attack","log files","router vulnerability","packet sniffer","phpmyadmin vulnerability","open source","phbb vulnerability","password attack","penetration technique","browser exploit","warberrypi ","wordpress exploit","binary memory","byod","router exploit","Cookie stuffing","Windows stack overflow","shell exploit","message digest","Cryptosystem","reverse shell","MitM","hardware backdoor","malicious code","lfi exploit","magnetic remanence","data intercept","ip cam flaw","meterpreter","system level exploration","pastejacking","network takeover","Sphearphishing","key logger","key escrow","Kerberos","flood attack","injection fuzzer","ipsec","evading ids","system intrusion","ipv6","ipv4","Fake update","packet injection","bruteforcer xss","android vulnerability","linux vulnerability","ios vulnerability","artificial intelligence","windows vulnerability","magstripe spoofer","handshake protocole","audit tool","armitage","grey box testing","disk encryption","frequency hopping","forward cipher","subdomain enumeration","Firefox vulnerability","bypass firewall","file encryption","ssl tls interception","extranet","domaine name permutation","ftp vulnerability","fingerprint tool","rssi","visual analysis tool","end to end encryption","robots.txt","encrypted network","tinfoleak","infosec","encoding","voip vulnerability","embedded crypto","electronic signature","egress filtering","eavesdropping","dual use certificate","dmz","wireless scanner","decrypt","decipher","wireless audit","data security","data integrity","network mapper","data encryption standard","data encryption algorithm","incident response tool","defcon","cyber attack","web spider","cryptology","hash function","cryptographic","cryptanalysis","command injection","compression side-channel","credential","cover coding","xss spider","key generation","network exploitation","network attack","local pentest","COMSEC","CVS","common vulnerabilities","internet of things","misconfiguration","collision hash","internet of shit","cloud computing","clear text","Xor","checksum","bulk encryption","joomla vulnerability","sqli","data leak","users passwords","blackbox pentest","quantic computer","Critical patch","playstation jailbreak","banner grabbing","xbox jailbreak","backdoor infosec","hexadecimal","privacy windows","authentication token","authentication protocol","audit framework","open source security tool","magic number signature","BSides","antispyware","ip spoofing detection","QR code infosec","anonymous","advanced persistent threats","pirate bay","advanced encryption standard","admin account","add-on security","ad hoc network","hacked site","defaced","bypass login","cryptography","phishing infosec","honeypot","hacking","ddos","malware","rfid","patch flaw","SocialEngineering","0day","cross site scripting","cyber security","install backdoor","forensic","blind sql injection","local file inclusion","privilege escalation","hacker attack","request forgery","metasploit","password","sql injection","privilege elevation","drupal vulnerability","chinese hacker","penetration testing","header injection","pentest","man in the middle","man in the browser","remote access","java security","buffer overflow","keylog","nuke script","darknet","russian hacker","remote exploit","israel hack","ransomware","trojan","botnet","snowden","nsa","blackhat","whitehat","hacktivist","printer exploit"]

random.shuffle(Keywords)

Following = ['CUSecTech', 'InfoSecHotSpot', 'IndieRadioPlay', 'TopMaths', 'ergn_yldrm', 'MegalopolisToys', 'ISC2_Las_Vegas', 'jeffreycady', 'XenDesktop', 'BugBountyZone', 'sciendus', 'Dambermont', 'ghwizuuy', 'hackmiami', 'smirnovvahtang', 'uncl3dumby', 'theStump3r', 'SecureAuth', 'StagesInfograph', '9gnews365', 'secmo0on', 'alexheid', 'XenApp', 'vleescha1', 'CMDSP', 'abouham92597469', 'NetNeutralityTp', 'puja_mano', 'AliSniffer', 'DrupalTopNews', 'ChromeExtenNews', 'sebastien_i', 'Techworm_in', 'argevise', 'windows10apps4r', 'primeroinfotek', 'HAKTUTS', 'ciderpunx', 'kfalconspb', 'whitehatsec', 'furiousinfosec', 'Trencube_GD', 'CtrlSec', 'hacking_report', 'n0psl', 'CryptoKeeUK', '0xDUDE', 'crowd42', '_HarmO_', 'CNNum', 'OxHaK', 'Paddy2Paris', 'RevueduDigital', 'androidapps4rea', 'cryptoland', 'CombustibleAsso', 'geeknik', 'HansAmeel', 'cryptoishard', 'YoouKube', 'jouermoinscher', 'moixsec', 'cyberwar', 'danielbarger67', 'SecurityNewsbot', 'cityofcrows', 'SysAdm_Podcast', 'shafpatel', 'k4linux', 'Refuse_To_Fight', 'x_adn', 'Duffray14', 'AbdelahAbidi', 'pranyny', 'razlivintz', 'unmanarc', 'wallarm', 'foxooAnglet', 'foxoo64', 'brainhackerzz', 'duo_labs', 'zenterasystems', 'jilles_com', 'partyveta760', 'ComixToonFr', 'doaa90429042', 'bestvpnz', 'aebay', 'suigyodo', 'parismonitoring', 'menattitude', 'BretPh0t0n', 'ChariseWidmer', 'racheljamespi', 'ZeNewsLink', 'Omerta_Infosec', '_plesna', 'LawsonChaseJobs', 'fredericpoullet', 'RogersFR', 'jesuiscandice7', 'jeanneG50', 'CryptoXSL', 'maccimum', 'foxtrotfourwbm', 'fido_66', 'AGveille', 'InfoManip', 'HiroProtag', 'jhosley', 'Netmonker', 'tetaneutralnet', 'DefiLocacite', 'MTCyberStaffing', 'thecap59', 'Max1meN1colella', 'CharlesCohle', 'BrianInBoulder', 'ArsneDAndrsy', 'BullFR', 'Five_Star_Tech', 'pourconvaincre', 'Be_HMan', 'click2livefr', 'ElydeTravieso', 'n0rssec', '_fixme', 'infographisteF', 'zephilou', 'puneeth_sword', 'CheapestLock', 'Eprocom', 'LocksmithNearMe', 'YoshiDesBois', 'databreachlaws', 'LDarcam', '_CLX', 'dreadlokeur', '_sinn3r', 'operat0r', 'Moutonnoireu', 'MatToufoutu', 'mubix', 'abcdelasecurite', 'meikk', 'MadDelphi', 'ec_mtl', 'unixist', 'EricSeversonSec', 'slaivyn', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'cabusar', 'julien_c', 'moswaa', 'lycia_galland', 'YrB1rd', 'DogecoinFR', 'corkami', 'Barbayellow', 'Spiceworks', 'dt_secuinfo', 'Yaagneshwaran', 'btreguier', 'TheStupidmonKey', 'follc', '2xyo', 'crazyjunkie1', 'LeCapsLock', 'gizmhail', 'piscessignature', 'JamiesonBecker', '_SaxX_', 'isgroupsrl', 'NuitInfo2K13', 'yenos', 'SecurityTube', 'Gameroverdoses', 'Brihx_', 'silvakreuz', 'DamaneDz', '_bratik', 'vprly', 'didierdeth', 'sudophantom', 'xxradar', 'Techno_Trick', 'malphx', 'wixiweb', 'ChrisGeekWorld', 'AmauryBlaha', 'LRCyber', 'FranckAtDell', 'netrusion', 'ubuntuparty', 'grokFD', 'CISOtech', 'NotifyrInc', 'marcotietz', 'accident', 'darthvadersaber', 'VForNICT', 'ID_Booster', 'yw720', 'AgenceWebEffect', 'JeanLoopUltime', 'guideoss', 'Security_FAQs', 'Oursfriteorchid', 'Gr3gland', 'caaptusss', 'ygini', 'videolikeart', 'Veracode', 'CyberExaminer', 'hackademics_', 'razopbaltaga', 'eric_kavanagh', 'Ikoula', 'LeBlogDuHacker', 'rexperski', 'MathieuAnard', 'ced117', 'Panoptinet', 'BuzzRogers', 'ITSecurityWatch', 'PatchMob', 'officialmcafee', 'hnshah', 'AnonLegionTV', 'sh1rleysm1th', 'soocurious', 'PremiereFR', 'mob4hire', 'ericosx', 'yesecurity', 'DLSPCDoctor', 'tyrus_', 'gritsicon', 'trollMasque', 'AmauryPi', 'OpenForceMaroc', 'CybersimpleSec', 'PorterHick', 'AllTechieNews', 'revvome', 'livbrunet', 'aeris22', 'InfoSecMash', 'gigicristiani', 'stephanekoch', 'leduc_louis', 'ilhamnoorhabibi', 'servermanagedit', 'GTAFRANCE', '1humanvoice', 'stmanfr', 'Current_Tech', 'PEGE_french', 'Kuzbari', 'iisp_hk', 'Facebook_Agent', 'ZeroSkewl', 'chuckdauer', 'Itsuugo', 'Florianothnin', 'neeuQdeR', 'HYCONIQ', 'disk_91', 'ZOOM_BOX_r', 'Rimiologist', 'Matrixinfologic', 'GeneralSeven', 'preventiasvcs', 'atmon3r', 'filowme', 'FcsFcsbasif', 'catalyst', 'Spawnhack', 'globalwifiIntl', 'CajunTechie', 'ConstructionFOI', 'k8em0', 'Flavioebiel', 'FlacoDev', 'Fibo', 'wisemedia_', 'floweb', 'adistafrance', 'AnonBig', 'tacticalflex', 'Katezlipoka', 'MathieuZeugma', 'SophiAntipolis', 'matalaz', 'edehusffis', 'patricksarrea', 'SnapAndShine', 'cryptomars', 'OpPinkPower', 'DidierStevens', 'patatatrax', 'AJMoloney', 'cheetahsoul', 'vxheavenorg', 'defconparties', 'gvalc1', 'clemence_robin', 'XeroFR', 'noncetonic', 'bonjour_madame', 'LeWebSelonEdrek', 'robajackson', 'greenee_gr', 'zahiramyas', 'nation_cyber', 'Rio_Beauty_', 'Sadnachar', 'SecRich', 'unbalancedparen', 'Fyyre', 'VirusExperts', 'Applophile', 'Aziz_Satar', 'SecretDefense', 'Hi_T_ch', 'wireheadlance', 'define__tosh__', 'hamsterjoueur', 'PUREMEDIAHDTV', 'secdocs', 'code010101', 'LagunISA', '_theNextdoor_', 'lefredodulub', 'i4ppleTouch', 'imatin_net', 'KiadySam', 'toiletteintime', 'espeule', '1er_degres', 'BSoie', 'Pintochuks', 'selphiewall479', 'ApScience', 'suivi_avec_lisa', 'TiffenJackson', 'SecretGossips', 'sarahMcCartney2', 'wheatley_core', 'PatSebastien']

Friends = ['pondeboard1', 'ceb0t', 'theStump3r', 'uncl3dumby', 'gr3yr0n1n', 'poa_nyc', 'Demos74dx', 'sebastien_i', 'HAKTUTS', 'R00tkitSMM', 'pondeboard', 'AcidRampage', 'IncursioSubter', 'BSeeing', 'evleaks', 'InfoSec_BT', 'HIDGlobal', 'kjhiggins', 'vkamluk', 'codelancer', 'ciderpunx', 'HugoPoi', 'kfalconspb', 'lconstantin', 'coolhardwareLA', 'fsirjean', 'h0x0d', 'RCCyberofficiel', 'Tech_NurseUS', 'whitehatsec', 'oej', 'Trencube_GD', 'cissp_googling', '_pronto_', 'CtrlSec', 'ModusMundi', 'SwiftOnSecurity', 'RichRogersIoT', 'jonathansampson', 'Luiz0x29A', 'StephenHawking8', 'dpmilroy', 'usa_satcom', 'hack3rsca', 'PELISSIERTHALES', 'g00dies4', 'rpsanch', 'furiousinfosec', 'Om_dai33', 'wulfsec', 'securiteIT', 'pavornoc', 'hacking_report', 'primeroinfotek', 'L4Y5_G43Y', 'PaulM', 'seclyst', 'cmpxchg16', 'iainthomson', 'e_modular', '_jtj1333', 'n0psl', 'blaked_84', 'tb2091', 'dfirfpi', 'manonbinet001', 'webmathilde', '0xDUDE', 'nn81', 'CryptoKeeUK', 'n1nj4sec', 'ydklijnsma', 'scanlime', '0x6D6172696F', 'nono2357', 'derekarnold', 'hasherezade', '_HarmO_', 'OxHaK', 'CWICKET', 'linuxaudit', 'Space__Between', 'lordofthelake', 'Hired_FR', 'Laughing_Mantis', 'InfoSecHotSpot', 'geeknik', 'CharlesCohle', 'BretPh0t0n', 'jilles_com', 'duo_labs', 'unmanarc', 'x_adn', 'k4linux', 'shafpatel', 'SysAdm_Podcast', 'Everette', 'DadiCharles', 'danielbarger67', 'quequero', 'SecurityNewsbot', 'cityofcrows', 'Dinosn', 'ibmxforce', 'thepacketrat', 'cryptoishard', 'DEYCrypt', 'attritionorg', 'mzbat', 'da_667', 'krypt3ia', 'Z0vsky', 'BSSI_Conseil', 'SecMash', 'corexpert', 'maldevel', 'pof', 'FFD8FFDB', 'Snowden', 'lexsi', 'bestvpnz', 'EnfanceGachee', 'samykamkar', 'pevma', 'kafeine', 'k0ntax1s', 'gN3mes1s', 'GawkerPhaseZero', 'FreedomHackerr', 'sec_reactions', '0xAX', 'nolimitsecu', 'bascule', 'm3g9tr0n', 'nbs_system', 'sn0wm4k3r', 'jivedev', 'd_olex', 'indiecom', 'BlueCoat', 'Tif0x', 'UnGarage', 'HomeSen', 'CTF365', 'Securityartwork', 'accessnow', 'ZeljkaZorz', 'mortensl', 'ThomasNigro', 'Sidragon1', 'garage4hackers', 'hanno', 'p4r4n0id_il', 'AsymTimeTweeter', 'Omerta_Infosec', 'nopsec', 'cyberguerre', 'Protocole_ZATAZ', 'Grain_a_moudre', 'BIUK_Tech', 'TMZvx', '_plesna', 'PhysicalDrive0', 'rodneyjoffe', 'ithurricanept', 'sec0ps', 'comex', 'deepimpactio', 'ClechLoic', 'AGveille', 'amzben', 'FIC_fr', 'EricSeversonSec', 'MalwarePorn', 'Odieuxconnard', 'unixist', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'pwcrack', 'PhilHagen', 'Falkvinge', 'IPv4Countdown', 'lycia_galland', 'wirehack7', 'linux_motd', 'lamagicien', 'ubuntumongol', '_cypherpunks_', 'TekDefense', 'LeakSourceInfo', 'moswaa', 'OsandaMalith', 'Lope_miauw', 'dt_secuinfo', 'morganhotonnier', 'Relf_PP', 'abcderza', 'Barbayellow', 'corkami', 'KitPloit', 'ec_mtl', 'bugs_collector', 'BleepinComputer', 'Tinolle1955', 'valdesjo77', 'xombra', 'julien_c', 'Spiceworks', 'snipeyhead', 'YrB1rd', 'Trojan7Sec', 'Yaagneshwaran', 'ZATAZWEBTV', 'f8fiv', 'Netmonker', 'epelboin', '0xmchow', 'angealbertini', 'Incapsula_com', 'SurfWatchLabs', 'Exploit4Arab', 'hackerstorm', '2xyo', 'JamiesonBecker', 'NuitInfo2K13', '_SaxX_', 'piscessignature', 'crazyjunkie1', 'SecurityTube', 'comptoirsecu', '_saadk', 'penpyt', 'yenos', 'Intrinsec', 'udgover', 'jujusete', 'poulpita', 'suffert', 'clementd', '_CLX', '_bratik', 'tomchop_', 'vprly', 'mboelen', 'martijn_grooten', 'aristote', 'gandinoc', 'silvakreuz', 'ifontarensky', 'cedricpernet', 'y0m', 'knowckers', 'lakiw', 'didierdeth', 'paulsparrows', 'sudophantom', 'arbornetworks', 'AzzoutY', 'cabusar', 'Xartrick', 'netrusion', 'AmauryBlaha', 'Techno_Trick', 'wixiweb', 'hackhours', 'netbiosX', 'Daniel15', 'Routerpwn', 'asl', 'jeetjaiswal22', 'shoxxdj', 'FranckAtDell', 'ubuntuparty', 'jpgaulier', 'adulau', 'fredraynal', 'shu_tom', 'Cyberprotect', 'LRCyber', 'cymbiozrp', 'bitcoinprice', 'lafibreinfo', 'dreadlokeur', 'YoouKube', 'NotifyrInc', 'olfashdeb', 'MiltonSecurity', 'quota_atypique', 'TNWmicrosoft', 'LLO64', 'davromaniak', 'ID_Booster', 'VForNICT', 'klorydryk', 'vam0810', 'SecurityWeek', 'secludedITaid', 'montrehack', 'cvebot', 'chetfaliszek', 'NeckbeardHacker', 'hipsterhacker', 'AgenceWebEffect', 'marcotietz', 'erwan_lr', 'guideoss', 'sonar_guy', 'notsosecure', 'FlipFlop8bit', 'MalwareAnalyzer', 'yw720', 'SebBLAISOT', 'Cubox_', 'Ninja_S3curity', 'maximemdotnet', 'lea_linux', 'securitypr', '0xUID', 'MargaretZelle', 'Gr3gland', 'steveklabnik', 'iooner', 'caaptusss', 'tuxfreehost', 'ygini', 'Mind4Digital', 'ADNcomm', 'Veracode', 'hackademics_', 'xhark', 'TopHatSec', '0xSeldszar', 'PLXSERT', 'eric_kavanagh', 'IT_securitynews', 'devttyS0', 'Parisot_Nicolas', 'dclauzel', 'SCMagazine', 'JoceStraub', 'HackerfreeUrss', 'dascritch', 'aabaglo', 'ITConnect_fr', 'razopbaltaga', 'cargamax', 'MyOmBox', 'Wobility', 'evdokimovds', 'dookie2000ca', 'nuke_99', 'isgroupsrl', '_fwix_', 'LeBlogDuHacker', 'Ikoula', 'PortableWebId', 'OfficialGirish', 'httphacker', 'ripemeeting', 'ymitsos', 'Solarus0', 'Zestryon', 'ko_pp', 'etribart', 'TomsGuideFR', 'k3170Makan', 'jeeynet', 'qualys', 'KdmsTeam', 'frsilicon', 'astro_luca', 'rexperski', 'spiwit', 'nuclearleb', 'mcherifi', 'laVeilleTechno', 'framasoft', 'NyuSan42', 'nextinpact', 'PirateOrg', 'MathieuAnard', 'blesta', 'IPv6Lab', 'billatnapier', 'starbuck3000', 'jmplanche', 'pbeyssac', 'Keltounet', 'cwolfhugel', 'ZeCoffre', 'Dave_Maynor', 'durand_g', 'TMorocco', 'CyberExaminer', 'PatchMob', 'Nathanael_Mtd', '1nf0s3cpt', 'ospero_', 'ced117', 'LinuxActus', 'Panoptinet', 'schoolofprivacy', 'TrustedSec', 'maccimum', 'hadhoke', 'Jordane_T', 'novogeek', 'ChimeraSecurity', 'officialmcafee', 'GolumModerne', 'milw0rms', 'AsmussenBrandon', 'arnolem', 'Goofy_fr', 'AnonLegionTV', 'infoworld', 'soocurious', 'atarii', 'SebydeBV', 'JacquesBriet', 'ITSecurityWatch', 'SecurityFact', 'dorkitude', 'CISecurity', 'bishopfox', 'jeremieberduck', 'ericosx', 'dimitribest', 'levie', 'andreaglorioso', 'tyrus_', 'DLSPCDoctor', 'guiguiabloc', 'AlainClapaud', 'yesecurity', 'trollMasque', 'planetprobs', 'vincib', 'LeCapsLock', 'kafeinnet', 'Irrodeus', 'jbfavre', 'guestblog', 'rboulle', 'Fr33Tux', 'SecurityHumor', 'creoseclabs', 'm0rphd', 'argevise', 'gritsicon', 'veorq', 'Abdelmalek__', 'OpenForceMaroc', 'hashbreaker', 'AlexandreThbau1', 'MacPlus', 'yrougy', 'MaldicoreAlerts', 'AmauryPi', 'TrendMicroFR', 'sirchamallow', 'ACKFlags', 'jameslyne', 'LaNMaSteR53', 'AllTechieNews', 'garfieldair', 'PorterHick', 'arstechnica', 'sendio', 'CipherLaw', 'Golem_13', 'livbrunet', 'RealMyop', 'KenBogard', 'KarimDebbache', 'SmoothMcGroove', 'AlDeviant', 'Canardpcredac', 'SebRuchet', 'F_Descraques', 'Unul_Officiel', 'Poischich', 'drlakav', 'genma', 'lastlineinc', 'Cryptomeorg', 'CybersimpleSec', 'DarkReading', 'tqbf', 'gyust', 'KanorUbu', 'walane_', 'jedisct1', 'hadopiland', 'all_exploit_db', 'brutelogic_br', 'lechat87', 'gigicristiani', 'aeris22', 'terminalfix', 'ChristophePINO', 'ihackedwhat', 'InfoSecMash', 'bayartb', 'ErrataRob', 'DefuseSec', 'jcsirot', 'christiaan008', 'gopigoppu', 'lawmanjapan', 'RichardJWood', 'darthvadersaber', 'BryanAlexander', 'leduc_louis', 'distriforce', 'democraticaudit', 'PaulChaloner', 'kentbye', 'HacknowledgeC', 'servermanagedit', 'Coders4africa', 'securitycast', 'macbid', 'tomsguide', 'DrInfoSec', '1humanvoice', 'fsf', 'volodia', 'clusif', 'gbillois', 'theliaecommerce', 'JoshMock', 'MarConnexion', 'stmanfr', 'archiloque', 'ggreenwald', 'libdemwasjailed', 'inthecloud247', 'BlogsofWarIntel', 'pewem_formation', 'zdnetfr', 'Current_Tech', 'ilhamnoorhabibi', 'PEGE_french', 'Lu1sma', 'msftsecurity', 'ashish771', 'brutenews', 'iPhoneTweak_fr', 'my_kiwi', 'SilvaForestis', 'PierreTran', 'Kuzbari', 'r0bertmart1nez', 'yttr1um', 'hrousselot', 'crashsystems', 'benlandis', 'netsecu', 'securityaffairs', 'Stormbyte', 'iisp_hk', 'zonedinteret', 'Facebook_Agent', 'confidentiels', 'CryptoFact', 'chuckdauer', 'vriesjm', '_antoinel_', 'dhanji', '_reflets_', 'Anon_Online', 'MailpileTeam', 'Itsuugo', 'mdecrevoisier', 'freeboxv6', 'garwboy', 'StackCrypto', 'ChanologyFr', '_gwae', 'ashk4n', 'nzkoz', 'Florianothnin', 'neeuQdeR', 'UsulduFutur', 'BullGuard', 'samehfayed', 'olesovhcom', 'dragondaymovie', 'Itforma', 'HYCONIQ', 'axcheron', 'blakkheim', 'pressecitron', 'ChrisGeekWorld', 'episod', 'thalie30', 'disk_91', 'idfpartipirate', 'PPAlsace', 'FlorenceYevo', 'gdbassett', 'VulnSites', 'Secunia', 'iteanu', 'sciendus', 'esrtweet', '6l_x', 'MduqN', 'Skhaen', 'daveaitel', 'ZeroSkewl', 'Rimiologist', 'ekse0x', 'ZOOM_BOX_r', 'aanval', 'fhsales', 'Ruslan_helsinky', 'OpLastResort', 'fcouchet', 'GTAXLnetIRC', 'TheAdb38', 'DeloitteUS', 'GeneralSeven', 'AustenAllred', 'AlliaCERT', 'Double_L83', 'scoopit', 'Dylan_irzi11', 'fr0gSecurity', 'atmon3r', '0x736C316E6B', 'Hask_Sec', 'Zer0Security', 'xssedcom', 'php_net', 'phpizer', 'JpEncausse', 'M4ke_Developp', 'nkgl', 'preventiasvcs', 'SwiftwayNet', 'c4software', 'who0', 'gandi_net', 'H_Miser', 'nikcub', 'gcouprie', 'MindDeep', 'MdM_France', 'SpritesMods', 'NakedSecurity', 'GDataFrance', 'conciseonline', 'filowme', 'regislutter', 'CelebsBreaking', 'globalwifiIntl', 't2_fi', 'catalyst', 'x6herbius', 'cryptocatapp', 'arahal_online', 'mtigas', 'ALLsecuritySoft', 'lisachenko', 'renaudaubin', 'wamdamdam', '01net', 'secuobsrevuefr', 'DataSecuB', 'drambaldini', 'secu_insight', 'cyber_securite', 'smeablog', 'DecryptedMatrix', 'eCoreTechnoS', 'topcodersonline', 'Sec_Cyber', 'thegaryhawkins', 'CajunTechie', 'Othrys', 'jeromesegura', 'RazorEQX', 'Xylit0l', 'c_APT_ure', 'it4sec', 'ConstructionFOI', 'Official_SEA16', 'OpGabon', 'SecuraBit', 'esheesle', 'brutelogic', 'taziden', 'sam_et_max', 'iMilnb', 'Clubic', 'greenee_gr', 'fo0_', 'nathanLfuller', 'carwinb', 'puellavulnerata', 'samphippen', 'ntisec', 'dummys1337', 'flanvel', 'SUPINFO', 'Epitech', 'Erebuss', 'infobytesec', 'garybernhardt', 'mab_', 'wisemedia_', 'LagunISA', 'wiretapped', 'verge', 'crowd42', 'virusbtn', 'FlacoDev', 'SunFoundation', 'TheNextWeb', 'guillaumeQD', 'IBMSecurity', 'code010101', 'gvalc1', 'adistafrance', 'LeWebSelonEdrek', 'tacticalflex', 'imatin_net', 'espeule', 'Applophile', 'nation_cyber', 'zahiramyas', 'alexheid', 'SecMailLists', 'mob4hire', 'AnonBig', 'FloCorvisier', 'MathieuZeugma', 'Katezlipoka', 'w_levin', 'climagic', 'PartiPirate', 'InfosecNewsBot', 'nedos', 'jerezim', 'katylevinson', 'ThVillepreux', 'PBerhouet', 'dbbimages', 'irqed', 'BLeQuerrec', 'patricksarrea', 'pierre_alonso', 'Flameche', 'AndreaMann', 'SciencePorn', 'mvario1', 'AbbyMartin', 'TheGoodWordMe', 'chroniclesu', 'DoubleJake', 'Kilgoar', 'TylerBass', 'FievetJuliette', 'Reuters', 'mrjmad', 'Sebdraven', 'SophiAntipolis', 'LaFranceapeur', 'papygeek', 'gordonzaula', 'neufbox4', 'plugfr', 'BenoitMio', '_Kitetoa_', 'Numendil', 'laquadrature', 'kheops2713', 'Slatefr', 'benjaltf4_', 'Fibo', 'codesscripts', 'zorelbarbier', 'Be_HMan', 'FranceAnonym', 'SpartacusK99', 'Free_Center', 'TrucAstuce', 'schignard', 'ciremya', 'MatVHacKnowledg', 'FreenewsActu', 'XSSed_fr', 'planetubuntu', 'S_surveillance', 'cyphercat_eu', 'Hack_Gyver', 'ncaproni', 'MISCRedac', 'Cyber_Veille', 'journalduhack', 'bidouillecamp', 'Apprenti_Sage', 'Oxygen_IT', 'FIC_Obs', 'orovellotti', 'cyberdefenseFR', 'l1formaticien', 'Reseauxtelecoms', 'neuromancien', 'actuvirus', 'cryptomars', 'amaelle_g', 'Hybird', 'Monitoring_fr', 'Zythom', 'InfosReseaux', 'speude', 'lavachelibre', 'dezorda', 'Bugbusters_fr', '3615internets', 'planetedomo', 'Mayeu', 'HeliosRaspberry', 'CiscoFrance', 'anonfrench', 'IvanLeFou', 'NosOignons', 'OSSIRFrance', 'patatatrax', 'EFF', 's7ephen', 'kaspersky', '2600', 'cheetahsoul', 'OpPinkPower', 'AJMoloney', 'ecrans', 'anonhive', 'julien_geekinc', 'Anonymous_SA', 'USAnonymous', 'e_kaspersky', 'FSecure', 'ClipperChip', 'ax0n', 'hevnsnt', 'Aratta', 'yolocrypto', 'waleedassar', 'postmodern_mod3', 'kochetkov_v', 'pwntester', 'bartblaze', 'TheDanRobinson', 'unpacker', 'r_netsec', 'AnonymousPress', 'priyanshu_itech', 'kinugawamasato', 'mozwebsec', 'zonehorg', 'beefproject', 'YourAnonNews', 'boblord', 'vikram_nz', 'PublicAnonNews', 'kkotowicz', 'hackersftw', '0xerror', 'fancy__04', 'l33tdawg', 'node5', '0xjudd', '_mr_me_', 'sickness416', 'googleio', 'infosecmafia', 'p0sixninja', 'isa56k', 'TheWhiteHatTeam', 'inj3ct0r', 'snowfl0w', 'SocEngineerInc', 'jdcrunchman', 'DiptiD10', 'ehackingdotnet', 'jack_daniel', 'BrandonPrry', 'TurkeyAnonymous', 'MarkWuergler', 'pranesh', 'eddieschwartz', 'mozilla', 'deCespedes', 'M0nk3H', 'tpbdotorg', 'IPredatorVPN', 'smarimc', 'Thomas_Drake1', 'opindia_revenge', 'Malwarebytes', 'EHackerNews', 'HNBulletin', 'dietersar', 'CCrowMontance', 'r3shl4k1sh', 'DanielEllsberg', 'PMOIndia', 'SecurityPhresh', 'vxheavenorg', 'kgosztola', 'TheHackersNews', 'jeromesaiz', 'Trem_r', 'netsabes', 'Flaoua', 'DannyDeVito', 'p0sixn1nja', 'twitfics', 'wzzx', 'DustySTS', 'Lincoln_Corelan', 'SecureTips', 'InfoSecRumors', 'matthew_d_green', 'agl__', 'elwoz', 'apiary', '0xabad1dea', 'dangoodin001', 'kpoulsen', 'ethicalhack3r', 'SecBarbie', 'dguido', 'marcusjcarey', 'jadedsecurity', 'petitpetitam', 'hackeracademy', 'moreauchevrolet', 'Jean_Leymarie', 'tricaud', 'Nipponconnexion', 'OtakuGameWear', 'schneierblog', 'g4l4drim', '0x73686168696e', 'securityvibesfr', 'window', 'sm0k_', 'pentesteur', 'AlainAspect', 'chandraxray', 'AstronomyNow', 'Astro_Society', 'SpitzerScope', 'NASAspitzer', 'NASAWebb', 'NASAFermi', 'SpaceflightNow', 'NASAStennis', 'sciam', 'WISE_Mission', 'NASA_Images', 'NatGeo', 'NASAblueshift', 'universetoday', 'NASAJPL_Edu', 'NASA_Orion', 'TrinhXuanThuan', 'Infographie_Sup', 'MartinAndler', 'pierenry', 'Bruno_LAT', 'RichardDawkins', 'guardianscience', 'TheSkepticMag', 'TomFeilden', 'gemgemloulou', 'AdamRutherford', 'Baddiel', 'DrAliceRoberts', 'ProfWoodward', 'SarcasticRover', 'robajackson', 'MarsCuriosity', 'BBCBreaking', 'shanemuk', 'Schroedinger99', 'AtheneDonald', 'imrankhan', 'danieldennett', 'paulwrblanchard', 'MartinPeterFARR', 'DPFink', 'sapinker', 'chrisquigg', 'minutephysics', 'AdamFrank4', 'SpaceX', 'astrolisa', 'Erik_Seidel', 'simonecelia', 'PhilLaak', 'TEDchris', 'colsonwhitehead', 'plutokiller', 'dvergano', 'carlzimmer', 'j_timmer', 'edyong209', 'Laelaps', 'bmossop', 'maiasz', 'ericmjohnson', 'WillmJames', 'BadAstronomer', 'billprady', 'reneehlozek', 'PolycrystalhD', 'BoraZ', 'sethmnookin', 'albionlawrence', 'RisaWechsler', 'seanmcarroll', 'imaginaryfndn', 'PhysicsNews', 'DiggScience', 'bigthink', 'PopSci', 'AIP_Publishing', 'NSF', 'NewsfromScience', 'BBCScienceNews', 'PhysicsWorld', 'ScienceNews', 'physorg_com', 'TED_TALKS', 'TreeHugger', 'physorg_space', 'physorg_tech', 'NASAGoddard', 'CERN_FR', 'neiltyson', 'ProfBrianCox', 'SethShostak', 'b0yle', 'NASAJPL', 'worldofscitech', 'michiokaku', 'OliverSacks', 'AMNH', 'JannaLevin', 'bgreene', 'AssoDocUp', 'MyScienceWork', 'ParisDiderot', 'molmodelblog', 'neilfws', 'pjacock', 'dalloliogm', 'yokofakun', 'mrosenbaum711', 'joshwhedon', 'BrentSpiner', 'moonfrye', 'greggrunberg', 'Schwarzenegger', 'RealRonHoward', 'arnettwill', 'AmandaSeyfried', 'JasonReitman', 'DohertyShannen', 'JohnStamos', 'frankiemuniz', 'TheRealNimoy', 'EyeOfJackieChan', 'dhewlett', 'ZacharyLevi', 'MillaJovovich', 'JohnCleese', 'BambolaBambina', 'CERN', 'CNES', 'Inserm', 'NASA', 'USGS', 'NatureNews', 'Planck', 'IN2P3_CNRS', 'Inria', 'INC_CNRS', 'tgeadonis', 'inp_cnrs', 'AlainFuchs', 'CNRSImages', 'FabriceImperial', 'CNRS', 'laurentguyot', 'consult_detect', 'NewsBreaker', 'ISS_Research', 'nicolaschapuis', 'PolarisTweets', 'uncondamne', 'veytristan', 'gplesse', 'MattBellamy', 'LeParisien_Tech', 'Pontifex_fr', 'DenisCourtine', 'PascalDronne', 'NSegaunes', 'LeParisien_Buzz', 'NoemieBuffault', 'LesInconnus', 'FBIBoston', 'Pascallegitimus', 'lucabalo', 'isabellemathieu', 'FlorentLadeyn', 'NaoelleTopChef', 'quentintopchef', 'julienduFFe', 'natrevenu', 'yannforeix', 'defrag', 'rybolov', 'securid', 'stacythayer', 'tcrweb', 'Techdulla', 'TimTheFoolMan', 'treguly', 'YanceySlide', 'golfhackerdave', 'liquidmatrix', 'jonmcclintock', 'infosecpodcast', 'HypedupCat', 'Hak5', 'georgevhulme', 'gcluley', 'gattaca', 'g0ne', 'EACCES', 'digininja', 'devilok', 'd4ncingd4n', 'CSOonline', 'anthonymckay', 'abaranov', 'aaronbush', '_LOCKS', 'security_pimp', 'teksquisite', 'blpnt', 'alpharia', 'jgarcia62', '_MC_', 'InfoSec208', 'SPoint', 'i0n1c', 'torproject', 'room362', 'nicowaisman', 'VirusExperts', 'DavidHarleyBlog', 'follc', 'episeclab', 'manhack', 'pollux7', 'y0ug', 'Hallewell', 'SteveGoldsby', 'polarifon', 'malwarecityFR', 'Webroot', 'Infosanity', 'BitDefenderAPAC', 'VirusExpert', 'securitypro2009', 'blackd0t', 'securityfocus', 'DanaTamir', 'securitywatch', 'securitynetwork', 'PrivacySecurity', 'securitystuff', 'myCSO', 'RSAsecurity', 'SecurityExtra', 'WebSecurityNews', 'web_security', 'SCmagazineUK', 'TechProABG', 'malwareforensix', 'stephanekoch', 'daleapearson', 'CyberSploit', 'veryblackhat', 'opexxx', 'Hakin9', 'EvilFingers', 'isaudit', 'SpiderLabs', 'securegear', 'gdssecurity', 'ioerror', 'yaunbug', 'dstmx', 'zentaknet', 'wireheadlance', 'TenableSecurity', 'secdocs', 'proactivedefend', 'racheljamespi', 'xxradar', 'aebay', 'vincentzimmer', 'xanda', 'MarioVilas', 'sting3r2013', 'SecRich', 'deanpierce', 'HaDeSss', 'Jolly', 'searchio', 'thomas_wilhelm', 'gollmann', 'HackerTheDude', 'ADMobilForensic', 'SecurityStream', 'gadievron', 'tomaszmiklas', 'irongeek_adc', '_____C', 'operat0r', 'carne', 'fmavituna', 'PandaSecurityFR', 'freaklabs', 'alphaskade', 'hgruber97', 'noncetonic', 'AVGFree', 'k0st', 'kargig', 'lgentil', 'andreasdotorg', 'redragonvn', 'theharmonyguy', 'NoSuchCon', 'b10w', '0security', 'Z3r0Point', 'bortzmeyer', 'ahoog42', 'gianluca_string', 'eLearnSecurity', 'k4l4m4r1s', 'issuemakerslab', 'matalaz', 'ForcepointLabs', 'iExploitXinapse', 'itespressofr', 'ehmc5', 'practicalexplt', 'Pentesting', 'avkolmakov', 'manicode', 'HITBSecConf', 'sensepost', 'TeamSHATTER', 'n00bznet', 'thegrugq', 'judy_novak', 'TaPiOn', 'revskills', 'randomdross', 'malphx', 'OpenMalware', 'syngress', '2gg', 'GNUCITIZEN', 'chrissullo', 'michael_howard', 'c7five', 'pdp', 'securosis', 'Shadowserver', 'BlackHatHQ', 'securityincite', 'bsdaemon', 'Secn00b', 'dyngnosis', 'mwtracker', 'BorjaMerino', 'packetlife', 'toolcrypt', 'hackmiami', 'OWASP_France', 'jkouns', 'Mario_Vilas', 'zate', '_supernothing', 'aszy', 'lestutosdenico', 'espreto', '_sinn3r', 'aloria', 'Fyyre', 'SymantecFR', 'aircrackng', 'hackerschoice', 'MuscleNerd', 'smalm', 'OxbloodRuffin', 'subliminalhack', 'bannedit0', 'armitagehacker', 'RealGeneKim', 'mxatone', 'Snort', 'rebelk0de', 'hackingexposed', 'virustotalnews', 'InfiltrateCon', 'aramosf', 'msfdev', 'ChadChoron', 'n0secure', 'ITRCSD', 'CyberDefender', 'ArxSys', 'lulzb0at', 'crypt0ad', 'Stonesoft_FR', 'LordRNA', 'WindowsSCOPE', 'yo9fah', 'michelgerard', 'NAXSI_WAF', 'v14dz', 'x0rz', 'tbmdow', 'kasperskyfrance', 'Agarri_FR', 'ISSA_France', 'Jhaddix', 'Heurs', 'PlanetCreator', 'infernosec', 'rexploit', 'ConfCon', 'securityshell', 'bonjour_madame', 'minusvirus', 'emiliengirault', 'dvrasp', 'virtualabs', 'rfidiot', 'ttttth', 'msuiche', 'Ivanlef0u', 'Korben', 'hackersorg', 'shell_storm', 'WTFuzz', 'MoonSols', 'newsoft', 'vnsec', 'in_reverse', 'hackerfantastic', 'mtrancer', 'datacenter', 'stelauconseil', 'CNIL', 'exploitdb', 'BillBrenner70', 'lagrottedubarbu', 'HackingDave', 'VUPEN', 'siddartha', 'bluetouff', 'sstic', 'ToolsWatch', 'emmasauzedde', 'lseror', 'bearkasey', 'xme', 'helpnetsecurity', 'hackinthebox', 'Transiphone', 'hackaday', 'TheSuggmeister', 'Herve_Schauer', 'humanhacker', 'it_audit', 'Jipe_', 'FredLB', '0vercl0k', 'secbydefault', 'kerouanton', 'dragosr', 'endrazine', 'HBGary', 'pentestit', 'madpowah', 'serphacker', 'security4all', 'SecuObs', 'vloquet', 'joegrand', 'matrosov', 'DIALNODE', 'brucon', 'corelanc0d3r', 'RSnake', '0xcharlie', 'taviso', '41414141', 't0ka7a', 'thedarktangent', 'mubix', 'jonoberheide', 'spacerog', 'ChrisJohnRiley', 'securityninja', 'threatpost', 'nasko', 'mwrlabs', 'justdionysus', 'iHackwing', 'DJLahbug', 'cyber_security', 'hardhackorg', 'e2del', 'a41con', 'msftsecresponse', 'sans_isc', 'egyp7', 'antic0de', 'mikko', '_MDL_', 'mdowd', 'carnal0wnage', 'jeremiahg', 'xorlgr', 'cesarcer', 'BlackHatEvents', 'MatToufoutu', 'csec', 'selectrealsec', 'CERTXMCO', 'SecuritySamurai', 'razlivintz', 'etcpasswd', 'The_Sec_Pub', 'meikk', 'securityweekly', 'alexsotirov', 'DidierStevens', 'beist', 'stalkr_', 'dakami', 'halvarflake', 'dinodaizovi', 'silviocesare', 'stephenfewer', 'barnaby_jack', 'andremoulu', 'thierryzoller', 'PwnieAwards', 'reversemode', 'kalilinux', 'gynvael', 'pusscat', 'abcdelasecurite', 'johnjean', 'ninjanetworks', 'sotto_', 'SecretDefense', 'FFW', 'commonexploits', 'x86ed', 'zsecunix', 'hack_lu', 'Majin_Boo', 'BadShad0w', 'FlUxIuS', 'valuphone', 'free_man_', 'teamcymru', 'ihackstuff', 'secureideas', 'sansforensics', 'benoitbeaulieu', 'LaFermeDuWeb', 'TwitPic', 'noaheverett', 'lostinsecurity', 'democracynow', 'dougburks', 'zephilou', 'kevinmitnick', 'defcon', 'SecurityBSides', 'haxorthematrix', 'rmogull', 'unbalancedparen', 'perfectvendetta', 'siccsudo', 'Nan0Sh3ll', 'newroot', 'ClsHackBlog', '27c3', 'c3streaming', 'SOURCEConf', 'eugeneteo', 'moxie', 'dlitchfield', 'thezdi', 'scarybeasts', 'ryanaraine', 'kernelpool', 'esizkur', 'richinseattle', 'WeldPond', 'k8em0', 'jduck', 'ultramegaman', 'tsohlacol', 'HeatherLeson', 'myrcurial', 'nudehaberdasher', 'drraid', 'Agarik', 'Aziz_Satar', 'hackinparis', 'sdwilkerson', 'Satyendrat', 'LawyerLiz', 'UnderNews_fr', 'deobfuscated', 'HacKarl', 'StopMalvertisin', 'djrbliss', 'TinKode', 'HappyRuche', 'rssil', 'sysdream', 'acissi', 'migrainehacker', 'xsploitedsec', 'sucurisecurity', 'bonjourvoisine', 'Sorcier_FXK', 'mikekemp', 'jaysonstreet', 'roman_soft', 'xavbox', 'HackBBS', 'securitytwits', 'Hi_T_ch', 'DarK_Kiev', 'lbstephane', 'hugofortier', 'bl4sty', 'kaiyou466', 'Thireus', 'Paul_da_Silva', 'fbaligant', '_metalslug_', 'ochsff', 'fjserna', 'JonathanSalwan', 'ericfreyss', 'julianor', 'j00ru', '0xGrimmlin', 'define__tosh__', 'hesconference', 'Calculonproject', 'ZenkSecurity', 'Moutonnoireu', 'newsycombinator', 'securityh4x', 'corbierio', 'Security_Sifu', 'str0ke', 'owasp', 'milw0rm', 'gsogsecur', 'USCERT_gov', 'packet_storm', 'CoreSecurity', 'CiscoSecurity', 'ECCOUNCIL', 'securityweb', 'debian_security', 'ubuntu_security', 'SocialMediaSec', 'offsectraining', 'JournalDuPirate', 'ThisIsHNN', 'nmap', 'metasploit', 'orangebusiness', 'tixlegeek', 'rapid7', 'defconparties', 'ProjectHoneynet', 'NoWatch', '1ns0mn1h4ck', 'zataz', 'r00tbsd', 'hackerzvoice', 'JournalDuGeek', 'Senat_Direct', 'franceculture', 'MetroFrJustice', 'MrAntoineDaniel', 'tanguy', '_clot_', 'Reuno', 'chiptune', 'nicolasfolliot', 'johnmartz', 'lifehacker', 'Vfalkrr', 'AurelieThuot', 'PinkPaink', 'jnkboy', 'ManardUV', 'AsherVo', 'Stephan_Kot', 'thatgamecompany', 'Dedodante', 'RomainSegaud', 'TheMarkTwain', 'Maitre_Eolas', 'jmechner', 'SeinfeldToday', '5eucheu', 'FRANCHEMENT_', 'SuricateVideo', 'alainjuppe', 'antoine64', 'ydca_nico', 'aleksou', 'docslumpy', 'jeremy345', 'TRYWAN', 'UrielnoSekai', 'Mister_AlAmine', 'KrSWOoD', 'hamsterjoueur', 'JyanMaruku', 'insertcoinFR', 'MisterAdyboo', 'MrBouclesDor', 'Gorkab', '____Wolf____', 'Ben_MORIN', 'lestortuesninja', 'neocalimero', 'Sadnachar', 'KazHiraiCEO', 'Bethesda_fr', 'ChrisToullec', 'Juliette1108', 'RisingStarGames', 'LtPaterson', 'VGLeaks', 'SonySantaMonica', 'l87Nico', 'Yatuu', 'cbalestra', 'yosp', 'twfeed', 'ludaudrey', 'RpointB', 'danielbozec', 'LiveScience', 'Rue89', 'ScienceChannel', 'ScienceDaily', 'ubergizmofr', 'Gizmodo', 'Virgini2Clausad', 'fabriceeboue', 'ThibBracci', 'labeauf', 'waterkids', 'MisterMcFlee', 'FranckLassagne', 'GraiggyLand', 'Galagan_', 'BenCesari', '_RaHaN_', 'Tris_Acatrinei', 'Valent1Bouttiau', 'Julien_Bouillet', 'UncleTex', 'Suchablog', 'laboitecom', 'coverflow_prod', 'TeamTerrasse', 'IGmagazine', 'Wael3rd', 'Rogedelaaa', 'starcowparis', 'liloudalas', 'emanu124', 'xfrankblue', 'K0RSIK0', 'UlycesEditions', 'Djoulo', 'cabanong', 'laureleuwers', 'clemence_robin', 'suriondt', '_Supertroll', 'Neveu_Tiphaine', '_theNextdoor_', 'tomnever', 'DavidChoel', 'Elmedoc', 'Delzarissa', 'Nolife_Online', 'NicolAspatoule', 'Frederic_Molas', 'Marcuszeboulet', 'PlayStation', 'RockstarGames', 'Naughty_Dog', 'notch', 'pirmax', 'miklD75', 'ClorindeB', 'NathalieAndr', 'ODB_Officiel', 'LeGoldenShow', 'HIDEO_KOJIMA_EN', 'damiensaez', 'DIEUDONNEMBALA', 'FQXi', 'PerleDuBac', 'SatoshiKon_bot', 'shin14270', 'tsamere', 'Bouletcorp', 'CasselCecile', 'RaynaudJulie', 'LionnelAstier', 'swinefever', 'normanlovett1', 'SteveKeys66', 'DannyJohnJules', 'LeoDiCaprio', 'wikileaks', 'TORDFC', 'RedDwarfHQ', 'DalaiLama', 'Al_Hannigan', 'AnthonySHead', 'SteveMartinToGo', 'bobsaget', 'gwenstefani', 'JohnMCochran', 'ActuallyNPH', 'CobieSmulders', 'alydenisof', 'jasonsegel', 'kavanaghanthony', 'RafMezrahi', 'BellemareOut', 'BellemarePieR', 'rataud', 'piresrobert7', 'beigbedersays', 'IamJackyBlack', 'oizo3000', 'ericetramzy', 'yannlaffont', 'michel_denisot', 'VincentDesagnat', 'PaulMcCartney', 'Pascal__Vincent', 'JimCarrey', 'simonastierHC', 'manulevyoff', 'GillesLellouche', 'axellelaffont', 'xaviercouture', 'emougeotte', 'bernardpivot1', 'sgtpembry', 'Xavier75', 'NicolasBedos1', 'Chabat_News', 'stephaneguillon', 'farrugiadom', 'francoisrollin', 'kyank', 'levrailambert', 'lolobababa', 'jimalkhalili', 'alexnassar', 'suivi_avec_lisa', 'Suzuka_Nolife', 'DavidHasselhoff', 'CCfunkandsoul', 'CaptainAJRimmer', 'DougRDNaylor', 'bobbyllew', 'katherineravard', 'ReizaRamon', 'kaorinchan', 'NolifeOfficiel', 'floweb', 'Thugeek', 'LoloBaffie', 'charlottesavary', 'SebRaynal', 'GirlButGeek', 'bjork', 'YOUNMICHAEL', 'hartza_info', 'ApScience', 'ApertureSciCEO', 'wheatley_core', 'ApertureSciPR', 'lilyallen', 'koreus', 'MichaelYoun']

banlist = ['WhitePaper','WHITEPAPER','whitepaper','Whitepaper','To help you','to help you','To Help You','Marketing','marketing','check out this','mimicking ghosts','fundamental tactics','FREE','Richard Armitage','@EdgeofSports','Tips','tips','Increase','growth','free','Growth','Join Free ','vulnerability of women','cornwall','Forensic Mystery','Learn how','Healthcare','Security Epidemic','ASMSG','microbiome','flood of refugees','Donald Trump','spider couples','Follow us','Sida','carotte','moche','slow motion','fake tweets','meuf']

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

def checkmenu(wordlist):

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

			print "Removing from search list ..."
			wordlist = list(set(wordlist) - set(lines))
			print
			print
			print "New lenght of searchlist : " + str(len(wordlist)) + " (Was " + str(oldlen) + " )"
			print "=="
			print
			lenmatch = len(set(lines) & set(wordlist))
		file.close()
		newkeywords = wordlist
		print
		print "=="
		print "Search terms already used removed successfully"
		print "=="
		checkM = 1

	except:
		print "=="
		print "No previous searchs found for today"
		print "=="
	


def lastmeal(lastsearch):


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



def SaveTotalCall(call,update):
                print
                print
                print
                print
                print
		print "===================SAVING CALLS==================="
		print

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

		file = open(TmpDay,"r"+"a")
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

                file2 = open(TmpDay2,"r"+"a")
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
                print "===================Done Saving Calls==================="
                print
                print
                print
                print
                print


def Retweet():

 	global apicall
	global updatecall
	global totalupdatecall

        if allok == 1:
		print
		print
		print
		print
		print
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                print "!                RETWEETING               !"
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

	        tri = sorted(retweetlist,key=lambda line: int(line.split("-")[0]),reverse=True)
	
        	QueueList = tri

		nbrRtwt =  2223 - int(totalupdatecall)
		print
		print "=="
		print "I Think i m able to retweet %d items in list ." %nbrRtwt
		print
		time.sleep(1)

		if nbrRtwt == 0:
			print "Cant retweet all of them .."
			print "Trying to guess of many tweets can still be send ."
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
				
#			sys.exit()

		if nbrRtwt > len(QueueList):
			nbrRtwt = len(QueueList)
			print "resizing to list size"
			print
		print "=="
		print
		tmpcount = 0
		for item in QueueList[:nbrRtwt]:

				limits()

				FinalItem = item.split("-")[1]
				time.sleep(1)
				print
				print "**"
				print "Retweeting : ",FinalItem
				print "Score : ",item.split("-")[0]
				tmpcount = tmpcount + 1
				try:
		                	twitter.retweet(id = FinalItem)
			        	print "Done !"
					print "Tweets left to send %i / %i " % (tmpcount,nbrRtwt)
					print "**"
					print
					print "*=*=*=*=*=*=*=*=*=*"
					print "Saving Tweet id"
					print "*=*=*=*=*=*=*=*=*=*"
					Saveid(FinalItem)
					time.sleep(1)
					apicall = apicall +1
					updatecall = updatecall + 1
				except TwythonError as e:
							print "Twython Error:"
							print e
							if "Twitter API returned a 403 (Forbidden), User is over daily status update limit." in e:
									print "Oups ..too many requests for today (From Retweet function)"
									SaveTotalCall(apicall,updatecall)
									lastmeal(Keywords[:rndwords])
									sys.exit()
							if "Twitter API returned a 429 (Too Many Requests), Rate limit exceeded" in e:
									apicall = 180
									limits()
							if "Twitter API returned a 403 (Forbidden), You have already retweeted this tweet." in e:
									print "Already Retweet trying next one"
									apicall = apicall + 1
def tweetlist(point,id):

        ammo = str(point) + "-" + str(id)
        retweetlist.append(ammo)

	print "=="
	print "Loaded into Queue"
	print "=="
	print




def limits():

	global apicall
	global updatecall
	global totalupdatecall
	global totalcall
	global twitter
	global searchlimit
	global restabit

	print
	print "==================="
	print "Current Apicall = ",apicall
	print "Total call = ",totalcall
	print "="
	print "Current Update call =",updatecall
        print "Total Update call = ",totalupdatecall
	print "==================="

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
                print "CURRENT SEARCH RATE LIMITS ALMOST REACHED "
                print ""
		print "Saving current Search Term"
		lastmeal(Keywords[:rndwords])
                print "Saving Total Calls to file"
                SaveTotalCall(apicall,updatecall)
                print "Reseting current apicalls"
                updatecall = 0
                apicall = 0
                searchlimit = 0
		restabit = 0

                print "Login out"
                print "WAITING 900 seconds"

                for i in xrange(900,0,-1):
                        time.sleep(1)
                        sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
                        sys.stdout.flush()

                print "Waking up.."
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
                print "Saving current Search Term"
                lastmeal(Keywords[:rndwords])

                print "CURRENT SEARCH RATE LIMITS ALMOST REACHED "
                print ""
                print "Saving Total Calls to file"
                SaveTotalCall(apicall,updatecall)
                print "Reseting current apicalls"
                updatecall = 0
                apicall = 0
		searchlimit = 0

                print "Login out"
                print "WAITING 900 seconds"

                for i in xrange(900,0,-1):
                        time.sleep(1)
                        sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
                        sys.stdout.flush()

                print "Waking up.."
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
		print "CURRENT API RATE LIMITS ALMOST REACHED "
		print ""
                print "Saving current Search Term"
                lastmeal(Keywords[:rndwords])
                print "Saving Total Calls to file"
                SaveTotalCall(apicall,updatecall)
                print "Reseting current apicalls"
		updatecall = 0
                apicall = 0

		print "Login out"
		print "WAITING 900 seconds"
		
		for i in xrange(900,0,-1):
    			time.sleep(1)
			sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
			sys.stdout.flush()

		print "Waking up.."
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


	if totalcall > 7777:
                print
                print
                print
                print
                print

                print "****************************************"
                print
                print "API RATE LIMIT ALMOST REACHED FOR TODAY (Total 6666)"
		print
                print "****************************************"
                print
                print
                print "Saving current Search Term"
                lastmeal(Keywords[:rndwords])

                print
                print
                print

                SaveTotalCall(apicall,updatecall)
		lastmeal(Keywords[:rndwords])
		sys.exit()

	if totalupdatecall > 2223:

                print
                print
                print
                print
                print
                print "****************************************"
                print
                print "API RATE LIMIT ALMOST REACHED FOR TODAY (Update 2223)"
                print
                print "****************************************"
                print
                print
                print
                print "Saving current Search Term"
                lastmeal(Keywords[:rndwords])

                print
                print
                SaveTotalCall(apicall,updatecall)
		lastmeal(Keywords[:rndwords])
 		sys.exit()

def Ban(tweet):
	#working on it#	
	global Banned

	print
	print "*=*=*=*=*=*=*=*=*=*"
	print "Checking if this Tweet contains any forbidden terms:"
	print
	for forbid in banlist:
		if forbid in tweet:

			print
			print "This tweet contains forbidden terms :"
			print
			print tweet
			print
			print "Going to trash ..."
			print "*=*=*=*=*=*=*=*=*=*"
			print
			Banned = 1
			time.sleep(3)
	if Banned == 0:

		print "Good to go"
	        print "*=*=*=*=*=*=*=*=*=*"
		print


def Saveid(id):

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
                file.write(str(id) + "\n")
		file.close()

		print
		print
		print "*=*=*=*=*=*=*=*=*=*"
		print "Id :",id
		print "Saved"
		print "*=*=*=*=*=*=*=*=*=*"
		print
		print


def Idlist(id):

		global alreadysend

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

		file = open(idsaved,"r")
                lines = file.read().splitlines()

		for saved in lines:

			if str(saved) in str(id):

				print
				print "*=*=*=*=*=*=*=*=*=*"
				print "Already sent .. "
				print "*=*=*=*=*=*=*=*=*=*"
				print
				alreadysend = 1

		if alreadysend == 0:

			print
			print "*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
			print "This id has not been saved before"
			print "*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
			print


def Scoring(tweet,search):

	global apicall
	global totalcall
	global updatecall
	global totalupdatecall
	global Banned
	global alreadysend

	Score = 0
	Banned = 0
	alreadysend = 0

	print
	print
	print
	print
	print
	print
	print
        print "*************************************************************************************" 
	print "============================Starting Scoring function================================"
	print ""

	if 'retweet_count' in tweet and tweet['retweet_count'] != 0:

			print "##"
			print "This tweet has been retweeted %i times " % tweet['retweet_count']
			print "##"

			Score = Score + 1
			if tweet['retweet_count'] > 3 and tweet['retweet_count'] < 5:
				Score  = Score + 3
                        if tweet['retweet_count'] > 5 and tweet['retweet_count'] < 10:
                                Score  = Score + 4
                        if tweet['retweet_count'] > 10 and tweet['retweet_count'] < 15:
                                Score  = Score + 6
                        if tweet['retweet_count'] > 15 and tweet['retweet_count'] < 20:
                                Score  = Score + 8
                        if tweet['retweet_count'] > 20 and tweet['retweet_count'] < 25:
                                Score  = Score + 10
                        if tweet['retweet_count'] > 25 and tweet['retweet_count'] < 30:
                                Score  = Score + 11
                        if tweet['retweet_count'] > 30 and tweet['retweet_count'] < 35:
                                Score  = Score + 12
                        if tweet['retweet_count'] > 35 and tweet['retweet_count'] < 40:
                                Score  = Score + 13
                        if tweet['retweet_count'] > 40 and tweet['retweet_count'] < 45:
                                Score  = Score + 14
                        if tweet['retweet_count'] > 45 and tweet['retweet_count'] < 50:
                                Score  = Score + 15
                        if tweet['retweet_count'] > 50 and tweet['retweet_count'] < 55:
                                Score  = Score + 16
                        if tweet['retweet_count'] > 55 and tweet['retweet_count'] < 60:
                                Score  = Score + 17
                        if tweet['retweet_count'] > 60 and tweet['retweet_count'] < 65:
                                Score  = Score + 18
                        if tweet['retweet_count'] > 65 and tweet['retweet_count'] < 70:
                                Score  = Score + 19
                        if tweet['retweet_count'] > 70 and tweet['retweet_count'] < 75:
                                Score  = Score + 20
                        if tweet['retweet_count'] > 75 and tweet['retweet_count'] < 80:
                                Score  = Score + 21
                        if tweet['retweet_count'] > 80 and tweet['retweet_count'] < 85:
                                Score  = Score + 22
                        if tweet['retweet_count'] > 85 and tweet['retweet_count'] < 90:
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
                        Score = Score + 15


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
	if tweet['lang'] == "en" or tweet['lang'] == "fr" or tweet['lang'] == "en-gb":

		Idlist(tweet['id'])

		if alreadysend == 0:

			Ban(tweet['text'])

			if Banned == 0:
				if Score > 15 :
					print
					print
					print
					print "######################################"
					print "Adding to Retweet List"
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
					time.sleep(2)
					tweetlist(Score,tweet['id'])
				else:
					print ""
					print "================================================================================"
					print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
					print "This tweet does not match the requirement needed score to be retweeted. (Score)"
					print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
					print "================================================================================"
					print ""
		
					time.sleep(1)
			else:
	                                print ""
	                                print "================================================================================"
	                                print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
	                                print "This tweet does not match the requirement needed score to be retweeted. (Banned)"
	                                print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
	                                print "================================================================================"
	                                print ""
					time.sleep(1)
		else:
			                print ""
                                        print "==================================="
                                        print ":( :( :( :( :( :( :( :( :( :( :( :("
                                        print "This tweet has been already sent .."
                                        print ":( :( :( :( :( :( :( :( :( :( :( :("
                                        print "==================================="
                                        print ""
                                        time.sleep(1)



	else:
                                print ""
				print "================================================================================"
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
                                print "This tweet does not match the requirement needed to be retweeted. (Language)"
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
				print "================================================================================"
                                print ""
				time.sleep(1)

#        time.sleep(2)


	print
	print





def searchTst(word):
	global apicall
	global updatecall
	global twitter
	global restabit

	ratechk = 0

	try :
        	rate = twitter.get_application_rate_limit_status()
	        search = rate['resources']['search']['/search/tweets']['remaining']

		apicall = apicall + 2
		ratechk = 1

        except Exception as e:

		print "mysterious error"
		print
		print e
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
		        print "Starting search function"
			print "**"
	                print "##########################################"

			print
			print "=/\/\/\/\/\/\/\/\/\/\/\="
			print "=Calling Limit function="
			print "=/\/\/\/\/\/\/\/\/\/\/\="
	
			limits()
			try:
		        	searchresults = twitter.search(q=word, count = 200)
				print "##########################################"
				print "Results found "
				print ""
				apicall = apicall + 1
		
		
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
				print "Chargement des tweets pour " + word
				twitter.send_direct_message(user_id="292453904", text="Chargement des tweets pour " + str(word))
				print ""
				print "Done"
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
						time.sleep(1)
			print
			print
	                print "##########################################"
			print "**"
			print "Search function terminated"
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
				print
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
				print "Saving non wanted search to no.result"

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
print "=Calling Search function="
print "=/\/\/\/\/\/\/\/\/\/\/\/\="

Minwords = len(Keywords)/10
Maxwords = len(Keywords)/5
rndwords = random.randint(Minwords,Maxwords)

print
print "**"
print "Today's Menu :"
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
print "=Check Last Searched hashtags function started="
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
	print "=New Menu for today !="
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
print "= All Done Now Calling Retweet function="
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
print
print
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
print "=Retweet function stopped="
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
print
print "=/\/\/\/\/\/\/\/\/\="
print "=Saving calls count="
print "=/\/\/\/\/\/\/\/\/\="
print
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
print "=Saving Today's menu="
print "=/\/\/\/\/\/\/\/\/\/="
print 
print
print
print

lastmeal(Keywords[:rndwords])
print
print "#################################################TheEnd#############################################################"
#################################################TheEnd#############################################################
