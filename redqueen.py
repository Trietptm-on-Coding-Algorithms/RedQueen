#!/usr/bin/python
import time
import random
from twython import Twython, TwythonError
from TwitterApiKeys import app_key, app_secret, oauth_token, oauth_token_secret
from operator import itemgetter

#Some Vars

twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)

Keywords = ["zombie host","Zeroize","worm","wlan","Wireless Local Area Network","Wireless Application Protocol","Wireless Access Point","wep","Wired Equivalent Privacy","Wi-Fi Protected Access 2","Web Bug","Vulnerability Analysis","virtual private network","Virtual Machine","Unsigned data","Unauthorized access","Unauthorized Disclosure","Tunneling","revoked certificate","untrusted Certificate","Trusted Certificate","Trojan Horse","Transport Layer Security","Triple DES","Traffic Flow Security","traffic padding","Traffic Encryption Key","security traffic Analysis","Tracking Cookie","tampered data","Tampering","Tailored Security","System Integrity","System Administrator","Symmetric Key","Surrogate Access","supply chain attack","Striped Core","Steganography","Spyware","Spam Filtering","spam","Smart Card","Skimming","single Hop Problem","signed Data","Signature Certificate","data Sensitivity","Security Testing","Security Mechanism","security kernel","security Fault Analysis","reverse Engineering","Security Engineering","Security Banner","ssl","Secure Socket Layer","sha","Secure Hash Algorithm","SECDNS","Scatternet","Scanning","SCADA","Sandboxing","Rootkit","Root Certification","Root access","rogue device","robust security network","risk monitoring","risk mitigation","Rijndael","restricted data","reserve keying","repository","replay attacks","write access","Read Access","Random bit Generator","Random Number Generator","RFID vulnerability","RFID flaw","Radio Frequency Identification","public key","private key","pseudorandom","Proxy Agent","tor","vpn open source","free vpn","proxy list","proxychain","Proxy","Protocol Entity","Protected Distribution System","promiscuous mode","probing","privilege management","api key","private key","Privacy System","port scanning","bluetooth vulnerability","bluetooth flaw","piconet","personal identification number","Payload","password list","password cracking","passive wiretapping","passive security testing","passive attack","packet filter","wifi flaw","open source","online attack","network weaving","penetration technique","sniffing","network address translation ","network access control","multi hop","byod","minimalist cryptography","mimicking","MIME","multipurpose internet mail extensions","message digest","Cryptosystem","Mandatory Access Control","MitM","malicious logic","malicious code","malicious applets","magnetic remanence","data intercept","probability of Detection","logic bomb","local access","link encryption","keystroke monitoring","key production key","key logger","key escrow","Kerberos","jamming","security architecture","ipsec","intrusion detection systems","system intrusion","ipv6","ipv4","internet protocol","integrity check","incident handling","imitative communications deception","ip spoofing","identity binding","artificial intelligence","ai","ia","handshaking","handshaking procedures","guessing entropy","gray box testing","disk encryption","frequency hopping","forward cipher","Flooding","Firmware","firewall","file encryption","false positive","extranet","exploit code","error detection code","ephemeral key","risk management","end to end security","end to end encryption","encryption","encrypted network","encrypt","infosec","encode","encipher","embedded crypto","electronic signature","egress filtering","eavesdropping","dual use certificate","dmz","demilitarized zone","decrypt","decipher","rot13","data security","data integrity","data flow control","data encryption standard","data encryption algorithm","data aggregation","defcon","cyber attack","cyber incident","cryptology","hash function","cryptographic","cryptanalysis","cross certificate","critical security","credential","cover coding","authentication code","key generation","network exploitation","network attack","computer incident response","COMSEC","CVS","common vulnerabilities","internet of things","misonfiguration ","collision hash","code book","cloud computing","clear text","Xor","checksum","bulk encryption","brute force","block cipher","data leak","users data","black box testing","bit error","biometric","debugger","banner grabbing","backtracking","backdoor","hexadecimal","security monitoring","authentication token","authentication protocol","audit","attack signature","magic number","asymmetric","antispyware","anti spoof","anti jam","anonymous","advanced persistent threats","advanced key processor","advanced encryption standard","admin account","add-on security","ad hoc network","activation data","access point","bypass login","cryptography","phishing","honeypot","hacking","ddos","malware","rfid","hash","SocialEngineering","0day","cross site scripting","cyber security","security vulnerability","forensic","blind sql injection","local file inclusion","privilege escalation","fork bomb","request forgery","metasploit","password","sql injection","privilege elevation","vulnerability","xss","penetration testing","header injection","pentest","man in the middle","man in the browser","remote access","java security","buffer overflow","keylog","session fixation","security flaw","remote exploit","wpa2","ransomware","trojan","botnet","snowden","nsa","blackhat","whitehat","hacktivist","Access Authority"]

random.shuffle(Keywords)

Following = ['CUSecTech', 'InfoSecHotSpot', 'IndieRadioPlay', 'TopMaths', 'ergn_yldrm', 'MegalopolisToys', 'ISC2_Las_Vegas', 'jeffreycady', 'XenDesktop', 'BugBountyZone', 'sciendus', 'Dambermont', 'ghwizuuy', 'hackmiami', 'smirnovvahtang', 'uncl3dumby', 'theStump3r', 'SecureAuth', 'StagesInfograph', '9gnews365', 'secmo0on', 'alexheid', 'XenApp', 'vleescha1', 'CMDSP', 'abouham92597469', 'NetNeutralityTp', 'puja_mano', 'AliSniffer', 'DrupalTopNews', 'ChromeExtenNews', 'sebastien_i', 'Techworm_in', 'argevise', 'windows10apps4r', 'primeroinfotek', 'HAKTUTS', 'ciderpunx', 'kfalconspb', 'whitehatsec', 'furiousinfosec', 'Trencube_GD', 'CtrlSec', 'hacking_report', 'n0psl', 'CryptoKeeUK', '0xDUDE', 'crowd42', '_HarmO_', 'CNNum', 'OxHaK', 'Paddy2Paris', 'RevueduDigital', 'androidapps4rea', 'cryptoland', 'CombustibleAsso', 'geeknik', 'HansAmeel', 'cryptoishard', 'YoouKube', 'jouermoinscher', 'moixsec', 'cyberwar', 'danielbarger67', 'SecurityNewsbot', 'cityofcrows', 'SysAdm_Podcast', 'shafpatel', 'k4linux', 'Refuse_To_Fight', 'x_adn', 'Duffray14', 'AbdelahAbidi', 'pranyny', 'razlivintz', 'unmanarc', 'wallarm', 'foxooAnglet', 'foxoo64', 'brainhackerzz', 'duo_labs', 'zenterasystems', 'jilles_com', 'partyveta760', 'ComixToonFr', 'doaa90429042', 'bestvpnz', 'aebay', 'suigyodo', 'parismonitoring', 'menattitude', 'BretPh0t0n', 'ChariseWidmer', 'racheljamespi', 'ZeNewsLink', 'Omerta_Infosec', '_plesna', 'LawsonChaseJobs', 'fredericpoullet', 'RogersFR', 'jesuiscandice7', 'jeanneG50', 'CryptoXSL', 'maccimum', 'foxtrotfourwbm', 'fido_66', 'AGveille', 'InfoManip', 'HiroProtag', 'jhosley', 'Netmonker', 'tetaneutralnet', 'DefiLocacite', 'MTCyberStaffing', 'thecap59', 'Max1meN1colella', 'CharlesCohle', 'BrianInBoulder', 'ArsneDAndrsy', 'BullFR', 'Five_Star_Tech', 'pourconvaincre', 'Be_HMan', 'click2livefr', 'ElydeTravieso', 'n0rssec', '_fixme', 'infographisteF', 'zephilou', 'puneeth_sword', 'CheapestLock', 'Eprocom', 'LocksmithNearMe', 'YoshiDesBois', 'databreachlaws', 'LDarcam', '_CLX', 'dreadlokeur', '_sinn3r', 'operat0r', 'Moutonnoireu', 'MatToufoutu', 'mubix', 'abcdelasecurite', 'meikk', 'MadDelphi', 'ec_mtl', 'unixist', 'EricSeversonSec', 'slaivyn', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'cabusar', 'julien_c', 'moswaa', 'lycia_galland', 'YrB1rd', 'DogecoinFR', 'corkami', 'Barbayellow', 'Spiceworks', 'dt_secuinfo', 'Yaagneshwaran', 'btreguier', 'TheStupidmonKey', 'follc', '2xyo', 'crazyjunkie1', 'LeCapsLock', 'gizmhail', 'piscessignature', 'JamiesonBecker', '_SaxX_', 'isgroupsrl', 'NuitInfo2K13', 'yenos', 'SecurityTube', 'Gameroverdoses', 'Brihx_', 'silvakreuz', 'DamaneDz', '_bratik', 'vprly', 'didierdeth', 'sudophantom', 'xxradar', 'Techno_Trick', 'malphx', 'wixiweb', 'ChrisGeekWorld', 'AmauryBlaha', 'LRCyber', 'FranckAtDell', 'netrusion', 'ubuntuparty', 'grokFD', 'CISOtech', 'NotifyrInc', 'marcotietz', 'accident', 'darthvadersaber', 'VForNICT', 'ID_Booster', 'yw720', 'AgenceWebEffect', 'JeanLoopUltime', 'guideoss', 'Security_FAQs', 'Oursfriteorchid', 'Gr3gland', 'caaptusss', 'ygini', 'videolikeart', 'Veracode', 'CyberExaminer', 'hackademics_', 'razopbaltaga', 'eric_kavanagh', 'Ikoula', 'LeBlogDuHacker', 'rexperski', 'MathieuAnard', 'ced117', 'Panoptinet', 'BuzzRogers', 'ITSecurityWatch', 'PatchMob', 'officialmcafee', 'hnshah', 'AnonLegionTV', 'sh1rleysm1th', 'soocurious', 'PremiereFR', 'mob4hire', 'ericosx', 'yesecurity', 'DLSPCDoctor', 'tyrus_', 'gritsicon', 'trollMasque', 'AmauryPi', 'OpenForceMaroc', 'CybersimpleSec', 'PorterHick', 'AllTechieNews', 'revvome', 'livbrunet', 'aeris22', 'InfoSecMash', 'gigicristiani', 'stephanekoch', 'leduc_louis', 'ilhamnoorhabibi', 'servermanagedit', 'GTAFRANCE', '1humanvoice', 'stmanfr', 'Current_Tech', 'PEGE_french', 'Kuzbari', 'iisp_hk', 'Facebook_Agent', 'ZeroSkewl', 'chuckdauer', 'Itsuugo', 'Florianothnin', 'neeuQdeR', 'HYCONIQ', 'disk_91', 'ZOOM_BOX_r', 'Rimiologist', 'Matrixinfologic', 'GeneralSeven', 'preventiasvcs', 'atmon3r', 'filowme', 'FcsFcsbasif', 'catalyst', 'Spawnhack', 'globalwifiIntl', 'CajunTechie', 'ConstructionFOI', 'k8em0', 'Flavioebiel', 'FlacoDev', 'Fibo', 'wisemedia_', 'floweb', 'adistafrance', 'AnonBig', 'tacticalflex', 'Katezlipoka', 'MathieuZeugma', 'SophiAntipolis', 'matalaz', 'edehusffis', 'patricksarrea', 'SnapAndShine', 'cryptomars', 'OpPinkPower', 'DidierStevens', 'patatatrax', 'AJMoloney', 'cheetahsoul', 'vxheavenorg', 'defconparties', 'gvalc1', 'clemence_robin', 'XeroFR', 'noncetonic', 'bonjour_madame', 'LeWebSelonEdrek', 'robajackson', 'greenee_gr', 'zahiramyas', 'nation_cyber', 'Rio_Beauty_', 'Sadnachar', 'SecRich', 'unbalancedparen', 'Fyyre', 'VirusExperts', 'Applophile', 'Aziz_Satar', 'SecretDefense', 'Hi_T_ch', 'wireheadlance', 'define__tosh__', 'hamsterjoueur', 'PUREMEDIAHDTV', 'secdocs', 'code010101', 'LagunISA', '_theNextdoor_', 'lefredodulub', 'i4ppleTouch', 'imatin_net', 'KiadySam', 'toiletteintime', 'espeule', '1er_degres', 'BSoie', 'Pintochuks', 'selphiewall479', 'ApScience', 'suivi_avec_lisa', 'TiffenJackson', 'SecretGossips', 'sarahMcCartney2', 'wheatley_core', 'PatSebastien']

Friends = ['pondeboard1', 'ceb0t', 'theStump3r', 'uncl3dumby', 'gr3yr0n1n', 'poa_nyc', 'Demos74dx', 'sebastien_i', 'HAKTUTS', 'R00tkitSMM', 'pondeboard', 'AcidRampage', 'IncursioSubter', 'BSeeing', 'evleaks', 'InfoSec_BT', 'HIDGlobal', 'kjhiggins', 'vkamluk', 'codelancer', 'ciderpunx', 'HugoPoi', 'kfalconspb', 'lconstantin', 'coolhardwareLA', 'fsirjean', 'h0x0d', 'RCCyberofficiel', 'Tech_NurseUS', 'whitehatsec', 'oej', 'Trencube_GD', 'cissp_googling', '_pronto_', 'CtrlSec', 'ModusMundi', 'SwiftOnSecurity', 'RichRogersIoT', 'jonathansampson', 'Luiz0x29A', 'StephenHawking8', 'dpmilroy', 'usa_satcom', 'hack3rsca', 'PELISSIERTHALES', 'g00dies4', 'rpsanch', 'furiousinfosec', 'Om_dai33', 'wulfsec', 'securiteIT', 'pavornoc', 'hacking_report', 'primeroinfotek', 'L4Y5_G43Y', 'PaulM', 'seclyst', 'cmpxchg16', 'iainthomson', 'e_modular', '_jtj1333', 'n0psl', 'blaked_84', 'tb2091', 'dfirfpi', 'manonbinet001', 'webmathilde', '0xDUDE', 'nn81', 'CryptoKeeUK', 'n1nj4sec', 'ydklijnsma', 'scanlime', '0x6D6172696F', 'nono2357', 'derekarnold', 'hasherezade', '_HarmO_', 'OxHaK', 'CWICKET', 'linuxaudit', 'Space__Between', 'lordofthelake', 'Hired_FR', 'Laughing_Mantis', 'InfoSecHotSpot', 'geeknik', 'CharlesCohle', 'BretPh0t0n', 'jilles_com', 'duo_labs', 'unmanarc', 'x_adn', 'k4linux', 'shafpatel', 'SysAdm_Podcast', 'Everette', 'DadiCharles', 'danielbarger67', 'quequero', 'SecurityNewsbot', 'cityofcrows', 'Dinosn', 'ibmxforce', 'thepacketrat', 'cryptoishard', 'DEYCrypt', 'attritionorg', 'mzbat', 'da_667', 'krypt3ia', 'Z0vsky', 'BSSI_Conseil', 'SecMash', 'corexpert', 'maldevel', 'pof', 'FFD8FFDB', 'Snowden', 'lexsi', 'bestvpnz', 'EnfanceGachee', 'samykamkar', 'pevma', 'kafeine', 'k0ntax1s', 'gN3mes1s', 'GawkerPhaseZero', 'FreedomHackerr', 'sec_reactions', '0xAX', 'nolimitsecu', 'bascule', 'm3g9tr0n', 'nbs_system', 'sn0wm4k3r', 'jivedev', 'd_olex', 'indiecom', 'BlueCoat', 'Tif0x', 'UnGarage', 'HomeSen', 'CTF365', 'Securityartwork', 'accessnow', 'ZeljkaZorz', 'mortensl', 'ThomasNigro', 'Sidragon1', 'garage4hackers', 'hanno', 'p4r4n0id_il', 'AsymTimeTweeter', 'Omerta_Infosec', 'nopsec', 'cyberguerre', 'Protocole_ZATAZ', 'Grain_a_moudre', 'BIUK_Tech', 'TMZvx', '_plesna', 'PhysicalDrive0', 'rodneyjoffe', 'ithurricanept', 'sec0ps', 'comex', 'deepimpactio', 'ClechLoic', 'AGveille', 'amzben', 'FIC_fr', 'EricSeversonSec', 'MalwarePorn', 'Odieuxconnard', 'unixist', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'pwcrack', 'PhilHagen', 'Falkvinge', 'IPv4Countdown', 'lycia_galland', 'wirehack7', 'linux_motd', 'lamagicien', 'ubuntumongol', '_cypherpunks_', 'TekDefense', 'LeakSourceInfo', 'moswaa', 'OsandaMalith', 'Lope_miauw', 'dt_secuinfo', 'morganhotonnier', 'Relf_PP', 'abcderza', 'Barbayellow', 'corkami', 'KitPloit', 'ec_mtl', 'bugs_collector', 'BleepinComputer', 'Tinolle1955', 'valdesjo77', 'xombra', 'julien_c', 'Spiceworks', 'snipeyhead', 'YrB1rd', 'Trojan7Sec', 'Yaagneshwaran', 'ZATAZWEBTV', 'f8fiv', 'Netmonker', 'epelboin', '0xmchow', 'angealbertini', 'Incapsula_com', 'SurfWatchLabs', 'Exploit4Arab', 'hackerstorm', '2xyo', 'JamiesonBecker', 'NuitInfo2K13', '_SaxX_', 'piscessignature', 'crazyjunkie1', 'SecurityTube', 'comptoirsecu', '_saadk', 'penpyt', 'yenos', 'Intrinsec', 'udgover', 'jujusete', 'poulpita', 'suffert', 'clementd', '_CLX', '_bratik', 'tomchop_', 'vprly', 'mboelen', 'martijn_grooten', 'aristote', 'gandinoc', 'silvakreuz', 'ifontarensky', 'cedricpernet', 'y0m', 'knowckers', 'lakiw', 'didierdeth', 'paulsparrows', 'sudophantom', 'arbornetworks', 'AzzoutY', 'cabusar', 'Xartrick', 'netrusion', 'AmauryBlaha', 'Techno_Trick', 'wixiweb', 'hackhours', 'netbiosX', 'Daniel15', 'Routerpwn', 'asl', 'jeetjaiswal22', 'shoxxdj', 'FranckAtDell', 'ubuntuparty', 'jpgaulier', 'adulau', 'fredraynal', 'shu_tom', 'Cyberprotect', 'LRCyber', 'cymbiozrp', 'bitcoinprice', 'lafibreinfo', 'dreadlokeur', 'YoouKube', 'NotifyrInc', 'olfashdeb', 'MiltonSecurity', 'quota_atypique', 'TNWmicrosoft', 'LLO64', 'davromaniak', 'ID_Booster', 'VForNICT', 'klorydryk', 'vam0810', 'SecurityWeek', 'secludedITaid', 'montrehack', 'cvebot', 'chetfaliszek', 'NeckbeardHacker', 'hipsterhacker', 'AgenceWebEffect', 'marcotietz', 'erwan_lr', 'guideoss', 'sonar_guy', 'notsosecure', 'FlipFlop8bit', 'MalwareAnalyzer', 'yw720', 'SebBLAISOT', 'Cubox_', 'Ninja_S3curity', 'maximemdotnet', 'lea_linux', 'securitypr', '0xUID', 'MargaretZelle', 'Gr3gland', 'steveklabnik', 'iooner', 'caaptusss', 'tuxfreehost', 'ygini', 'Mind4Digital', 'ADNcomm', 'Veracode', 'hackademics_', 'xhark', 'TopHatSec', '0xSeldszar', 'PLXSERT', 'eric_kavanagh', 'IT_securitynews', 'devttyS0', 'Parisot_Nicolas', 'dclauzel', 'SCMagazine', 'JoceStraub', 'HackerfreeUrss', 'dascritch', 'aabaglo', 'ITConnect_fr', 'razopbaltaga', 'cargamax', 'MyOmBox', 'Wobility', 'evdokimovds', 'dookie2000ca', 'nuke_99', 'isgroupsrl', '_fwix_', 'LeBlogDuHacker', 'Ikoula', 'PortableWebId', 'OfficialGirish', 'httphacker', 'ripemeeting', 'ymitsos', 'Solarus0', 'Zestryon', 'ko_pp', 'etribart', 'TomsGuideFR', 'k3170Makan', 'jeeynet', 'qualys', 'KdmsTeam', 'frsilicon', 'astro_luca', 'rexperski', 'spiwit', 'nuclearleb', 'mcherifi', 'laVeilleTechno', 'framasoft', 'NyuSan42', 'nextinpact', 'PirateOrg', 'MathieuAnard', 'blesta', 'IPv6Lab', 'billatnapier', 'starbuck3000', 'jmplanche', 'pbeyssac', 'Keltounet', 'cwolfhugel', 'ZeCoffre', 'Dave_Maynor', 'durand_g', 'TMorocco', 'CyberExaminer', 'PatchMob', 'Nathanael_Mtd', '1nf0s3cpt', 'ospero_', 'ced117', 'LinuxActus', 'Panoptinet', 'schoolofprivacy', 'TrustedSec', 'maccimum', 'hadhoke', 'Jordane_T', 'novogeek', 'ChimeraSecurity', 'officialmcafee', 'GolumModerne', 'milw0rms', 'AsmussenBrandon', 'arnolem', 'Goofy_fr', 'AnonLegionTV', 'infoworld', 'soocurious', 'atarii', 'SebydeBV', 'JacquesBriet', 'ITSecurityWatch', 'SecurityFact', 'dorkitude', 'CISecurity', 'bishopfox', 'jeremieberduck', 'ericosx', 'dimitribest', 'levie', 'andreaglorioso', 'tyrus_', 'DLSPCDoctor', 'guiguiabloc', 'AlainClapaud', 'yesecurity', 'trollMasque', 'planetprobs', 'vincib', 'LeCapsLock', 'kafeinnet', 'Irrodeus', 'jbfavre', 'guestblog', 'rboulle', 'Fr33Tux', 'SecurityHumor', 'creoseclabs', 'm0rphd', 'argevise', 'gritsicon', 'veorq', 'Abdelmalek__', 'OpenForceMaroc', 'hashbreaker', 'AlexandreThbau1', 'MacPlus', 'yrougy', 'MaldicoreAlerts', 'AmauryPi', 'TrendMicroFR', 'sirchamallow', 'ACKFlags', 'jameslyne', 'LaNMaSteR53', 'AllTechieNews', 'garfieldair', 'PorterHick', 'arstechnica', 'sendio', 'CipherLaw', 'Golem_13', 'livbrunet', 'RealMyop', 'KenBogard', 'KarimDebbache', 'SmoothMcGroove', 'AlDeviant', 'Canardpcredac', 'SebRuchet', 'F_Descraques', 'Unul_Officiel', 'Poischich', 'drlakav', 'genma', 'lastlineinc', 'Cryptomeorg', 'CybersimpleSec', 'DarkReading', 'tqbf', 'gyust', 'KanorUbu', 'walane_', 'jedisct1', 'hadopiland', 'all_exploit_db', 'brutelogic_br', 'lechat87', 'gigicristiani', 'aeris22', 'terminalfix', 'ChristophePINO', 'ihackedwhat', 'InfoSecMash', 'bayartb', 'ErrataRob', 'DefuseSec', 'jcsirot', 'christiaan008', 'gopigoppu', 'lawmanjapan', 'RichardJWood', 'darthvadersaber', 'BryanAlexander', 'leduc_louis', 'distriforce', 'democraticaudit', 'PaulChaloner', 'kentbye', 'HacknowledgeC', 'servermanagedit', 'Coders4africa', 'securitycast', 'macbid', 'tomsguide', 'DrInfoSec', '1humanvoice', 'fsf', 'volodia', 'clusif', 'gbillois', 'theliaecommerce', 'JoshMock', 'MarConnexion', 'stmanfr', 'archiloque', 'ggreenwald', 'libdemwasjailed', 'inthecloud247', 'BlogsofWarIntel', 'pewem_formation', 'zdnetfr', 'Current_Tech', 'ilhamnoorhabibi', 'PEGE_french', 'Lu1sma', 'msftsecurity', 'ashish771', 'brutenews', 'iPhoneTweak_fr', 'my_kiwi', 'SilvaForestis', 'PierreTran', 'Kuzbari', 'r0bertmart1nez', 'yttr1um', 'hrousselot', 'crashsystems', 'benlandis', 'netsecu', 'securityaffairs', 'Stormbyte', 'iisp_hk', 'zonedinteret', 'Facebook_Agent', 'confidentiels', 'CryptoFact', 'chuckdauer', 'vriesjm', '_antoinel_', 'dhanji', '_reflets_', 'Anon_Online', 'MailpileTeam', 'Itsuugo', 'mdecrevoisier', 'freeboxv6', 'garwboy', 'StackCrypto', 'ChanologyFr', '_gwae', 'ashk4n', 'nzkoz', 'Florianothnin', 'neeuQdeR', 'UsulduFutur', 'BullGuard', 'samehfayed', 'olesovhcom', 'dragondaymovie', 'Itforma', 'HYCONIQ', 'axcheron', 'blakkheim', 'pressecitron', 'ChrisGeekWorld', 'episod', 'thalie30', 'disk_91', 'idfpartipirate', 'PPAlsace', 'FlorenceYevo', 'gdbassett', 'VulnSites', 'Secunia', 'iteanu', 'sciendus', 'esrtweet', '6l_x', 'MduqN', 'Skhaen', 'daveaitel', 'ZeroSkewl', 'Rimiologist', 'ekse0x', 'ZOOM_BOX_r', 'aanval', 'fhsales', 'Ruslan_helsinky', 'OpLastResort', 'fcouchet', 'GTAXLnetIRC', 'TheAdb38', 'DeloitteUS', 'GeneralSeven', 'AustenAllred', 'AlliaCERT', 'Double_L83', 'scoopit', 'Dylan_irzi11', 'fr0gSecurity', 'atmon3r', '0x736C316E6B', 'Hask_Sec', 'Zer0Security', 'xssedcom', 'php_net', 'phpizer', 'JpEncausse', 'M4ke_Developp', 'nkgl', 'preventiasvcs', 'SwiftwayNet', 'c4software', 'who0', 'gandi_net', 'H_Miser', 'nikcub', 'gcouprie', 'MindDeep', 'MdM_France', 'SpritesMods', 'NakedSecurity', 'GDataFrance', 'conciseonline', 'filowme', 'regislutter', 'CelebsBreaking', 'globalwifiIntl', 't2_fi', 'catalyst', 'x6herbius', 'cryptocatapp', 'arahal_online', 'mtigas', 'ALLsecuritySoft', 'lisachenko', 'renaudaubin', 'wamdamdam', '01net', 'secuobsrevuefr', 'DataSecuB', 'drambaldini', 'secu_insight', 'cyber_securite', 'smeablog', 'DecryptedMatrix', 'eCoreTechnoS', 'topcodersonline', 'Sec_Cyber', 'thegaryhawkins', 'CajunTechie', 'Othrys', 'jeromesegura', 'RazorEQX', 'Xylit0l', 'c_APT_ure', 'it4sec', 'ConstructionFOI', 'Official_SEA16', 'OpGabon', 'SecuraBit', 'esheesle', 'brutelogic', 'taziden', 'sam_et_max', 'iMilnb', 'Clubic', 'greenee_gr', 'fo0_', 'nathanLfuller', 'carwinb', 'puellavulnerata', 'samphippen', 'ntisec', 'dummys1337', 'flanvel', 'SUPINFO', 'Epitech', 'Erebuss', 'infobytesec', 'garybernhardt', 'mab_', 'wisemedia_', 'LagunISA', 'wiretapped', 'verge', 'crowd42', 'virusbtn', 'FlacoDev', 'SunFoundation', 'TheNextWeb', 'guillaumeQD', 'IBMSecurity', 'code010101', 'gvalc1', 'adistafrance', 'LeWebSelonEdrek', 'tacticalflex', 'imatin_net', 'espeule', 'Applophile', 'nation_cyber', 'zahiramyas', 'alexheid', 'SecMailLists', 'mob4hire', 'AnonBig', 'FloCorvisier', 'MathieuZeugma', 'Katezlipoka', 'w_levin', 'climagic', 'PartiPirate', 'InfosecNewsBot', 'nedos', 'jerezim', 'katylevinson', 'ThVillepreux', 'PBerhouet', 'dbbimages', 'irqed', 'BLeQuerrec', 'patricksarrea', 'pierre_alonso', 'Flameche', 'AndreaMann', 'SciencePorn', 'mvario1', 'AbbyMartin', 'TheGoodWordMe', 'chroniclesu', 'DoubleJake', 'Kilgoar', 'TylerBass', 'FievetJuliette', 'Reuters', 'mrjmad', 'Sebdraven', 'SophiAntipolis', 'LaFranceapeur', 'papygeek', 'gordonzaula', 'neufbox4', 'plugfr', 'BenoitMio', '_Kitetoa_', 'Numendil', 'laquadrature', 'kheops2713', 'Slatefr', 'benjaltf4_', 'Fibo', 'codesscripts', 'zorelbarbier', 'Be_HMan', 'FranceAnonym', 'SpartacusK99', 'Free_Center', 'TrucAstuce', 'schignard', 'ciremya', 'MatVHacKnowledg', 'FreenewsActu', 'XSSed_fr', 'planetubuntu', 'S_surveillance', 'cyphercat_eu', 'Hack_Gyver', 'ncaproni', 'MISCRedac', 'Cyber_Veille', 'journalduhack', 'bidouillecamp', 'Apprenti_Sage', 'Oxygen_IT', 'FIC_Obs', 'orovellotti', 'cyberdefenseFR', 'l1formaticien', 'Reseauxtelecoms', 'neuromancien', 'actuvirus', 'cryptomars', 'amaelle_g', 'Hybird', 'Monitoring_fr', 'Zythom', 'InfosReseaux', 'speude', 'lavachelibre', 'dezorda', 'Bugbusters_fr', '3615internets', 'planetedomo', 'Mayeu', 'HeliosRaspberry', 'CiscoFrance', 'anonfrench', 'IvanLeFou', 'NosOignons', 'OSSIRFrance', 'patatatrax', 'EFF', 's7ephen', 'kaspersky', '2600', 'cheetahsoul', 'OpPinkPower', 'AJMoloney', 'ecrans', 'anonhive', 'julien_geekinc', 'Anonymous_SA', 'USAnonymous', 'e_kaspersky', 'FSecure', 'ClipperChip', 'ax0n', 'hevnsnt', 'Aratta', 'yolocrypto', 'waleedassar', 'postmodern_mod3', 'kochetkov_v', 'pwntester', 'bartblaze', 'TheDanRobinson', 'unpacker', 'r_netsec', 'AnonymousPress', 'priyanshu_itech', 'kinugawamasato', 'mozwebsec', 'zonehorg', 'beefproject', 'YourAnonNews', 'boblord', 'vikram_nz', 'PublicAnonNews', 'kkotowicz', 'hackersftw', '0xerror', 'fancy__04', 'l33tdawg', 'node5', '0xjudd', '_mr_me_', 'sickness416', 'googleio', 'infosecmafia', 'p0sixninja', 'isa56k', 'TheWhiteHatTeam', 'inj3ct0r', 'snowfl0w', 'SocEngineerInc', 'jdcrunchman', 'DiptiD10', 'ehackingdotnet', 'jack_daniel', 'BrandonPrry', 'TurkeyAnonymous', 'MarkWuergler', 'pranesh', 'eddieschwartz', 'mozilla', 'deCespedes', 'M0nk3H', 'tpbdotorg', 'IPredatorVPN', 'smarimc', 'Thomas_Drake1', 'opindia_revenge', 'Malwarebytes', 'EHackerNews', 'HNBulletin', 'dietersar', 'CCrowMontance', 'r3shl4k1sh', 'DanielEllsberg', 'PMOIndia', 'SecurityPhresh', 'vxheavenorg', 'kgosztola', 'TheHackersNews', 'jeromesaiz', 'Trem_r', 'netsabes', 'Flaoua', 'DannyDeVito', 'p0sixn1nja', 'twitfics', 'wzzx', 'DustySTS', 'Lincoln_Corelan', 'SecureTips', 'InfoSecRumors', 'matthew_d_green', 'agl__', 'elwoz', 'apiary', '0xabad1dea', 'dangoodin001', 'kpoulsen', 'ethicalhack3r', 'SecBarbie', 'dguido', 'marcusjcarey', 'jadedsecurity', 'petitpetitam', 'hackeracademy', 'moreauchevrolet', 'Jean_Leymarie', 'tricaud', 'Nipponconnexion', 'OtakuGameWear', 'schneierblog', 'g4l4drim', '0x73686168696e', 'securityvibesfr', 'window', 'sm0k_', 'pentesteur', 'AlainAspect', 'chandraxray', 'AstronomyNow', 'Astro_Society', 'SpitzerScope', 'NASAspitzer', 'NASAWebb', 'NASAFermi', 'SpaceflightNow', 'NASAStennis', 'sciam', 'WISE_Mission', 'NASA_Images', 'NatGeo', 'NASAblueshift', 'universetoday', 'NASAJPL_Edu', 'NASA_Orion', 'TrinhXuanThuan', 'Infographie_Sup', 'MartinAndler', 'pierenry', 'Bruno_LAT', 'RichardDawkins', 'guardianscience', 'TheSkepticMag', 'TomFeilden', 'gemgemloulou', 'AdamRutherford', 'Baddiel', 'DrAliceRoberts', 'ProfWoodward', 'SarcasticRover', 'robajackson', 'MarsCuriosity', 'BBCBreaking', 'shanemuk', 'Schroedinger99', 'AtheneDonald', 'imrankhan', 'danieldennett', 'paulwrblanchard', 'MartinPeterFARR', 'DPFink', 'sapinker', 'chrisquigg', 'minutephysics', 'AdamFrank4', 'SpaceX', 'astrolisa', 'Erik_Seidel', 'simonecelia', 'PhilLaak', 'TEDchris', 'colsonwhitehead', 'plutokiller', 'dvergano', 'carlzimmer', 'j_timmer', 'edyong209', 'Laelaps', 'bmossop', 'maiasz', 'ericmjohnson', 'WillmJames', 'BadAstronomer', 'billprady', 'reneehlozek', 'PolycrystalhD', 'BoraZ', 'sethmnookin', 'albionlawrence', 'RisaWechsler', 'seanmcarroll', 'imaginaryfndn', 'PhysicsNews', 'DiggScience', 'bigthink', 'PopSci', 'AIP_Publishing', 'NSF', 'NewsfromScience', 'BBCScienceNews', 'PhysicsWorld', 'ScienceNews', 'physorg_com', 'TED_TALKS', 'TreeHugger', 'physorg_space', 'physorg_tech', 'NASAGoddard', 'CERN_FR', 'neiltyson', 'ProfBrianCox', 'SethShostak', 'b0yle', 'NASAJPL', 'worldofscitech', 'michiokaku', 'OliverSacks', 'AMNH', 'JannaLevin', 'bgreene', 'AssoDocUp', 'MyScienceWork', 'ParisDiderot', 'molmodelblog', 'neilfws', 'pjacock', 'dalloliogm', 'yokofakun', 'mrosenbaum711', 'joshwhedon', 'BrentSpiner', 'moonfrye', 'greggrunberg', 'Schwarzenegger', 'RealRonHoward', 'arnettwill', 'AmandaSeyfried', 'JasonReitman', 'DohertyShannen', 'JohnStamos', 'frankiemuniz', 'TheRealNimoy', 'EyeOfJackieChan', 'dhewlett', 'ZacharyLevi', 'MillaJovovich', 'JohnCleese', 'BambolaBambina', 'CERN', 'CNES', 'Inserm', 'NASA', 'USGS', 'NatureNews', 'Planck', 'IN2P3_CNRS', 'Inria', 'INC_CNRS', 'tgeadonis', 'inp_cnrs', 'AlainFuchs', 'CNRSImages', 'FabriceImperial', 'CNRS', 'laurentguyot', 'consult_detect', 'NewsBreaker', 'ISS_Research', 'nicolaschapuis', 'PolarisTweets', 'uncondamne', 'veytristan', 'gplesse', 'MattBellamy', 'LeParisien_Tech', 'Pontifex_fr', 'DenisCourtine', 'PascalDronne', 'NSegaunes', 'LeParisien_Buzz', 'NoemieBuffault', 'LesInconnus', 'FBIBoston', 'Pascallegitimus', 'lucabalo', 'isabellemathieu', 'FlorentLadeyn', 'NaoelleTopChef', 'quentintopchef', 'julienduFFe', 'natrevenu', 'yannforeix', 'defrag', 'rybolov', 'securid', 'stacythayer', 'tcrweb', 'Techdulla', 'TimTheFoolMan', 'treguly', 'YanceySlide', 'golfhackerdave', 'liquidmatrix', 'jonmcclintock', 'infosecpodcast', 'HypedupCat', 'Hak5', 'georgevhulme', 'gcluley', 'gattaca', 'g0ne', 'EACCES', 'digininja', 'devilok', 'd4ncingd4n', 'CSOonline', 'anthonymckay', 'abaranov', 'aaronbush', '_LOCKS', 'security_pimp', 'teksquisite', 'blpnt', 'alpharia', 'jgarcia62', '_MC_', 'InfoSec208', 'SPoint', 'i0n1c', 'torproject', 'room362', 'nicowaisman', 'VirusExperts', 'DavidHarleyBlog', 'follc', 'episeclab', 'manhack', 'pollux7', 'y0ug', 'Hallewell', 'SteveGoldsby', 'polarifon', 'malwarecityFR', 'Webroot', 'Infosanity', 'BitDefenderAPAC', 'VirusExpert', 'securitypro2009', 'blackd0t', 'securityfocus', 'DanaTamir', 'securitywatch', 'securitynetwork', 'PrivacySecurity', 'securitystuff', 'myCSO', 'RSAsecurity', 'SecurityExtra', 'WebSecurityNews', 'web_security', 'SCmagazineUK', 'TechProABG', 'malwareforensix', 'stephanekoch', 'daleapearson', 'CyberSploit', 'veryblackhat', 'opexxx', 'Hakin9', 'EvilFingers', 'isaudit', 'SpiderLabs', 'securegear', 'gdssecurity', 'ioerror', 'yaunbug', 'dstmx', 'zentaknet', 'wireheadlance', 'TenableSecurity', 'secdocs', 'proactivedefend', 'racheljamespi', 'xxradar', 'aebay', 'vincentzimmer', 'xanda', 'MarioVilas', 'sting3r2013', 'SecRich', 'deanpierce', 'HaDeSss', 'Jolly', 'searchio', 'thomas_wilhelm', 'gollmann', 'HackerTheDude', 'ADMobilForensic', 'SecurityStream', 'gadievron', 'tomaszmiklas', 'irongeek_adc', '_____C', 'operat0r', 'carne', 'fmavituna', 'PandaSecurityFR', 'freaklabs', 'alphaskade', 'hgruber97', 'noncetonic', 'AVGFree', 'k0st', 'kargig', 'lgentil', 'andreasdotorg', 'redragonvn', 'theharmonyguy', 'NoSuchCon', 'b10w', '0security', 'Z3r0Point', 'bortzmeyer', 'ahoog42', 'gianluca_string', 'eLearnSecurity', 'k4l4m4r1s', 'issuemakerslab', 'matalaz', 'ForcepointLabs', 'iExploitXinapse', 'itespressofr', 'ehmc5', 'practicalexplt', 'Pentesting', 'avkolmakov', 'manicode', 'HITBSecConf', 'sensepost', 'TeamSHATTER', 'n00bznet', 'thegrugq', 'judy_novak', 'TaPiOn', 'revskills', 'randomdross', 'malphx', 'OpenMalware', 'syngress', '2gg', 'GNUCITIZEN', 'chrissullo', 'michael_howard', 'c7five', 'pdp', 'securosis', 'Shadowserver', 'BlackHatHQ', 'securityincite', 'bsdaemon', 'Secn00b', 'dyngnosis', 'mwtracker', 'BorjaMerino', 'packetlife', 'toolcrypt', 'hackmiami', 'OWASP_France', 'jkouns', 'Mario_Vilas', 'zate', '_supernothing', 'aszy', 'lestutosdenico', 'espreto', '_sinn3r', 'aloria', 'Fyyre', 'SymantecFR', 'aircrackng', 'hackerschoice', 'MuscleNerd', 'smalm', 'OxbloodRuffin', 'subliminalhack', 'bannedit0', 'armitagehacker', 'RealGeneKim', 'mxatone', 'Snort', 'rebelk0de', 'hackingexposed', 'virustotalnews', 'InfiltrateCon', 'aramosf', 'msfdev', 'ChadChoron', 'n0secure', 'ITRCSD', 'CyberDefender', 'ArxSys', 'lulzb0at', 'crypt0ad', 'Stonesoft_FR', 'LordRNA', 'WindowsSCOPE', 'yo9fah', 'michelgerard', 'NAXSI_WAF', 'v14dz', 'x0rz', 'tbmdow', 'kasperskyfrance', 'Agarri_FR', 'ISSA_France', 'Jhaddix', 'Heurs', 'PlanetCreator', 'infernosec', 'rexploit', 'ConfCon', 'securityshell', 'bonjour_madame', 'minusvirus', 'emiliengirault', 'dvrasp', 'virtualabs', 'rfidiot', 'ttttth', 'msuiche', 'Ivanlef0u', 'Korben', 'hackersorg', 'shell_storm', 'WTFuzz', 'MoonSols', 'newsoft', 'vnsec', 'in_reverse', 'hackerfantastic', 'mtrancer', 'datacenter', 'stelauconseil', 'CNIL', 'exploitdb', 'BillBrenner70', 'lagrottedubarbu', 'HackingDave', 'VUPEN', 'siddartha', 'bluetouff', 'sstic', 'ToolsWatch', 'emmasauzedde', 'lseror', 'bearkasey', 'xme', 'helpnetsecurity', 'hackinthebox', 'Transiphone', 'hackaday', 'TheSuggmeister', 'Herve_Schauer', 'humanhacker', 'it_audit', 'Jipe_', 'FredLB', '0vercl0k', 'secbydefault', 'kerouanton', 'dragosr', 'endrazine', 'HBGary', 'pentestit', 'madpowah', 'serphacker', 'security4all', 'SecuObs', 'vloquet', 'joegrand', 'matrosov', 'DIALNODE', 'brucon', 'corelanc0d3r', 'RSnake', '0xcharlie', 'taviso', '41414141', 't0ka7a', 'thedarktangent', 'mubix', 'jonoberheide', 'spacerog', 'ChrisJohnRiley', 'securityninja', 'threatpost', 'nasko', 'mwrlabs', 'justdionysus', 'iHackwing', 'DJLahbug', 'cyber_security', 'hardhackorg', 'e2del', 'a41con', 'msftsecresponse', 'sans_isc', 'egyp7', 'antic0de', 'mikko', '_MDL_', 'mdowd', 'carnal0wnage', 'jeremiahg', 'xorlgr', 'cesarcer', 'BlackHatEvents', 'MatToufoutu', 'csec', 'selectrealsec', 'CERTXMCO', 'SecuritySamurai', 'razlivintz', 'etcpasswd', 'The_Sec_Pub', 'meikk', 'securityweekly', 'alexsotirov', 'DidierStevens', 'beist', 'stalkr_', 'dakami', 'halvarflake', 'dinodaizovi', 'silviocesare', 'stephenfewer', 'barnaby_jack', 'andremoulu', 'thierryzoller', 'PwnieAwards', 'reversemode', 'kalilinux', 'gynvael', 'pusscat', 'abcdelasecurite', 'johnjean', 'ninjanetworks', 'sotto_', 'SecretDefense', 'FFW', 'commonexploits', 'x86ed', 'zsecunix', 'hack_lu', 'Majin_Boo', 'BadShad0w', 'FlUxIuS', 'valuphone', 'free_man_', 'teamcymru', 'ihackstuff', 'secureideas', 'sansforensics', 'benoitbeaulieu', 'LaFermeDuWeb', 'TwitPic', 'noaheverett', 'lostinsecurity', 'democracynow', 'dougburks', 'zephilou', 'kevinmitnick', 'defcon', 'SecurityBSides', 'haxorthematrix', 'rmogull', 'unbalancedparen', 'perfectvendetta', 'siccsudo', 'Nan0Sh3ll', 'newroot', 'ClsHackBlog', '27c3', 'c3streaming', 'SOURCEConf', 'eugeneteo', 'moxie', 'dlitchfield', 'thezdi', 'scarybeasts', 'ryanaraine', 'kernelpool', 'esizkur', 'richinseattle', 'WeldPond', 'k8em0', 'jduck', 'ultramegaman', 'tsohlacol', 'HeatherLeson', 'myrcurial', 'nudehaberdasher', 'drraid', 'Agarik', 'Aziz_Satar', 'hackinparis', 'sdwilkerson', 'Satyendrat', 'LawyerLiz', 'UnderNews_fr', 'deobfuscated', 'HacKarl', 'StopMalvertisin', 'djrbliss', 'TinKode', 'HappyRuche', 'rssil', 'sysdream', 'acissi', 'migrainehacker', 'xsploitedsec', 'sucurisecurity', 'bonjourvoisine', 'Sorcier_FXK', 'mikekemp', 'jaysonstreet', 'roman_soft', 'xavbox', 'HackBBS', 'securitytwits', 'Hi_T_ch', 'DarK_Kiev', 'lbstephane', 'hugofortier', 'bl4sty', 'kaiyou466', 'Thireus', 'Paul_da_Silva', 'fbaligant', '_metalslug_', 'ochsff', 'fjserna', 'JonathanSalwan', 'ericfreyss', 'julianor', 'j00ru', '0xGrimmlin', 'define__tosh__', 'hesconference', 'Calculonproject', 'ZenkSecurity', 'Moutonnoireu', 'newsycombinator', 'securityh4x', 'corbierio', 'Security_Sifu', 'str0ke', 'owasp', 'milw0rm', 'gsogsecur', 'USCERT_gov', 'packet_storm', 'CoreSecurity', 'CiscoSecurity', 'ECCOUNCIL', 'securityweb', 'debian_security', 'ubuntu_security', 'SocialMediaSec', 'offsectraining', 'JournalDuPirate', 'ThisIsHNN', 'nmap', 'metasploit', 'orangebusiness', 'tixlegeek', 'rapid7', 'defconparties', 'ProjectHoneynet', 'NoWatch', '1ns0mn1h4ck', 'zataz', 'r00tbsd', 'hackerzvoice', 'JournalDuGeek', 'Senat_Direct', 'franceculture', 'MetroFrJustice', 'MrAntoineDaniel', 'tanguy', '_clot_', 'Reuno', 'chiptune', 'nicolasfolliot', 'johnmartz', 'lifehacker', 'Vfalkrr', 'AurelieThuot', 'PinkPaink', 'jnkboy', 'ManardUV', 'AsherVo', 'Stephan_Kot', 'thatgamecompany', 'Dedodante', 'RomainSegaud', 'TheMarkTwain', 'Maitre_Eolas', 'jmechner', 'SeinfeldToday', '5eucheu', 'FRANCHEMENT_', 'SuricateVideo', 'alainjuppe', 'antoine64', 'ydca_nico', 'aleksou', 'docslumpy', 'jeremy345', 'TRYWAN', 'UrielnoSekai', 'Mister_AlAmine', 'KrSWOoD', 'hamsterjoueur', 'JyanMaruku', 'insertcoinFR', 'MisterAdyboo', 'MrBouclesDor', 'Gorkab', '____Wolf____', 'Ben_MORIN', 'lestortuesninja', 'neocalimero', 'Sadnachar', 'KazHiraiCEO', 'Bethesda_fr', 'ChrisToullec', 'Juliette1108', 'RisingStarGames', 'LtPaterson', 'VGLeaks', 'SonySantaMonica', 'l87Nico', 'Yatuu', 'cbalestra', 'yosp', 'twfeed', 'ludaudrey', 'RpointB', 'danielbozec', 'LiveScience', 'Rue89', 'ScienceChannel', 'ScienceDaily', 'ubergizmofr', 'Gizmodo', 'Virgini2Clausad', 'fabriceeboue', 'ThibBracci', 'labeauf', 'waterkids', 'MisterMcFlee', 'FranckLassagne', 'GraiggyLand', 'Galagan_', 'BenCesari', '_RaHaN_', 'Tris_Acatrinei', 'Valent1Bouttiau', 'Julien_Bouillet', 'UncleTex', 'Suchablog', 'laboitecom', 'coverflow_prod', 'TeamTerrasse', 'IGmagazine', 'Wael3rd', 'Rogedelaaa', 'starcowparis', 'liloudalas', 'emanu124', 'xfrankblue', 'K0RSIK0', 'UlycesEditions', 'Djoulo', 'cabanong', 'laureleuwers', 'clemence_robin', 'suriondt', '_Supertroll', 'Neveu_Tiphaine', '_theNextdoor_', 'tomnever', 'DavidChoel', 'Elmedoc', 'Delzarissa', 'Nolife_Online', 'NicolAspatoule', 'Frederic_Molas', 'Marcuszeboulet', 'PlayStation', 'RockstarGames', 'Naughty_Dog', 'notch', 'pirmax', 'miklD75', 'ClorindeB', 'NathalieAndr', 'ODB_Officiel', 'LeGoldenShow', 'HIDEO_KOJIMA_EN', 'damiensaez', 'DIEUDONNEMBALA', 'FQXi', 'PerleDuBac', 'SatoshiKon_bot', 'shin14270', 'tsamere', 'Bouletcorp', 'CasselCecile', 'RaynaudJulie', 'LionnelAstier', 'swinefever', 'normanlovett1', 'SteveKeys66', 'DannyJohnJules', 'LeoDiCaprio', 'wikileaks', 'TORDFC', 'RedDwarfHQ', 'DalaiLama', 'Al_Hannigan', 'AnthonySHead', 'SteveMartinToGo', 'bobsaget', 'gwenstefani', 'JohnMCochran', 'ActuallyNPH', 'CobieSmulders', 'alydenisof', 'jasonsegel', 'kavanaghanthony', 'RafMezrahi', 'BellemareOut', 'BellemarePieR', 'rataud', 'piresrobert7', 'beigbedersays', 'IamJackyBlack', 'oizo3000', 'ericetramzy', 'yannlaffont', 'michel_denisot', 'VincentDesagnat', 'PaulMcCartney', 'Pascal__Vincent', 'JimCarrey', 'simonastierHC', 'manulevyoff', 'GillesLellouche', 'axellelaffont', 'xaviercouture', 'emougeotte', 'bernardpivot1', 'sgtpembry', 'Xavier75', 'NicolasBedos1', 'Chabat_News', 'stephaneguillon', 'farrugiadom', 'francoisrollin', 'kyank', 'levrailambert', 'lolobababa', 'jimalkhalili', 'alexnassar', 'suivi_avec_lisa', 'Suzuka_Nolife', 'DavidHasselhoff', 'CCfunkandsoul', 'CaptainAJRimmer', 'DougRDNaylor', 'bobbyllew', 'katherineravard', 'ReizaRamon', 'kaorinchan', 'NolifeOfficiel', 'floweb', 'Thugeek', 'LoloBaffie', 'charlottesavary', 'SebRaynal', 'GirlButGeek', 'bjork', 'YOUNMICHAEL', 'hartza_info', 'ApScience', 'ApertureSciCEO', 'wheatley_core', 'ApertureSciPR', 'lilyallen', 'koreus', 'MichaelYoun']

apicall = 0

allok = 0

retweetlist = []

QueueList = []

#Some Defs


def Retweet():


        if allok == 1:
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                print "!                RETWEETING               !"
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"


		for item in QueueList:

				limits()

				FinalItem = item.split("-")[1]

				print "Retweeting : ",item
		                try:
		                        twitter.retweet(id = FinalItem)
			                print "Done !"
					print
					
					apicall = apicall +1
					print
		
                                except :
                                        print
                                        print "Error Sorry im trying the next one "
                                        print

				time.sleep(2)


def tweetlist(point,id):

        ammo = str(point) + "-" + str(id)
        retweetlist.append(ammo)

	tri = sorted(retweetlist,key=lambda line: int(line.split("-")[0]),reverse=True)

	QueueList = tri
	print
	print "=="
	print "Loaded into Queue"
	print "=="
	print




def limits():
	global apicall
	rate = twitter.get_application_rate_limit_status()
	 
	print
	print "Apicall = ",apicall
	print

	if apicall >= 170:
		print
		print "****************************************"
		print "****************************************"
		print
		print "API RATE LIMITS ALMOST REACHED "
		print ""
		print "WAITING 15 MINUTES"
		time.sleep(900)
		print "Waking up.."
		print ""

                print
                print "****************************************"
                print "****************************************"
                print
		
		apicall = 0

		
		return apicall

#def Ban(






def Scoring(tweet):
#	global apicall
	Score = 0
        print "*************************************************************************************" 
	print "============================Starting Scoring function================================"
	print ""

	if 'retweet_count' in tweet and tweet['retweet_count'] != 0:
		
			print "This tweet has been retweeted %i times " % tweet['retweet_count']
			Score = Score + 1
			
			
			if tweet['retweet_count'] > 4 and tweet['retweet_count'] < 10:
				Score  = Score + 3
                        	

                        if tweet['retweet_count'] > 10 and tweet['retweet_count'] < 20:
                                Score  = Score + 4
                                

                        if tweet['retweet_count'] > 20 and tweet['retweet_count'] < 30:
                                Score  = Score + 5
                                

                        if tweet['retweet_count'] > 30 and tweet['retweet_count'] < 40:
                                Score  = Score + 6
                                

                        if tweet['retweet_count'] > 40 and tweet['retweet_count'] < 50:
                                Score  = Score + 7
                                

                        if tweet['retweet_count'] > 50 and tweet['retweet_count'] < 60:
                                Score  = Score + 8
                                

                        if tweet['retweet_count'] > 60 and tweet['retweet_count'] < 70:
                                Score  = Score + 9
                                

                        if tweet['retweet_count'] > 70 and tweet['retweet_count'] < 80:
                                Score  = Score + 10
                                

                        if tweet['retweet_count'] > 80 and tweet['retweet_count'] < 90:
                                Score  = Score + 11
                                

                        if tweet['retweet_count'] > 90 and tweet['retweet_count'] < 100:
                                Score  = Score + 12
                                

                        if tweet['retweet_count'] > 100 and tweet['retweet_count'] < 150:
                                Score  = Score + 13
                                

                        if tweet['retweet_count'] > 150 and tweet['retweet_count'] < 200:
                                Score  = Score + 14
                                

                        if tweet['retweet_count'] > 200 and tweet['retweet_count'] < 250:
                                Score  = Score + 15
                                

                        if tweet['retweet_count'] > 250 and tweet['retweet_count'] < 300:
                                Score  = Score + 16
                                

                        if tweet['retweet_count'] > 300 and tweet['retweet_count'] < 350:
                                Score  = Score + 17
                                

                        if tweet['retweet_count'] > 350 and tweet['retweet_count'] < 400:
                                Score  = Score + 18
                                

                        if tweet['retweet_count'] > 300 and tweet['retweet_count'] < 350:
                                Score  = Score + 19
                                

                        if tweet['retweet_count'] > 350 and tweet['retweet_count'] < 400:
                                Score  = Score + 20
                                

                        if tweet['retweet_count'] > 400 and tweet['retweet_count'] < 450:
                                Score  = Score + 21
                                

                        if tweet['retweet_count'] > 450 and tweet['retweet_count'] < 500:
                                Score  = Score + 22
                                

                        if tweet['retweet_count'] > 500 and tweet['retweet_count'] < 550:
                                Score  = Score + 23
                                

                        if tweet['retweet_count'] > 600 and tweet['retweet_count'] < 650:
                                Score  = Score + 24
                                

                        if tweet['retweet_count'] > 700 and tweet['retweet_count'] < 750:
                                Score  = Score + 25
                                

                        if tweet['retweet_count'] > 750 and tweet['retweet_count'] < 800:
                                Score  = Score + 26
                                

                        if tweet['retweet_count'] > 850 and tweet['retweet_count'] < 900:
                                Score  = Score + 27
                                

                        if tweet['retweet_count'] > 900 and tweet['retweet_count'] < 950:
                                Score  = Score + 28
                                

                        if tweet['retweet_count'] > 950 and tweet['retweet_count'] < 1000:
                                Score  = Score + 29
                                

                        if tweet['retweet_count'] > 1000 and tweet['retweet_count'] < 1500:
                                Score  = Score + 30
                                

                        if tweet['retweet_count'] > 1500 and tweet['retweet_count'] < 2000:
                                Score  = Score + 31
                                

                        if tweet['retweet_count'] > 2000 :
                                Score  = Score + 32
                                





        if 'entities' in tweet:
			
#		print tweet
		print


		if 'urls' in tweet['entities'] and len(tweet['entities']['urls']) > 0:
			print "This tweet contains a link : ",tweet['entities']['urls'][-1]['expanded_url']
			Score = Score + 1
                        


                if 'hashtags' in tweet['entities'] and len(tweet['entities']['hashtags']) > 0:
                        print "This tweet contains Hashtag : ",tweet['entities']['hashtags'][-1]['text']
                        Score = Score + 1
                        


                if 'media' in tweet['entities'] and len(tweet['entities']['media']) > 0:
                        print "This tweet contains Media : ",tweet['entities']['media'][-1]['media_url']
                        Score = Score + 1
                        

                if tweet['favorite_count'] > 0:

                        print "This tweet has been fav : ",tweet['favorite_count']
			Score = Score + 1
			

			fav = tweet['favorite_count']
			if fav > 10 and fav < 20:
                        	Score = Score + 1
			if fav > 20 and fav < 30:
				Score = Score + 2
			if fav > 30 and fav < 40:
				Score = Score + 3
                        if fav > 40 and fav < 50:
                                Score = Score + 4 
                        if fav > 50 and fav < 60:
                                Score = Score + 5
                        if fav > 60 and fav < 70:
                                Score = Score + 6
                        if fav > 70 and fav < 80:
                                Score = Score + 7 
                        if fav > 80 and fav < 90:
                                Score = Score + 8
                        if fav > 90 and fav < 100:
                                Score = Score + 9
                        if fav > 100 and fav < 150:
                                Score = Score + 10 
                        if fav > 150 and fav < 200:
                                Score = Score + 11
                        if fav > 200 and fav < 250:
                                Score = Score + 12
                        if fav > 250 and fav < 300:
                                Score = Score + 13
                        if fav > 300 and fav < 350:
                                Score = Score + 14
                        if fav > 350 and fav < 400:
                                Score = Score + 15
                        if fav > 400 and fav < 500:
                                Score = Score + 16
                        if fav > 500 and fav < 600:
                                Score = Score + 17
                        if fav > 600 and fav < 700:
                                Score = Score + 18
                        if fav > 700 and fav < 800:
                                Score = Score + 19 
                        if fav > 800 and fav < 900:
                                Score = Score + 20
                        if fav > 900 and fav < 1000:
                                Score = Score + 21
                        if fav > 1000 and fav < 2000:
                                Score = Score + 22
                        if fav > 2000:
                                Score = Score + 23




                        



                if 'followers_count' in tweet['user'] and tweet['user']['followers_count'] > 0:
                        print "Source followers count  : ",tweet['user']['followers_count']

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
                                




                if 'verified' in tweet['entities'] and len(tweet['entities']['verified']) == "True":
                        print "This tweet has been sent by a verified user : ",tweet['entities']['verified']
                        Score = Score + 15
                        


                if 'screen_name' in tweet['user'] :
			coop = tweet['user']['screen_name']
			print
			print "This tweet is from ",coop
			print
			if coop in Following:

	                        print "This tweet is from a known user : ",tweet['user']['screen_name']
        	                Score = Score + 15
                	        

			if coop in Friends:
			
				print "This tweet is from a friend : ",tweet['user']['screen_name']
				Score = Score + 15
                                

	if tweet['lang'] == "en" or tweet['lang'] == "fr" or tweet['lang'] == "en-gb":

			if Score > 3:
				print "######################################"
				print "Adding to Retweet List"
				print "Tweet Score : ",Score
				print "Tweet ID :", tweet['id']
				print "######################################"
				print ""

				tweetlist(Score,tweet['id'])
			else:
				print ""
				print "This tweet does not match the requirement needed score to be retweeted. (Score)"
				print ""

			time.sleep(2)
	else:
                                print ""
                                print "This tweet does not match the requirement needed to be retweeted. (Language)"
                                print ""

        time.sleep(2)


	print
	print
	print "================================Scoring function stopped==========================================="
	print
        print "***************************************************************************************************"





def searchTst(word):
	global apicall

        rate = twitter.get_application_rate_limit_status()
        search = rate['resources']['search']['/search/tweets']['remaining']

	if search != ["1"]:

		print
		print "##########################################"
	        print "Starting search function"
		try:
	        	searchresults = twitter.search(q=word, count = 10)
			print "##########################################"
			print "Results found "
			print ""
			apicall = apicall + 1
	
	
	        except :
					print
	                                print "Error Sorry im trying the next one "
					print
	
		try:
			print ""
			print "Je viens de d'envoyer la liste de tweets pour " ,word
			twitter.send_direct_message(user_id="292453904", text="Je viens d'envoyer la liste de tweets pour " + str(word))
			print ""
			print "Done"
			
			apicall = apicall +1
	
			print ""

		except:
                                        print
                                        print "Error Sorry im trying the next one "
                                        print

	
		print "Search function terminated"
		print ""
		print "##########################################"
	
	        for item in searchresults["statuses"]:
	
			Scoring(item)
	else:
                print
                print "****************************************"
                print "****************************************"
                print
                print "API RATE LIMITS ALMOST REACHED "
                print ""
		print "Search call left : ",search
                print "WAITING 15 MINUTES"
                time.sleep(900)
                print "Waking up.."
                print ""

                print
                print "****************************************"
                print "****************************************"
                print


#Some Code

print "Calling Search function"

for key in Keywords:
	searchTst(key)

print
print " Done "
print
print "Now Calling Retweet function"
print

allok = 1

Retweet()
#################################################TheEnd#############################################################
