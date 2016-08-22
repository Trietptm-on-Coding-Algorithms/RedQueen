#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import random
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import os
import datetime
from twython import Twython, TwythonError
from TwitterApiKeys import app_key, app_secret, oauth_token, oauth_token_secret
from operator import itemgetter
from pyfiglet import Figlet

#Some Vars

fuck = 0

waithour = 0

waithalf = 0

moyscore = []

rtsave = ""

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

Keywords = ["debsums","maldet","lynis","rkhunter","clamav","chkrootkit","QuarksPwdump","PwDump","MimiKatz","GsecDump","drive-by download","DROWN PKCS","PKCS","poodle oracle","Beast exploit","logjam","Lucky13","kamkar","rolljam","rfcatwks","yardstickone","hackrf one","CognoSec","SecBee","killerbee python","zigbee","aes-ccm","aes-cbc","aes-ctr","osi model","802.11","802.15.4","BYOIoT","actor-centric","target-centric","Gootkit","Dridex","ooda loop","boucle ooda","pyramid of pain","cryptolocker","master boot record","userland","bootkit petya","dnsmasq","glibc","getaddrinfo","DNS over TCP","domotique","domotic","cryptage nombre premier","prime number crypt","Joorem", "scapy3k", "m00zh33", "asmistruth", "ekeefe3457", "caleb_fenton", "iHeartMalware", "nakincharly", "jduck", "ivspiridonov", "pxlsec", "justinsteven", "ArnaudDlms", "msmakhlouf", "mistamark", "catalyst256", "Flo354", "jaime_parada", "FestChemFaisant", "jetbrains", "boolaz", "mattblaze", "valorcz", "scrscanada", "benoit_ampea", "leroiborgne", "TomRagFR", "guedo", "Mo7sen", "matt_gourd", "pyconfr", "drefanzor", "5683Monkey", "Mina_Vidar", "onabortnik", "AndyDeweirt", "Cryptie_", "pmdscully", "coldshell", "acervoise", "2Dennis", "jamespugjones", "clementoudot", "roidelapluie", "robertfliege", "maartenvhb", "hm1ch", "AndyWilliamsCEO", "woanware", "Info_Assure", "Cryptomeorg", "jjtmlat", "mmu_man", "theglongo", "laure_delisle", "kiirtanrosario", "carelvanrooyen", "MarioAudet", "kalyparker", "hgabignon", "Mekhalleh", "thomassiebert", "brendonfeeley", "netrusion", "alliesuz", "Iglocska", "kittychix", "ErrataRob", "addelindh", "REhints", "USCERT_gov", "JeromeTripia", "akochkov", "sroberts", "__eth0", "DavidJBianco", "CYINT_dude", "swannysec", "fumfel", "switchcert", "GovCERT_CH", "ochsenmeier", "infosecaddict", "s0nk3y", "certbund", "stefj", "Creased_", "ISC2_Las_Vegas", "nullandnull", "h3x2b", "LockyBOT", "ShramanACK", "GrehackConf", "espie_openbsd", "chicagoben", "ringo_ring", "theosint", "paulRchds", "octal", "d_lanm", "ruhrsec", "dSebastien", "SchwaigBag", "ForensicMaggie", "unicorn_engine", "keystone_engine", "jmariocadavid", "brentmdev", "SwiftOnSecurity", "wallofsheep", "vartraghan", "bbaskin", "ddouhine", "jvitard", "AndreGironda", "noetite", "dafthack", "sneakdotberlin", "MISPProject", "freddy1876", "ydklijnsma", "B_Stivalet", "M4ximeOlivier", "DilTown", "jeroenvda", "nguvin", "CertSNCF", "darrellbohatec", "julienmaladrie", "skywodd", "WikiJM", "sneakymonk3y", "cool_breeze26", "antonivanovm", "Conducteur_RER", "LPA_infogerance", "Blueelvis_RoXXX", "cyb3rops", "smaret", "amaelle_g", "cnoanalysis", "ovidiug", "AZobec", "evematringe", "kvandenbrande", "in_threat", "davidbizeul", "benkow_", "py3k", "bountyfactoryio", "ciunderhill", "matthew_d_green", "elibendersky", "g0ul4g", "randal_olson", "slabetoule", "bettercap", "goldshtn", "VXShare", "futex90", "evilsocket", "ZIMPERIUM", "MalwareTechBlog", "X_Cli", "seblw", "KyanKhoFan", "letsencrypt", "yaniv_see", "Palamida_Inc", "geek_king", "FLesueur", "lexoyo", "pwissenlit", "odzhancode", "_g3nuin3", "obilodea", "bambenek", "0xf4b", "tbarabosch", "mgschrenk", "RMLLsec16", "Bugcrowd", "_bobbysmalls", "anoufriev", "Pat_Ventuzelo", "ITSecX", "teoseller", "bradarndt", "cl0udmaker", "herrcore", "cudeso", "lignesNetU_SNCF", "iansus", "mboman", "sqlinjwiki", "gregflanagan22", "tiix_wtf", "metaconflict", "nlavielle", "trailofbits", "KraftCERT", "ClausHoumann", "RobertoQuinones", "Unixity", "unmanarc", "JulienPorschen", "fel1x", "WadeAlcorn", "EricRZimmerman", "L4g4", "maciekkotowicz", "aojald", "AndreasRades", "pidgeyL", "ClsHackBlog", "iseezeroday", "cmatthewbrooks", "mynameisv_", "shenril", "FSecure_IoT", "scotthworth", "YoannFranco", "FredHilbert", "DTCyberSec", "valentijn", "jiboutin", "arangodb", "yprez", "gN3mes1s", "flcarbone", "pello", "julientouche", "joancalvet", "lehtior2", "SchwarzonSec", "docker", "MongoDB", "ElasticNews", "daniel_bilar", "pentest_swissky", "josephzho", "williballenthin", "FabienMarin", "tais9", "1o57", "QubesOS", "Zerodium", "mrjmad", "iSECPartners", "ioCassie", "sylvainbruyere", "PyBaltimore", "jms_dot_py", "rrogier", "robtlee", "volatility", "XTaran", "actudefense", "sleuthkit", "0x4n6", "moong1ider", "hns_platform", "amicaross", "iotcert", "ckyvra", "CORELANSL", "dzogrim", "0xygate", "Canonical", "ubunt", "ubuntucloud", "tsouvignet", "MalwareMustDie", "sdkddk", "sehque", "asdfg232323x", "Master_of_OSINT", "_Stroumph", "lopessecurity", "DebeurePatrice", "FredericJacobs", "Nima_Nikjoo", "thierryzoller", "MarieGMoe", "MS_Ignite", "EC3Europol", "smllmp", "moyix", "ENCS_Julien", "decalage2", "a_de_pasquale", "PhilippePotin", "philippeveys", "EuropeanSeC2015", "Vircom_Inc", "stRiksVindicta", "_GRRegg", "doegox", "XipiterSec", "ikravets", "Paulaumas", "MissMooc", "tacticalmaid", "cloudgravity", "_haplo__", "PyViv", "augouard", "airpair", "UKOSINT", "jusafing", "litalasher", "TestingSaaS", "SiliconArmada", "ILLUMINATEDBE", "ryan_liang", "Python_Agent", "lepicerienum", "cybersecscar", "Linschn", "KaganKongar", "brian_warehime", "Smarttech01", "Kym_Possible", "papygeek", "etiennelb", "pvergain", "cybereason", "MAAWG", "R1tch1e_", "Fast_IR", "StratosphereIPS", "JusticeRage", "stephaneguillon", "Ahugla", "DigiFoRRensics", "ywilien", "4bestsecurity", "Data88Geek", "ptit_pigeon", "DirtNeMeSiA", "yararules", "PatriceAuffret", "KirstyM_SANS", "XavierGorce", "CommitStrip", "HarlinAtWork", "DanbecBeck", "moxie", "hut8uk", "jean_sylvain", "pierre_alonso", "HECFBlog", "CyberWarfaRRe", "pythontrending", "PythonArsenal", "wirehead2501", "theintercept", "loot_myself", "fbOpenSource", "dcuthbert", "0wosk", "sim0nx", "djm6809", "d4rw1nk5", "_JLeonard", "ge0__", "hackingteam", "pix", "ClaireNaudeix", "NuHarbor", "42wim", "NRabrenovic", "SunnyWear", "tuxedo_ha", "nlt56lorient", "OXITS", "hacks4pancakes", "OrientDB", "KayleighB_SANS", "David_RAM0S", "hack3core", "infsec", "citizenlab", "jasonish", "MyTechCommunity", "CorsaireHarlock", "comptoirsec", "SANSEMEA", "monkeylearn", "cecyf_coriin", "spacerog", "jack_daniel", "ihackedwhat", "doar_e", "anthonykasza", "pstirparo", "xorred", "kartoch", "F_kZ_", "Damian_Zelek", "mrozieres", "FirefoxNightly", "enigma0x3", "NCSCgov", "fasm3837", "AbouDjaffar", "Neur0z0ne", "A_H_Carpenter", "bcrypt", "Place_Beauva", "MathildeLBJ", "Charlie_Hebdo_", "skydge", "ceprevost", "s3cdev", "ncrocfer", "gcouprie", "cedoxX", "spamhaus", "omriher", "robbyfux", "_sodaa_", "SecEvangelism", "bestitsource", "Brett_Shavers", "lumisec", "HovikYerevan", "securitybrew", "MarkDiStef", "AndreaBarisani", "triflejs", "Andrew___Morris", "redteamsblog", "Risk_Cambridge", "Bry_Campbell", "sylvander", "marianmerritt", "pkalnai", "ErsatzAusDirect", "kar1nekks", "diodesign", "MaartenVDantzig", "Loria_Nancy", "julloa", "TiNico22", "N1aKan", "HorusSec", "2kdei", "Melusine_2", "bornot_t", "franceortelli", "v1nc3re", "SHG_Nackt", "WebBreacher", "chrisnoisel", "WEareTROOPERS", "dcauquil", "o0tAd0o", "DynResearch", "ZeroNights", "Burp_Suite", "mgualtieri", "Robert4787", "mjbroekman", "Le_Loop", "catchthewhistle", "m_c_scappa", "4n68r", "pymnts", "tryolabs", "yrougy", "NickInfoSec", "FuturistGirl", "GI_Steve", "pr4jwal", "wpawlikowski", "Reversity", "repmovsb", "matthias_kaiser", "patchguard", "Cyber_FR", "AntibotFR", "deresz666", "virtkick", "r00t0vi4", "Dusseul", "dysoco", "randileeharper", "unix_root", "johanneslondon", "BretPh0t0n", "nanderoo", "Maijin212", "cortesi", "slashdevsda", "DavidLWaterson", "ColasV1", "Yen0p", "Newnioux", "lorenzo2472", "presentservices", "piotrkijewski", "TextMining_r", "brodzfr", "adriengnt", "Whitey_chan", "MrsRel1k", "ElcomSoft", "FioraAeterna", "TordueGniale", "AquaZirius", "lezero1", "DhiaLite", "KnockItOff", "alexcpsec", "dhubbard858", "miliekooky", "feedbrain", "mrbarrett", "el_killerdwarf", "bethlogic", "_r04ch_", "Silou_Atien", "Bobetman", "GirlCodeAPage", "jeromesaiz", "selil", "fumeursdepipe", "pipegazette", "accentsoft", "Zekah", "iamevltwin", "sarahjeong", "Joh4nn_", "dckovar", "eldracote", "SecureHunterAM", "OPSWAT", "casinthecloud", "CodeAndSec", "MontagnierP", "ArchC0N", "raffaelmarty", "jocondeparodie", "natashenka", "Suricata_IDS", "rootkovska", "imrim", "aurelsec", "melo_meli", "Pdgbailey", "TheRealSpaf", "Pe_CERT", "HaxoGreen", "KevTheHermit", "nevilleadaniels", "tuxpanik", "kmkz_security", "HackSpark", "d0znpp", "CamilleRoux", "IOCBucketFeed", "FeministPics", "nolimitsec", "ChristopheH00", "OliCass", "konstanta7691", "zenithar", "pevma", "zackhimself", "ReverserRaman", "DavidDoret", "nsmfoo", "lisachwinter", "abnev", "MichalKoczwara", "__ner0", "perefouras", "SandG_", "cases_l", "maradydd", "dguido", "KLNikita", "Voksanaev_OSINT", "SARCWV", "theosintguy", "mompontet", "stachli", "t4rtine", "faittus", "node5", "malware_traffic", "marinivezic", "qb_irma", "r1hamon", "queenwaldorff", "PietroDelsante", "DavisSec", "jwgoerlich", "OpenCryptoAudit", "Daniel_Lerch", "CloudFlare", "LEACSOPHIE", "HuyTDo", "annatroberg", "Cephurs", "noog", "robnavrey", "Mumr1k", "ruchequiditoui", "Secure4Me", "Ekimvontrier", "Game0verFlow", "the_jam", "emd3l", "EdwardTufte", "AlineKav", "maximilianhils", "FraneHa", "Malwared_", "DoctorNoFI", "miguelraulb", "phretor", "JeromeNotin", "NS_Radio", "andreasdotorg", "StamusN", "cherepanov74", "0x0000EBFE", "XI_Research", "mobinja", "bigezy_", "IForkin", "maaax78", "funoverip", "dijoritsec", "raistolo", "__dxx__", "nirouviere", "attrc", "MathildeLemee", "agnes_crepet", "TuxDePoinsisse", "securesearcher", "novirusthanks", "Armelle_b", "FradiFrad", "binitamshah", "MalwareSigs", "neelmehta", "mbedtls", "BSeeing", "SSTIC2014", "SteveGarf", "CERT_UK", "EKwatcher", "gmillard", "bizcom", "levigundert", "gbozic", "SecViews", "_Sec_C", "katsudon45", "MaliciaRogue", "brucedang", "ESET_France", "JanetCSIRT", "cbrocas", "_moloson_", "insitusec", "pvrego", "0xKarimz", "20_cent_", "muller_sec", "LESSYves", "mixIT_lyon", "lazy_daemon", "FliegenEinhorn", "NadAchouiLesage", "dw33z1lP", "gnsivagnanam", "righettod", "northvein", "JershMagersh", "Space_Origin", "kriss_dek", "winSRDF", "Pr1v4t3z0n3", "EMSST_DE", "AbelWike", "_dup_", "Mectoob", "ThinkTankDiff", "Exploratology", "reedox", "xabean", "evj", "CastermanBD", "PierreSec", "satyanadella", "IrisClasson", "fidh_fr", "Sabine_dA", "ktinoulas", "jmichel_p", "CathCervoni", "FreddyGrey", "windyoona", "nkokkoon", "cndint", "sebast_marseill", "broisy", "cci_forensics", "arnaudsoullie", "devpsc", "ZhengOlivier", "pypi", "lefterispan", "twallutis", "ashk4n", "caromonnot", "verovaleros", "dt_secuinfo", "gnulinuxmag", "ShadyK8em0", "Pcap2Bubbles", "jyria", "Seifreed", "marnickv", "carl_chenet", "f1329a", "CharlotteTicot", "soaj1664ashar", "NemanNadia", "cookworkingFR", "capstone_engine", "savon_noir", "StephCaradec", "mc_naves", "ExoticVPS", "Uneheuredepeine", "efFRONTees", "securityfreax", "inliniac", "aseemjakhar", "pinkflawd", "hugo_glez", "Tinolle1955", "SplunkSec", "_SaxX_", "Kujman5000", "tomsmaily", "corkami", "mkevels", "evacide", "VincentCespedes", "Fred_Mazo", "laurenceforaud", "starbuck3000", "aloria", "Y0no", "UNIQPASS", "siedlmar", "sehnaoui", "0x3e3c", "RichardJWood", "Natsakay", "DamDamOfficial", "canariproject", "ShettyShet", "adamkashdan", "johalbrecht", "Vivet_Lili", "j_schwalb", "snipeyhead", "Ptit_Cheminot", "CommanderKarrie", "martelclem", "RevDrProxy", "w3map", "spydurw3b", "ViolaineDomon", "kfalconspb", "Itsuugo", "Venomanceress", "phn1x", "Mar_Lard", "Trojan7Sec", "mark_ed_doe", "gradetwo", "ccomb", "KitPloit", "cryptopathe", "IsChrisW", "CuriositySec", "SilverSky", "esetglobal", "ohm2013", "PirateOrg", "ubuntufr", "kennethdavid", "mvjanus", "lopu61", "Ibrahimous", "viruswiki", "m0m0lepr0", "DarrelRendell", "CyberSheepdog", "Iznogoud1984", "AdrienneCharmet", "poona_t", "quota_atypique", "EFF", "mikesiko", "KAI2HT003", "hurricanelabs", "B1gGaGa", "hackers_conf", "Ludo_z", "rosemaryb_", "23_BU573DD_23_", "DeepInTheCode", "CatatanSiNovel", "osm_be", "adofo", "moutane", "mageia_org", "MalwareAnalyzer", "MaguiMagoo", "13h15", "tixlegeek", "emapasse", "cceresola", "Hectaman", "RCMelick", "Seczoneco", "mastercruzader", "blaster69270", "EthanCrosse", "tr0p0sphere", "d4v3nu11", "jennymangos", "MmeAPT", "jesperjurcenoks", "CryptoPartyFI", "lifegeek_co", "MacForensicsLab", "alex_kun", "hxteam", "kali_linux_fr", "hugofortier", "xeip1ooBiD", "Minipada", "_fwix_", "ak4t0sh", "_batou_", "simonroses", "vulnexsl", "Joel_Havermans", "AlMahdiALHAZRED", "archoad", "cryptomars", "n_arya0", "KrollOntrack_FR", "juanferocha", "pedrolastiko", "nordicsecconf", "teo_teosha", "PyRed7", "posixmeharder", "tdjfr", "2vanssay", "mamie_supernova", "_8B_", "cryptax", "legumx", "FredGOUTH", "Apprenti_Sage", "FlorentCBD", "r00tapple", "_Quack1", "vm666", "Tinolle", "poulpita", "Netzob", "pollux7", "jordangrossemy", "PConchonnet", "s3clud3r", "mvdevnull", "PirateBoxCamp", "HiDivyansh", "Julllef", "quatrashield", "defloxe", "sekoia_fr", "secuip", "hedgehogsec", "FightCensors_fr", "vprly", "andrewallen", "Nipponconnexion", "IMAD_A", "MattNels", "micheloosterhof", "QuanTechResume", "metabrik", "Guillaume_Lopes", "rommelfs", "rshaker2", "agelastic", "openminded_c", "andymccurdy", "rgacogne", "OlivierRaulin", "Berenseke", "_gabfry_", "GaylordIT", "security_sesha", "secnight", "autobotx2", "ThreatSim", "snare", "davymourier", "Navo_", "K3nnyfr", "infomirmo", "eth0__", "psael", "crdflabs", "8VW", "clabourdette", "openleaders", "okamalo", "valerieCG", "ElMoustache", "calhoun_pat", "Mlle_Krikri", "44CON", "aknova", "courrierinter", "Vinssos", "bugwolf", "TAMannerud", "charlesherring", "codeluux", "quinnnorton", "sensepost", "glennzw", "Bulbeuse", "fygrave", "oleavr", "JeroenLambrecht", "etiennebaudin", "machn1k", "nProtect_Online", "Dejan_Kosutic", "mattst0rey", "randiws", "JamieCaitlin", "Kentsson", "Securityartwork", "walter_kemey", "NUMAparis", "itean", "csec", "ViolentPython", "EasilyMisread", "pierrebrunetti", "SiafuTeam", "Korbik", "_Sn0rkY", "_Kitetoa_", "SylviaBreger", "annso_", "homakov", "altolabs", "tomaszmiklas", "ForensicsDaily", "borjalanseros", "jon1012", "DerbyCon", "1nf0s3cpt", "mozsec", "checkfx", "abarutchev", "maldevel", "HackerHalted", "MduqN", "free_man_", "tracid56", "3615RTEL", "srleks", "CarbonBlack_Inc", "placardobalais", "fradasamar", "digital2real", "Art29C", "Skhaen", "bgpranking", "mmangen", "Izura", "Pot2Miel", "varmapano", "instruder", "iefuzzer", "MinhTrietPT", "0F1F0F1F", "demon117", "Wechmanchris", "Cyberarms", "AlexNogard1", "Diaz__Daniel", "MickaelDorigny", "tranche_d_art", "SilentGob", "bl4sty", "d3b4g", "_c_o_n_t_a_c_t_", "T0mFr33", "p3rry_ornito", "piconbier", "HaileyMcK", "florentsegouin", "nicoladiaz", "MobiquantTech", "esthete", "Ched_", "speugniez", "Maxou56800", "mydeliriumz", "thinkofriver", "_RC4_", "malwr", "shutdown76", "loxiran_", "kaiserhelin", "Wagabow", "PhillipDeVille1", "bdnewsnet", "binaryz0ne", "Bitchcraftx", "HackSysTeam", "monachollet", "BenoitMaudet", "dj_tassilo", "0xcd80", "Jl_N_", "AbelRossignol", "r0mda", "Xst3nZ", "martin_leni", "schwartzen", "fluproject", "Glytches", "SecShoggoth", "Botcrawl", "whitehatsec", "b3h3m0th", "kroudo", "armitagehacker", "LauraChappell", "jonoberheide", "mruef", "ESET", "CoderW3x", "mozhacks", "ryandotsmith", "shellf", "RolfRolles", "aaronportnoy", "Myne_us", "dan_kuykendall", "pentesting101", "samykamkar", "hannibals", "0xFFFFFFFE", "OWASP_feed", "gmuReversing", "pedramamini", "veorq", "_MC_", "shmoocon", "Tony_DEVR", "rayet_etawhid", "SeTx_X", "OISFoundation", "1ns0mn1h4ck", "milovisho", "francoisgaspard", "AlineBsr", "kyank", "HackaServer", "ren0_a", "alex_lanstein", "fredmilesi", "DubourgPaul", "getpy", "ruxcon", "Ch1nT4n", "Atchissonnymous", "JosiasAd", "nasserdelyon", "ljo", "Luzark_", "black_pearl01", "beuhsse", "chr1s", "Yaogwai", "james__baud", "SandeepNare", "Mitsukarenai", "debian", "elinormills", "ticxio", "StefSteel", "Horgh_rce", "LucPernet", "OSSIRFrance", "phdays", "hardwareActus", "LaNMaSteR53", "Evild3ad79", "shipcod3", "mrtrick", "TDKPS", "laramies", "kmx2600", "alexgkirk", "secbydefault", "Dkavalanche", "Securonix", "Abzin0", "jvzelst", "zfasel", "truesecbe", "olesovhcom", "CERTXMCO_veille", "fr0gSecurity", "hiddenillusion", "FIC_Obs", "MxTellington", "bindshell_", "securitymoey", "rcsec", "hn9", "MrTrustico", "rattis", "nico248000", "queenmafalda", "0p3nS3c001M", "deesse_k", "_Reza__", "idobiradio", "hesconference", "charles__perez", "ntech10", "rapha_86", "HerrGuichard", "amina_belkhir", "fabien_lorch", "cambronnetwit", "hashcat", "flavia_marzano", "Blackploit", "alisoncroggon", "planet_shane", "tottenkoph", "precisionsec", "exoticliability", "d_olex", "RobInfoSecInst", "und3rtak3r", "iCyberFighter", "Digital4rensics", "X01VVD01X", "__ek0", "qqwwwertyuiop", "C3cilioCP", "Tobias_L_Emden", "ph_V", "fcoene", "YBrisot", "jeffreydoty", "CryptX2", "m0nster847", "rh_ahmed", "x_p0ison_x", "manicode", "alberror", "jacko_twit", "MeutedeLoo", "MathieuAnard", "jlucori", "kalin0x", "sec_reactions", "ifontarensky", "_malcon_", "hectoromhe", "ITrust_France", "tlsn0085", "Botconf", "ArxSys", "sam_et_max", "dariamarx", "melangeinstable", "MasterScrum", "Xoib", "Cyberwarzonecom", "DCLSearch", "binaryreveal", "rbidule", "JeanLoupRichet", "dildog", "jedisct1", "meteorjs", "Unix_XP", "LiddoTRiTRi", "brutelogic", "IamNirajKashyap", "0xU4EA", "Blackmond_", "xavieralabart", "ksaibati", "hanson4john", "schaaaming", "BSSI_Conseil", "blackswanburst", "Zythom", "ackrst", "fede_k", "yochum", "hackademics_", "AntiMalwares", "PierreBienaime", "reverse4you_org", "tfaujour", "awoe", "jmo0__", "JulesPolonetsky", "wseltzer", "csoghoian", "XSSVector", "quentin_ecce", "engelfonseca", "t4L", "diver_dirt", "mbriol", "jsaqqa", "pci0", "Numendil", "coolness76", "osospeed", "WhiteKnight32KS", "ArnoReuser", "Sug4r7", "DefconRussia", "valdesjo77", "penpyt", "0xVK", "whitehorse420", "MalwarePorn", "VTVeteran", "_vin100", "kasimerkan", "MaxTraxBeats", "apauna", "EHackerNews", "MykolaIlin", "talfohrt", "FabriceSimonet", "vkluch", "SeedNuX", "yadlespoir", "BradPote", "RocketMkt", "joselecha", "culleyetc", "securityworld", "gcheron_", "leejacobson_", "ACPerrigaud", "kantinseulement", "set314", "Cryptoki", "glesysab", "MISCRedac", "shocknsl", "n1k0", "UtuhWibowo", "drambaldini", "gleborek", "_goh", "Hi_T_ch", "BradleyK_Baker", "jeremy_richard", "jryan2004", "Robert_Franko", "cyberguerre", "fredack76", "psorbes", "MarioHarjac", "imrudyo", "snake97200", "r1chev", "iHackers", "HamonV", "Di0Sasm", "CharlotteEBetts", "arnaud_fontaine", "Murasakiir", "___Alex____", "fbyme", "SecurityWire", "powertool2", "Y_Z_J", "Fr333k", "subhashdasyam", "heydonovan", "SourceFrenchy", "CabinetB", "Fabiothebest89", "Infosec_skills", "Queseguridad", "DimitriDruelle", "inkystitch", "Olivier_Tetard", "AurelieSweden", "lupotx", "abriancea", "it4sec", "yoogihoo", "Matthi3uTr", "Spartition", "soccermar", "dankar10", "boobmad", "tsl0", "fambaer65", "rootkitcn", "tacticalflex", "msftsecresponse", "GreatDismal", "thedarktangent", "ryanlrussell", "securityerrata", "virustotal", "83147Fadilla", "0x1983", "OtaLock", "suffert", "JohnF_Martin", "drericcole", "linuxacademyCOM", "JoseNFranklin", "cuckoosandbox", "robertthalheim", "ejobbycom", "EskenziFR", "FabienSoyez", "shadd0r", "Plaxo", "_Tr00ps", "helmirais", "spaceolive", "Harry_Etheridge", "neurodeath", "BestITNews", "dr_morton", "Serianox_", "NicolasJaume", "mtanji", "jabberd", "KyrusTech", "bouyguestelecom", "canavaroxum", "MRicP", "jcran", "Milodios", "CompuSecure", "outsourcemag", "Z0vsky", "kaleidoscoflood", "xiarch", "bxsays", "climagic", "CrySySLab", "GJ_Edwards", "RS_oliver", "Laviero", "_rbertin", "rik_ferguson", "reconmtl", "maxime_tz", "TravisCornell", "simpletonbill", "JA25000", "cymbiozrp", "Marruecos_Maroc", "qbihet", "fishnet_sec", "armitagej", "J_simpsonCom", "StevenJustis", "ISSA_France", "kasperskyfrance", "bigz_math", "Peterc_Jones", "schtipoun", "hfloch", "Pianographe", "ElMhaydi", "Cyberprotect", "jrfrydman", "tomchop_", "pmburea", "sans_isc", "Vigdis_", "DigitSecr", "minml5e", "zast57", "Tenkin1", "aahm", "randyLkinyon", "NetSecurityTech", "taviso", "0xcharlie", "SophosLabs", "ssiegl_", "f_caproni", "RobertSchimke", "WalliserQueen", "caiet4n", "Barbayellow", "Taron__", "davfi_france", "calibersecurity", "INTERPOL_Cyber", "spiwit", "casperjs_org", "haguec", "pafsec", "defane", "LongoJP", "JasmyneRoze", "osterbergmedina", "khossen", "TwitSecs", "f4kkir", "action09", "han0tt", "security4all", "SecureTips", "erocarrera", "_WPScan_", "SecurityCourse1", "_nmrdn", "sdxcentral", "DI_Forensics", "vap0rx", "ZeBeZeBa", "lilojulien", "ouroboros75", "schippe", "fabien_duchene", "ielmatani", "onialex64", "eero", "ScreamingByte", "prasecure991", "jpgaulier", "CrowdStrike", "flgy", "EtienneReith", "laith_satari", "deados", "vfulco", "waleedassar", "aanval", "4and6", "negotrucky", "freesherpa", "moohtwo", "initbrain", "rodrigobarreir", "Malwarebytes", "maschinetreiber", "Puckel_", "jennjgil", "AndrivetSeb", "zuko_uno", "andersonmvd", "okhin", "Eeleco", "CNIL", "elvanderb", "_plo_", "FastFig", "hackerbus", "56_fj", "Xartrick", "exploitid", "v0ld4m0rt", "tgouverneur", "DebStuben", "RonGula", "thotcon", "G4N4P4T1", "Yxyon", "_bratik", "Majin_Boo", "vhutsebaut", "stephane1point0", "Urkraftv", "_Debaser_", "ximepa_", "irixbox", "coolx28", "Korsakoff1", "Regiteric", "botherder", "Hakin9", "Herdir", "fbardea", "oduquesne", "thecyberseb", "krzywix", "thezdi", "glasg0ed", "Nomade91", "clabman", "just_dou_it", "cizmarl", "brix666Canadian", "_Egwene_", "fAiLrImSiOnN", "l0phty", "thomasfld", "PavelDFIR", "virustotalnews", "leonquiroga", "phanubhai", "Aryaa__", "EightPaff", "N_oRmE", "barbchh", "mcherifi", "NWsecure", "crowley_eoin", "k8em0", "sysdream", "ElChinzo", "k_sec", "ikoniaris", "MarkMcRSA", "rattle1337", "a804046a", "botnets_fr", "garfieldtux", "Cubox_", "MaKyOtOx", "AccelOps", "dummys1337", "w4kf", "toastyguy", "kongo_86", "Fly1ngwolf", "malwarel", "TigzyRK", "syed_khaled", "jhadjadj", "Patchidem", "crazyws", "tlk___", "malekal_morte", "silentjiro", "Erebuss", "fzcorp", "LucianoHuck", "FireEye", "PwnieAwards", "secureideas", "MarcusSachs", "cactiix", "bannedit0", "crypt0ad", "taosecurity", "aNaoy", "KelvinLomboy", "geekjr", "SANSPenTest", "kapitanluffy", "_rootcon_", "ProjectxInfosec", "ryanaraine", "SeraphimsPhoto", "lspitzner", "noktec", "NoraGaspard", "MsMaggieMayhem", "Tishrom", "FaudraitSavoir", "sravea", "bricolobob", "Mandiant", "DarkReading", "securityninja", "_saadk", "calebbarlow", "philpraxis", "spamzi", "MehdiElectron", "Tif0x", "TMSteveChen", "quantm1366", "NeeKoP", "nyusu_fr", "ph0b", "_argp", "SharpeSecurity", "offsectraining", "thegrugq", "seanhn", "marciahofmann", "ihackbanme", "pirhoo", "collinrm", "DFIRob", "felixaime", "cBekrar", "StevenVanAcker", "vierito5", "saracaul", "NTarakanov", "S1D_", "sabineblanc", "Amelicm", "Vie_de_Metro", "emi_castro", "SigBister", "laura_anne182", "markloisea", "ubersec", "Hugotoutseul", "k3rn3linux", "harunaydnlogl", "SpiderLabs", "lhausermann", "vltor338", "WorldWatchWeb", "jamesejr7", "kafeine", "rmogull", "razaina", "Koios53b", "MinuteSexe", "w3af", "ateixei", "AlliaCERT", "JalelTounsi", "Medsiha", "JonathanSalwan", "mubix", "kylemaxwell", "sagemath", "tbmdow", "SamTeffa", "lukeburnett", "veeeeep", "agonzaca", "travisgoodspeed", "markrussinovich", "cesarcer", "_sinn3r", "dalerapp", "Ylujion", "Lapeluche", "eveherna", "OrLiraz", "qgrosperrin", "udgover", "MonaZegai", "adesnos", "window", "gcaesar", "UrSecFailed", "kutioo", "malwarediaries", "n0secure", "obs_media_num", "Steve___Wood", "emgent", "HackingUpdate", "iDefense", "wopot", "nullcon", "sibiace_project", "aramosf", "cyberwar", "sandrogauci", "silviocesare", "HostExploit", "Dreamk36", "33022", "amarjitinfo", "owasp", "th3j35t3r", "fromlidje", "rybolov", "kerouanton", "Nathanael_Mtd", "gallypette", "CipherLaw", "CrimsonKaamos", "The_Silenced", "JGoumet", "BlantonBache", "threatintel", "hackinparis", "never_crack", "0xerror", "sioban44", "josoudsen", "SensiGuard", "hustlelabs", "hackerzvoice", "jollyroger1337", "geocoulouvrat", "PastebinLeaks", "p4r4n0id_il", "anton_chuvakin", "sysnetpro", "nigroeneveld", "MoonSols", "cryptoron", "hackinthebox", "l33tdawg", "HITBSecConf", "kriptus_com", "pbeyssac", "Paterva", "SmartInfoSec", "HackingDojo", "CERTFI", "Bertr4nd", "leducentete", "aanetgeek", "infosecmafia", "Javiover", "reboot_film", "pryerIR", "DeepEndResearch", "aris_ada", "savagejen", "Doethwal", "0xde1", "agent0x0", "btabaka", "justinbiebiere", "i_m_ca", "Hexacorn", "JeromeSoyer", "wallixcom", "secuobsrevuefr", "vanovb", "POuranos", "l_ballarin", "lestutosdenico", "nicklasto", "Ballajack", "mks10110", "afrocyberpunk", "quarkslab", "balabit", "wireheadlance", "C_Obs", "k3170Makan", "siddhi_salunke", "E_0_F", "T1B0", "stelauconseil", "Lady_Kazya", "siri_urz", "M86Labs", "Onthar", "mbenlakhoua", "jeremiahg", "hdmoore", "iunary", "dvdhein", "braor", "sunblate", "SeguridadMartin", "CQCloud", "bri4nmitchell", "vietwow", "Dinosn", "isvoc", "eLearnSecurity", "DarkCoderSc", "SwiftwayNet", "nathimog", "gertrewd", "alexandriavjrom", "moneyfreeparty", "ntdebugging", "OWNI", "CERT_Polska_en", "commonexploits", "Chongelong", "Asher_Wolf", "s0tet", "Psykotixx", "Karion_", "sinbadsale", "nowwz", "yodresh", "BlackyNay", "0xBADB", "yeec_online", "paco_", "Parasoft", "pretorienx", "TrC_Coder", "creativeoNet", "0x6D6172696F", "SecurityXploded", "Fou1nard", "7h3rAm", "ChanoyuComptoir", "ioerror", "avivra", "Stonesoft_FR", "manhack", "mwrinfosecurity", "caltar", "asintsov", "corbierio", "Panda_Security", "benhawkes", "chrisrohlf", "ethicalhack3r", "tkolsto", "firejoke", "R1secure", "Urbanplaytime", "indi303", "c_APT_ure", "CodeCurmudgeon", "DavidGueluy", "unohope", "aspina", "DanGarrett97", "EnergySec", "H_Miser", "arbornetworks", "eromang", "telecomix", "ForensicDocExam", "gl707", "agevaudan", "YungaPalatino", "D3l3t3m3", "shafigullin", "Jhaddix", "baYannis", "camenal", "AskDavidChalk", "cthashimoto", "enatheme", "zandor13", "loosewire", "artem_i_baranov", "jvanegue", "nudehaberdasher", "aaSSfxxx", "Actualeet", "dUAN78", "Asmaidovna", "rmkml", "JobProd_DOTNET", "4n6s_mc", "Tris_Acatrinei", "Geeko_forensic", "AlanOnSecurity", "t_toyota", "ericfreyss", "aboutsecurity", "barryirwin", "no_name_here", "Safer_Online", "o0_lolwut_0o", "meikk", "coryaltheide", "paulfroberts", "patrickmcdowell", "RCELabs", "sergiohernando", "JC_DrZoS", "chiehwenyang", "snfernandez", "dakami", "DudleySec", "EddyWillems", "SANSInstitute", "buffer_x90", "internot_", "AmazinQuote", "nikemax2007", "swept", "halilozturkci", "badibouzi", "SafeNetFR", "treyka", "Ivan_Portilla", "megatr0nz", "slvrkl", "bortzmeyer", "binsleuth", "zed_0xff", "fluxfingers", "BEESECURE", "circl_l", "certbe", "defcon", "brucon", "syn2cat", "Metlstorm", "tryks_", "AusCERT", "lreerl", "sud0man", "kyprizel", "kabel", "Jipe_", "PhysicalDrive0", "HoffmannMich", "jaysonstreet", "g4l4drim", "j0emccray", "fuuproject", "htbridge", "ebordac", "zesquale", "KalkulatorsPro", "dragosr", "Holistic_Steph", "legna29A", "ESETResearch", "_calcman_", "aristote", "DrewHintz", "Yayer", "C134nSw33p", "thgkr", "Hydraze", "y0m", "Heurs", "honeymole", "andreglenzer", "TechBrunchFR", "epelboin", "rafi0t", "PagedeGeek", "stackOver80", "Creativosred", "routardz", "ITVulnerability", "Hat_Hacker", "CyberwarForum", "kalptarunet", "Redscan_Ltd", "BerSecLand", "cabusar", "infiltrandome", "ccc", "biosshadow", "r0bertmart1nez", "yanisto", "k_sOSe", "TheCyberLawyer", "DCITA", "apektas", "Viss", "twatter__", "EmergingThreats", "ochsff", "9bplus", "Thaolia", "raganello", "evebugs", "eastdakota", "stacybre", "Shiftreduce", "BitdefenderFR", "domisite", "CaMs2207", "IKARUSANTIVIRUS", "StrategicSec", "Jagdale63", "mrdaimo", "opexxx", "marcusjcarey", "esignoretti", "leonward", "Sourcefire", "binarydom", "timecoderz", "Phonoelit", "_snagg", "Sharp_Design", "s_kunk", "gon_aa", "mrkoot", "FSEMEA", "saleh__alsanad", "S21secSecurity", "SugeKnight4", "danhaagman", "sl4ke", "openSUSE", "debiansecurity", "debianfr", "AlanPhillips7", "7safe", "_CLX", "DrM_fr", "Securelist", "csananes", "yenos", "Agarri_FR", "tactika", "Nelson_Thornes", "chri6_", "MarcoFigueroa", "UnderNews_fr", "edasfr", "selectrealsec", "chr1x", "voyagesbooster", "follc", "rackta", "Jaxov", "isguyra", "AFromVancouver", "w4rl0ck_d0wn", "infosecmedia", "steevebarbea", "Zap0tek", "NESCOtweet", "niCRO", "nono2357", "Emeaudroide", "fredraynal", "corelanc0d3r", "xanda", "mov_ebp_esp", "binnie", "theAlfred", "Securitycadets", "patrikrunald", "snowfl0w", "GadixCRK", "kahusecurity", "reversemode", "hackinfo", "t0ka7a", "switchingtoguns", "zecurion", "NKCSS", "Yahir_Ponce", "eag1e5", "ghdezp", "komrod", "Paul_da_Silva", "torproject", "abuse_ch", "alchemist16", "ibou9", "azerty728", "Baptiste_Lorber", "Yann2192", "RichardDOwens", "2gg", "MAn0kS", "rssil", "f4m0usb34u7y", "PR4GM4", "TyphoidMarty", "picikeen", "thE_iNviNciblE0", "kenneth_aa", "HacKanCuBa", "teamcymr", "neox_fx", "openhackday", "thesmallbrother", "MFMokbel", "jeromesegura", "WawaSeb", "trolldbois", "curqq", "danphilpott", "ProjectHoneynet", "KDPryor", "extraexploit", "mortensl", "UNICRI", "cowreth", "macteca", "HackerTheDude", "cedricpernet", "stefant", "issuemakerslab", "cillianhogan", "carlLsecurity", "SecuObs", "googijh", "haroonmeer", "dum0k", "virusbtn", "gcluley", "StopMalvertisin", "sbrabez", "VirusExperts", "deobfuscated", "pentestmexico", "mrbellek", "fpaget", "richinseattle", "0xjudd", "gamamb", "smoothimpact", "zsecunix", "FredLB", "andremoul", "TeamSHATTER", "milkmix_", "IOActive", "Xylit0l", "chetwisniewski", "angealbertini", "marco_preuss", "Fyyre", "dyngnosis", "SecurityIsSexy", "defendtheworld", "Satyendrat", "knowckers", "sabina_datc", "TaPiOn", "in_reverse", "ChadChoron", "dshaw_", "vanjasvajcer", "malphx", "EskimoNerd", "ncaproni", "7rl", "cthevenet", "sphackr", "unk0unk0", "hEx63", "sempersecurus", "inuk_x", "GotoHack", "justinlundy_", "kenjisam", "borrett", "__emil", "shu_tom", "Y0Z4M", "bartblaze", "danielvx", "BlackHatEvents", "DustySTS", "ZtoKER", "netrap", "zmworm", "goretsky", "tametty", "0x58", "jbfavre", "recriando", "revskills", "cbriguet", "munmap", "irciverson", "professor__x", "JPBICHARD", "amaximciuc", "hss4337", "dphrag", "seanxcore", "group51", "fschifilliti", "bik3te", "rajats", "_Blade81", "deroko_", "asc3tic", "__x86", "jasc22", "MarioVilas", "SSL_Europa", "xorlgr", "philmuncaster", "OracleSecurity", "HTCIA", "SecMash", "arnaud_thurudev", "lcheylus", "ccg", "jfug", "ghostie_", "TheUglyStranger", "Shinegrl", "hXffm", "TheNexusDI", "Kizerv", "bojanz", "rebelk0de", "iMHLv2", "insecurebyte", "kakroo", "WasatchIT", "Ange1oC", "GiveUThePinger", "airaudj", "kjswick", "Ideas4WEB", "TwisterAV", "TheHackerFiles", "neosysforensics", "fbinc355", "kasperskyuk", "diocyde", "EncryptStick", "b1nary0", "RomainMonatte", "SalesNovice", "radware", "SUPER_Security", "Nattl", "missuniverse110", "perdrum", "coresecblog", "steaIth", "mikko", "infosecbulletin", "J4ckP4rd", "__Obzy__", "CERT_mx", "alexlevinson", "CyberAdvisorsMN", "I_Fagan", "mike_fabrico", "dannysla", "virusstopper", "ChristiaanBeek", "toucansystem", "alvarado69", "adula", "Denis_Akkavim", "hardik05", "305Vic", "itech_summit", "mollysmithjj", "keysec", "nmatte90", "_x13", "binit92", "sebastiendamaye", "ITRCSD", "TheDataBreach", "ntsec2015", "PascalBrulez", "JokFP", "x0rz", "threatpost", "PiotrBania", "ozamt", "41414141", "msuiche", "forensikblog", "fjserna", "mdowd", "milw0rm", "str0ke", "metasploit", "i0n1c", "antic0de", "gattaca", "CyberSploit", "hack_l", "XSSniper", "Sysinternals", "DumpAnalysis", "zentaknet", "DidierStevens", "egyp7", "malwaredb", "ubuntusecurity", "isaudit", "bsdaemon", "milojh", "Myst3rie", "0security", "Sorcier_FXK", "nicolasbrulez", "MatToufout", "virtualabs", "CertSG", "esizkur", "dysternis", "paradoxengine", "filipebalestra", "h2hconference", "berendjanwever", "0vercl0k", "matrosov", "sirdarckcat", "edskoudis", "pentestit", "securityshell", "rapid7", "r00tbsd", "g0tmi1k", "int_0x80", "newroot", "dt0r", "0xroot", "alienvault", "cyphunk", "fail0verflow", "qualys", "ModSecurity", "fo0_", "Veracode", "McAfee_Labs", "XSSExploits", "beefproject", "deepsec", "vthreat", "voidspace", "secviz", "googlehacking", "Openwall", "j00r", "2xyo", "analyzev", "hernano", "windsheep_", "ptracesecurity", "infernosec", "anthonymckay", "virtualite", "_decius_", "aircrackng", "jz__", "DeviantZero", "Darkstack", "aramh", "dynsec", "hackerschoice", "packet_storm", "csima", "nickharbour", "digistam", "fmarmond", "Ixia_ATI", "EncryptedBeader", "monstream00", "Hacksawz20", "jcanto", "biopunk", "ZenkSecurity", "inj3ct0r", "wifihack", "toolcrypt", "lexsi", "aszy", "CyberCrime101", "sstic", "VerSprite", "y0ug", "80211EL", "gollmann", "holesec", "ispadawan", "mortman", "agololobov", "Raaka_elgupo", "selenakyle", "Immunityinc", "SecMailLists", "Reversing4", "wimremes", "headhntr", "codeengn", "xkcdrss", "fbz", "mmurray", "IPv4Countdown", "davesan", "etcpasswd", "paulsbohm", "iagox86", "PainSecurity", "AcroMace", "haxorthematrix", "rfidiot", "rootlabs", "FluxReiners", "dsancho66", "drehca", "StephanChenette", "TiffanyRad", "thomas_wilhelm", "ChrisJohnRiley", "3ricj", "KristinPaget", "_MDL_", "SecBarbie", "halsten", "bluetouff", "n0fate", "Hfuhs", "HackBBS", "greyunderscore", "mwrlabs", "ThreatHunting", "stacythayer", "Carlos_Perez", "mj0011_sec", "kees_cook", "kyawzinko", "malwaregroup", "TomRittervg", "opcode0x90", "jorgemieres", "OpenMalware", "shingara", "manu2342", "commodon", "lonervamp", "cwroblew", "marklucovsky", "ZeroDayLab", "verbosemode", "malc0de", "DavidBruant", "Jolly", "jaybeale", "SteveClement", "singe", "eQuiNoX__", "JohnnyLong", "skipp", "vnsec", "sudeeppatil", "stackghost", "Neitsa", "sirjaz", "iseclab", "AdobeSecurity", "TinKode", "ekse0x", "evdokimovds", "peterkruse", "foxgrrl", "vessial", "leonyson", "Kleissner", "Nullthreat", "hackerfantastic", "EnRUPT", "WIRED", "al3x", "ShellGhostCode", "Eicar", "pod2g", "yelsink", "shakacon", "hackerkaraoke", "carnal0wnage", "sansforensics", "xme", "Pentesting", "SecurityTube", "stfn42", "g30rg3_x", "SPoint", "vloquet", "CERTXMCO", "exploitsearch", "qobaiashi", "ak1010", "sanguinarius_Bt", "ponez", "uglypackets", "dnoiz1", "xRuFI0x", "the_s41nt", "kernelpool", "TheHackersNews", "unpacker", "THEdarknet", "angelinaward", "crai", "endrazine", "ESETNA", "agent_23_", "Aarklendoia", "NoSuchCon", "shydemeanor", "joernchen", "astera", "angelodellaera", "tricaud", "stalkr_", "MarketaIrglova", "Glen_Hansard", "TheSwellSeason", "kriggins", "villys777", "briankrebs", "ortegaalfredo", "kpyke", "TalosSecurity", "p0bailey", "msksecurity", "VUPEN", "PremiereFR", "DOFUSfr", "ActuSF", "OhItsIan", "ma_r_ie", "wecho", "Fluorette", "Maitre_Eolas", "NonAuxHausses", "NosVillesUrba", "smaciani", "newsoft", "emiliengirault", "abionic", "luizdiastwit", "PureFMRadio", "ValeryBonnea", "_protoculture", "nmap", "LP_LaPresse", "sylv1_sec", "grebert", "fdebailleul", "antirootkit", "ionomusic", "nicolaslegland", "manga_news", "wikileaks", "vlaavlaa", "OneLouderApps", "GouZ", "attackvector", "madgraph_ch", "kalilinux", "exploitdb", "Archlance", "KazeFrance", "NicolasThomas", "Hainatoa", "QuentinLafon", "GreatSongnet", "KredMarketing", "Ivanlef0", "_cuttygirl", "KuroTweet", "asi_all", "spyworld_act", "HootsuiteMobile", "reseau_unamipro", "widgetbooster", "lareponsed", "CooperHenry", "mushroommag", "geekact", "MarianneleMag", "seb_godard", "kavekadmfr", "ahmedfatmi", "geekbooster", "gitedemontagne", "capucine11", "rizzrcom", "Stefko001", "webpositif", "grevedutgv", "LucBernouin", "bakabeyond", "MangasTv", "parapigeon", "quoimaligne", "FGRibrea", "twittconsultant", "marinemarchande", "sebastiensimon", "SweatBabySweat_", "Twitchaiev", "hynzowebblog", "greg32885", "Evangenieur", "AirFranceFR", "tweeterp4n", "boloms", "exploracoeurexp", "moderateur", "crouzet", "Capucine_Cousin", "egadenne", "jlgodard", "DelcourtTonkam", "oli2be", "iSebastien", "digsby", "ovaxio", "lapunaise", "xhark", "blackwarrior", "MathieuBruc", "populationdata", "Garnier08", "cafesfrance", "sirchamallow1", "naro", "Technidog", "Summy46", "gamesandgeeks", "Korben", "Mariegaraud", "eogez", "jpelie", "mthldv", "DavidAbiker", "philippe_lagane", "ju_lie", "sirchamallow", "cberhault", "ouifm", "stagueve", "Romain", "julierobert", "ChrisLefevre", "SimonRobic", "pressecitron", "Zebrure", "AwdioI", "Inzecity", "ga3lle", "Veronica", "LePost", "google", "vitujc", "littlethom23", "EstherBrumme", "Awdio", "DJKweezes","kimberleykerza", "SGdrakop", "0xj3r3my", "Joorem", "SmileBzh", "davinciforensic", "slambynews", "ACKSYNjACKSYN", "MatthiasEckhart", "getInfoSec", "m00zh33", "wizkidnc", "asmistruth", "Achilli3st", "ccbethompson", "mobiussys", "fear_index", "sairammuraly", "ediot2", "AldebranKft", "JeffProd", "ObjectRocket", "TimBenedet", "nakincharly", "Alex_Stormrage", "NetScaler", "security_feeds", "unsignedjuice", "rikterskale", "CodeMorse5", "mistamark", "AFI_Sydney", "apokrif1", "DFIRtraining", "jaime_parada", "criznash", "fran62130", "usrAnonymous", "staybeyond_rckz", "rezor59", "Serenoxis", "jorge_princee", "Master_0098", "DemetrioMilea", "AlM4hdiALHAZRED", "IshanGirdhar", "GIP_GENOPOLE_IT", "WeAreAPT69", "iamlus3r", "iamWLFX", "Polyconseiltech", "magiknono", "valorcz", "SethHanford", "JeremyGibb", "LaServietSky", "CharlieVedaa", "InYoFaceWithMe", "ween7", "kevinott38", "KMagajne", "pejacquier", "SciaticNerd", "Harwood_Tom", "InfoSecurityTop", "_gau_rav", "KibanaTopNews", "_SWEXXX_", "benoit_ampea", "leroiborgne", "guedo", "TomRagFR", "matt_gourd", "jmaguayosanchez", "ht_adrian", "Adrien_Thua", "drefanzor", "javib51", "thierrybxl", "gweltaz_K", "eightzerobits", "c0rtezhill", "onabortnik", "AndyDeweirt", "Cryptie_", "philophobia78", "pmdscully", "p1d630n", "SalonEuronaval", "coffjack", "erusted", "2Dennis", "GithubTopNews", "EdPiette", "roidelapluie", "OSINTSolutions", "clementoudot", "0xrb", "NaykiSec", "terredelamattre", "roadwander", "InfoSecRick", "eugeneteo", "White_Kernel", "monkeylearn", "hoangcuongflp", "Jokar898", "nelson_40net", "maartenvhb", "glesysab", "davidsonjrg", "f_kifli", "peta909", "virusbtn", "RobMarmo", "TayVip", "AndyWilliamsCEO", "Antr4ck", "hm1ch", "_Gof_", "Twat181", "ClPython", "tanguya", "c0rehe110", "the_moorbs", "fybugail", "useris20x", "HelloCreme", "1RicardoTavares", "sl4ke", "mlorcy56", "0xshellcode", "pecb_e", "TechVidRoulette", "LowellLedin", "HuaweiTopNews", "XCtzn", "dunaxiwezili", "SB03165440", "RobertStrugger", "jmarklove", "Fil573", "RakeshM16071987", "gb_master", "theglongo", "BeaCantwell", "neu5ron", "lud0bar", "hehafatasep", "hj751", "louisdurufle", "j15allroad", "carelvanrooyen", "dagon202", "diruscon", "mike_lee777", "MarioAudet", "kalyparker", "hgabignon", "had3s_security", "had3s_security", "sosa9722", "Two_CV", "CODEX_NUL", "FournierRico", "somar404", "yassine_lemmo", "_0x1c0x13_", "brendonfeeley", "Iglocska", "Sach7009", "sourceforit_1", "holoxanohuky", "Intralapino", "FloSwiip", "hoip", "Rinaldi3Ste", "khungbo33", "beberlacrapule", "rezor5958", "gnooline", "evematringe", "ThreatMetrix", "JeremyDumez", "emojieface", "exp_data", "JeromeTripia", "ccsplit", "blobbels", "codemonkeysam", "alangeneva", "neilbulala", "fumfel", "swannysec", "cipherthink", "cestunnombidon", "nolaforensix", "s0nk3y", "DigitalMktgMvn", "ReTweetSecNews", "AliAndani", "6_1zM0", "Otis_oO", "michaeljuergens", "fengfeifirst", "RealtyConcepts2", "stefj", "MyInfo91851314", "Creased_", "ISC2_Las_Vegas", "eshardNews", "raelalaoui", "wiref4lcon", "talentwang", "MrSeal_", "drfreezev2", "kalikatech", "icanhaspii", "allmovie_yt", "malik_almeus", "micespargiliere", "__ITI__", "remy2310", "h3x2b", "stevelord", "satreix", "_Paulo_", "Siriu5B", "house_of_peen", "ShramanACK", "processgeek", "skouax", "pwn4bacon", "sudcode83", "BilbonMickael1", "OfficialMdub", "GrehackConf", "WhiteRabbit_sh", "tenacioustek", "chicagoben", "hackthepanda", "joseison", "Ac0uSeC", "PmaMgp", "manwefm", "d_lanm", "arturferreira", "moleeye81", "Rolland79Sylvie", "ForensicMaggie", "SchwaigBag", "dSebastien", "D_Veug", "mrmrinthemix", "rahul292009", "Eagainn", "brentmdev", "anatolye", "gregjnimmo", "romalegr", "AdacisNews", "threat_wizard", "_JulioGG", "dkrasa", "webexpert851", "b1gtang", "Bolyons29", "evanwagner", "Simon_Kenin", "BlueCollarCyber", "lynchan79", "EXPERT_SI", "SuRi_CSGO", "StopRacismDotCa", "kalebcrusos1998", "kc1redor", "DorisJenkinse", "ddouhine", "bambylamalice", "psavezx", "daves_espia", "A2iFeignies", "Xaaly_MX", "TharunSYadla", "lild4d", "xECK29x", "CyberSecuFR", "hackermill", "B4rC0", "aboutcambodiatr", "sonnybrunson", "ItsMedaBen", "brinhosa", "ax0us", "CDSMarine", "atfeliz", "NeonPint", "Flechemortelle", "fnkym0nky", "shakethemalware", "krausedw", "Y4nn1x", "Mixedmedia", "JulienLhe", "Fabi_Behling", "Spraid_Tech", "JacobDjWilson", "denvercyber", "AndreGironda", "kwartik", "tajveudiroukoi", "mansano_bruno", "da5ch0", "AdAstra247", "MSFT_Business", "Ntech63", "noetite", "nveys", "mahendrat", "fengjixuchui123", "JeanBernardYATA", "jeromesegura", "dafthack", "sneakdotberlin", "MhmtYY", "what000if", "ater49", "ironmano1", "CryptoWeb_fr", "DBAppUS", "RhinoSecurity", "eric_capuano", "Ptrck91", "Dehgaldino", "bricotux", "ypottany", "z0rk13", "mendel129", "freddy1876", "infoinvest20", "Julien_Bernard", "elearnindustry", "lukemks", "MacD750", "PITCHYH", "lucasoft_co_uk", "David_0xEB", "MrSundance1", "Cyber_Stevalys", "TheHitchhik3r", "DFIRMonk", "ricardoteixas", "ContactNystek", "rfayol", "sknuutin", "SecurityMagnate", "rcvinjanampati", "dem4ster", "B_Stivalet", "DigitalAntonius", "MozDevNet", "t3b0g025", "vilarojasjose", "BSidesZurich", "pejupej", "my_name_is_fer", "001sec", "kpr", "achrefezzahroun", "MFPHPodcast", "SuzeanneSpeir", "p00pw", "genma", "holmium8", "vvh1t3Cr0w", "IP_x_0n", "orwelllabs", "dainless", "KevinCardinali", "asfakian", "BK_Info_sec", "MaliciaRogue", "n_idir", "ElBritishZP", "DilTown", "M4ximeOlivier", "Requiem_fr", "Zilux", "DelabarreLuis", "jeroenvda", "newsoft", "jfbaillette", "Cyber_IR_UK", "Hil18de", "Brett_Shavers", "_evilMalwr", "st123ss", "GregTampa", "yodoesp", "testjampes", "s3scand0r", "hakim_sd", "moritan", "mickbmt", "lagomm", "VPinsembert", "chiagarad", "SocialPlanneur", "TheAlecJustice", "FinancialCrypto", "c_williams321", "steffenbauch", "YvesRosaire", "pirytuni", "darrellbohatec", "marc_cizeron", "SogetiHighTech1", "davidkoepi", "malwarescare", "edaboud", "Luno", "mal9i", "garyhak2009", "OracleDBTopNews", "ashraful_rajon4", "GTBen59", "ralphymoto", "AnarchistDalek", "Squidblacklist", "defsecnsattack", "dudeslce", "BoisselFrederic", "sgelisli", "espie_openbsd", "AliSniffer", "SSHROCKS", "Emeline_Martine", "Chacal73768683", "cyresity", "sneakymonk3y", "TheFireGhost", "soslicknick96", "azamhassan91", "digtlulz", "s3c_info", "cool_breeze26", "NahsiY", "pishumahtani", "ChargeParity", "michaeldacosta", "sp33dfreak_", "Jacques_Guittet", "LPA_infogerance", "Blueelvis_RoXXX", "BullShit21568", "LincolnKberger", "0slazy", "nsmfoo", "mangtahir79", "__s_yo", "secanalyste", "Yggdr4sill", "diallomed", "smaret", "M_Shafeeq_", "vartraghan", "Raphzer", "kimtibo", "WikiJM", "8luewaffle", "taziden", "decalage2", "amaelle_g", "ad_minwiki", "cnoanalysis", "davide_paltri", "p4r4d0x86", "jv16PowerTools", "GDataFrance", "AlxPrx", "den_n1s", "digitaltwisters", "LazyConsultant", "lucmbele", "MKlein_Dev", "Juanx02Jp532786", "MichaelJohn_DE", "mrjvsec", "brunofusaro", "dctrjns", "EnoCarlos", "TurboSecurity", "ovidiug", "DevSec_", "MarshellMelo", "pramaniksudipta", "TatyanaHaid", "DEGORCE10", "chaima27898388", "lehollandaisv", "tamzac", "bolomacosmoura", "kmonticolo", "KJanton", "GuilhemSAVEL", "sn0wm4k3r", "sourcecode1esme", "SpoonB0y", "NicolasWolf", "SFPwN", "SilkySmoOth___", "QuentinBrusa", "slim404", "Metalliqueuse", "YannRoques", "Li06ly", "skswati", "Tanium", "kosogistan", "gael_oyono", "cl0udmaker", "IESommet", "BenoitJeannet", "letexploitfly", "ba0216", "kl0x41dgs", "BugBountyZone", "consultortesis1", "Alexplzstandup", "Cybermarius1", "ciunderhill", "lubian_29", "csabaharmath", "abosalahps", "frhak", "randal_olson", "twp_zero", "slabetoule", "NRhasovic", "chaign_c", "bettercap", "omer2008", "InProvadys", "No0b_lol_lol", "llazzaro", "_datadesire_", "MacR0bins", "_bl4de", "grufbot", "jbillochon", "kafeimai", "d3vil7", "DaCloudVPN", "ghdezp", "JeromeGranger", "w0mbt", "_k3nj", "pr9try", "KesselSec", "didonadezuk", "sevenyears3", "WenheX", "samiallani", "SimonBuq", "RegnierJeremy", "seblw", "secelements", "J7Pepper", "juckly06", "tbillaut", "magicianc57", "Yannayli", "SecurityIT_Nick", "MalwrNinja", "aprimotore", "lipeandarair", "jusk217", "SerenityFluff", "rodneyrojas8", "jtrombley90", "CannaUE", "EtudesGamma", "HierundieWeber", "Nekyz_", "rpsanch", "XSpyderSC", "Prasadsofficial", "diorjad0re", "lec668", "5borographics", "volkovin", "cyberkryption", "KimMayans", "jackchou51706", "jgrmnprz", "jdreano", "yaniv_see", "ct_expo", "alice_smith_tes", "0net0all", "kakakacool", "AsymTimeTweeter", "Dylan_TROLES", "ccfis", "Aguilo_Network", "r_dacted", "Hani_Khasawneh", "Palamida_Inc", "geek_king", "Ubikuity", "FLesueur", "thetechhouseuk", "obilodea", "ocument", "pwissenlit", "odzhancode", "BF00d", "_g3nuin3", "MlckhA", "bambenek", "0xf4b", "sureshbangra26", "KRAJECKI3", "ni9ter", "Forensicbox", "kolinstw", "tbarabosch", "rajats", "infolec1", "skaveo_sys", "sigalpes", "CDNetworks_Euro", "0o_An0n_o0", "luxtrust", "patlaforge", "bvalentincom", "ClusirNdf", "crypto36", "enxi0", "Sev6rapian", "lea_linux", "polo46", "niarkme", "BrunoVasta", "robinlaude", "ITNOG2", "KanorUb", "neimad75", "Gros_Fail", "_st0m_", "YoussefHTTPCS", "shaunwheelhouse", "_scarscarscar_", "BreizhGab", "kernullist", "LG_CTIG", "xavier_pernot", "RandomAdversary", "katniss1982back", "plemaire_", "Bugcrowd", "share_in_blue", "msmakhlouf", "pyq881120", "pegabiz", "_bobbysmalls", "chmod750", "infosecaddict", "mathanrajtk", "snak3pli77ken", "BnjmnDvd90", "taiyyib", "forenslut", "pyth0n_Sky", "MJ_Webroot", "ZeNetPlumber", "hachedece", "pialfg_md", "Nozz_", "robot_sec", "AelCourtea", "Saasar", "ypqFNEbaXvug", "tsuMenethil", "marcfredericgo", "StephaneVinter", "mano_nwl", "_Skylane", "MaaaadderHatter", "StevenRThomson", "herrcore", "arachnobob666", "sivaltino", "unmanarc", "DRX_Sicher", "likeitcool", "SleuthKid", "Peter2E0", "sHaxo19", "justinlundy_", "_Bike_Maker_", "Z3ttabytee", "DavinsiLabs", "cudeso", "zbetcheckin", "shortdudey123", "brambleeena", "_pronto_", "tlansec", "zaheenhafzer", "ustayready", "SecurityITGirl", "Shikata_ga_naii", "mboman", "CheckandSecure", "2w1s78ed", "AidBenA", "DPeschet", "niph_", "AharonEtengoff", "_dracu_", "xtoddx", "cimfor_l", "metaconflict", "ShoppingstroyR", "gregflanagan22", "prats84", "joegumke", "RobertoQuinones", "Unixity", "anassadikii", "JanMartijn", "secaggr", "MotherOfTweet", "wget42", "kptnpez", "FireBounty", "jamver", "minouch290463", "EricRZimmerman", "Anthony_Jarrier", "sharadmalmanchi", "peakotin", "librab103", "TFFdeC", "argevise", "LiadMz", "rotue", "AllisonsFitness", "cyber_kaser", "VincentBA44", "JulienPorschen", "L4g4", "lsb42", "_yapoc", "r_o_b_e_r_t_1", "_jw415_", "xhamstercom", "suqdiq", "rukovrst", "InfosecTurdFerg", "IOActive", "Bangs96M", "aquavoo", "HamzaHamzabl", "con_figure", "thatinfosecrec", "0xs3c", "nullx31", "4sche", "vlad_bordian", "AndreasRades", "antoniozekic", "ClsHackBlog", "ztzandre", "fullblownsec", "memosalah83", "MorganSALLEY", "ZollTech", "JimmyPommerenke", "fegoffinet", "faradaysec", "pseudonyme_ovb", "castor1337", "FSecure_IoT", "TLSv12", "Malwerewolf", "mvktheboss", "scotthworth", "Pjboor", "Bryan8700", "FredHilbert", "malware_traffic", "eddelac", "braindrain", "thd_kh", "DTCyberSec", "mugundhanbalaji", "cybert0x", "DanielRufde", "ImeldaNallela", "01Beep10", "dbarzin", "TheSIEMGuy", "MReveilhac", "pythontrending", "Ma3rsK", "DONIERMEROZ", "jiboutin", "tuxpanik", "eax64", "ValBouin", "danmichelucci", "kohldampfer", "PishranGroup", "yprez", "esskaso", "rgacogne", "La_venel", "SonyHaze", "AdrienDotFAY", "SonuSnjain31", "qboudard", "mleccha", "yosetto", "Zizounnette", "redarowxsj", "HardlyHaki", "flcarbone", "pello", "thenoax", "Beto4891", "EinatSoudry", "monstertobeast", "AFreeTeaCup", "ed_santillanes", "x0velin", "code_injected", "HotnetInfo", "GGdie", "melazzouzi", "rostomgtr", "HannenAk", "osdefsec", "jesljesl", "SchwarzonSec", "EMHacktivity", "bcastets", "exp10t", "daggerconf", "Sk5ll3D", "g00dies4", "lzskiss", "anubis_pt", "StanKj", "ramala1993", "wazak2k2", "Adoveo", "jykegrunt1", "DanCimpean", "FairFred", "maypopp_fr", "kcobrien42", "GitM8", "kob_248", "Othebaud", "wtaatp80", "MallDarth", "Malwaredev", "PravinWakle", "KhepriX", "fparis22", "i0nAy", "FrankStrasbourg", "alexandrosilva", "dondecuman35", "AESATIS", "vxroot", "sh33psy", "ggranjus", "cdagouat", "StaticJobsLLC", "mrjmad", "e3amn2l", "NHenaff", "bradbonomo", "jcanto", "martinez_brain", "sylvainbruyere", "FuraxFox", "crmunoz27", "nikos_alashiass", "PyBaltimore", "PhilGros", "asstalldiop", "endprism", "YohanniAllyscar", "rrogier", "benjaminvialle", "JChaubet", "titan391", "ITsecurityBabe", "christian_j06", "RubixLabsFr", "_m4g", "420investholdng", "Sh4d0wS4int", "UnhappyCISO", "Sysaddict", "mickeander", "TrustNCS", "BillBaker20", "jvitard", "over2393", "baudry64", "Vaelio", "actudefense", "gowaskAlice", "amicaross", "rnaitom", "Th3N1nj4", "RemoteViews", "vivien_fraysse", "Jerswift8Swift", "WokenRabbit", "Pentestylesnake", "md5hashtag", "0x4n6", "MMSmolarz", "jimbobnet", "AbidHabib12", "CYINT_dude", "henridebrus", "HrycIvona", "ITConnect_fr", "kmut", "MariusRisko", "CecurityCorps", "tux0t", "_Diskett", "davidbizeul", "0x66757279", "PrOjEcTHaCkErs", "ForestrialBook", "PVynckier", "T_0x1c", "0x1cT", "jfsimoni1", "Dnucna", "neilujh", "philoogillet", "Kiwhacks", "Eng_Balfagih", "AlexandreSieira", "VishnuGorantla", "SD_Intelligence", "Kettei__", "CORELANSL", "Rathodlalji27", "0xygate", "sevreche", "tsouvignet", "tguillemois", "MiN2RIEN", "VidAlban", "johanfuentesf", "clement_michel", "lesblaguesduduc", "xgsinfosec", "Julien_Gamba", "touelfe", "JonahLupton", "StartUpsSecure", "ZadYree", "alexandre_grec", "Fl0u_", "BertrandTFilms", "_nicolasmichel", "krierjon", "sehque", "Master_of_OSINT", "Sr_Shohag7", "Mescal_Hzv", "dervyshe", "Conix_Groupe", "scorpions786", "lapadorjee", "rdtdyd", "paineTesteur", "JeremyBesseyre", "goldProsperity", "mh_mamun93", "bibin57110", "_Stroumph", "Erwan_Sec", "TCqnt", "_p3r1k0_", "DebeurePatrice", "HoudiniOctopus", "kachulec", "lsb42A", "OxFemale", "samibourami", "bzhinfosec", "amin_qul", "Bx3mf", "Yacine_att", "A5chy", "_tennc", "ja99", "k0z1can", "Nima_Nikjoo", "AKAlrajih", "thierryzoller", "ddtseb", "MarieGMoe", "MS_Ignite", "fadbab", "Inox3_", "mz23in", "ChatironT", "fredsonic75", "The_NeTpSyChO", "brentwrisley", "jeffman78", "ThomVess", "1nf0s3cp1mp", "JP0x1F", "catalyst256", "lukaszfr", "aomanzanera", "MStingleyTX", "moustik01", "cyberroad_e", "ENCS_Julien", "lestextesR", "0x4c1d", "BoiteNoireKill", "raj883759", "JulienDev4Dream", "fafar", "tweet_josselyn", "PhilippePotin", "MartolodArBed", "TristanBertin", "philippeveys", "Vircom_Inc", "EuropeanSeC2015", "alxmyst", "2e325c3750f6466", "BertrandToulon", "stRiksVindicta", "ynirk", "_GRRegg", "OTBRecruiting", "cyb3rops", "BurgTechSol", "FrancoisSopin", "drake92s5", "EdenCySec", "ednv8", "totoiste", "ksecondlab", "linkbruttocane", "GYH_iwo", "igniteflow", "_m0rphine", "kevlabourdette", "mgualtieri", "wago42", "MissMooc", "2vanssay", "Lord0ftheWar", "Dr_penal", "CihanYuceer", "Drapher", "tomeetomy", "nmbazgir", "myimran", "zllitt", "samsec", "max_r_b", "Sbgs80", "lai132888", "jeremiemathon", "Fla_ke", "Fr33Tux", "airpair", "MichalStaruch", "cyberaco", "flopgun", "Jean_Dalat", "Someone780", "aldoestebanpaz", "EricFRC", "TuunLa", "UKOSINT", "Gimli130", "Aka_Spiderweak", "ykerignard", "reversaur", "Balltheabove", "skorochkp", "SiliconArmada", "TestingSaaS", "pkitools", "s0crat", "jusafing", "litalasher", "Share_Link_FR", "JackRybinski", "saraell1", "urlvoid", "jsgrenon", "Prash_rgv", "ILLUMINATEDBE", "Flo_nivette", "ryan_liang", "rashiduln", "raghimi", "Crypt0_M3lon", "ITNsec", "zeveDM", "Python_Agent", "ewager", "bi7dr0p", "HPxpat", "LodiHensen", "lepicerienum", "ztormhouse", "GummoXXX", "Cleverdawn", "cam3r0n9", "cybersecscar", "17_dallet", "SecuInsider", "Linschn", "ldebackere", "anarcho_voyo", "Fayd_1", "brian_warehime", "KaganKongar", "The_Tick", "JevyLux2", "Shaunsaravanas", "E_Setuid", "papygeek", "etiennelb", "WhilelM", "pvergain", "Novettasol", "cybereason", "VindexTech", "devasundar_a", "madpowah", "fdomartins", "w4l3XzY3", "NeoCertified", "lliknart31", "datwittak", "jaurieres", "tux92", "Ahugla", "Evex_1337", "golgotte44", "m4xr4y", "StratosphereIPS", "Azca_tp", "servicellpasto", "LordAbitbol", "chrisdoman", "UndiesClothing", "fbouy", "poulpita", "hiubiah", "rlgrd", "M3te0r_Wave", "lauMarot", "WarpDelabass", "pluckljn", "sonkite225", "ArmatureTech", "DigiFoRRensics", "mrtuxi", "MGMonty66", "ywilien", "BouDiop1", "nigabeyna", "Data88Geek", "domen_bexo", "maher275", "KirstyM_SANS", "andrewbrinded", "yararules", "nolimitsec", "adarshaj", "vsantola", "Random_Lyceen", "lllmine1", "HarlinAtWork", "DanbecBeck", "spridel11", "Sorcier_FXK", "666_tweet", "BronzeAgee", "wide_nicopus", "jcpraud", "SecIT_Summit", "hut8uk", "jean_sylvain", "imrim", "CyberWarfaRRe", "HECFBlog", "V_Gourvennec", "dev_mess", "les_oscars", "blair_strang", "mariasans81", "rifec", "bigmuse85", "sec_joao", "cedriccazenave", "Joel__Gros", "chokami", "fygrave", "XXXnoflagXXX", "4securitytweet", "Geclaaaw", "AuffretI", "0wosk", "vtcreative", "kerhuon", "todbox", "Rogsis1", "sim0nx", "jkimmusyoka23", "noopzen", "_julesi", "flavio2012Toic", "DerdniK", "igor51", "yzileo", "hyp_h5p", "d4rw1nk5", "julientouche", "ClaireNaudeix", "NuHarbor", "sdkddk", "lfm421", "tomyang9", "e4b816", "TTAVTest21", "Davidforense", "aasifrafiq", "pologtijaune", "jreen85", "ICOexchange", "dginio", "armazicum", "marcmilligan", "8bd130498da745a", "Natwayzee", "jerome7528", "k_y0p", "NRabrenovic", "Security_Sleuth", "SunnyWear", "rezor59robert", "sysinsider", "tuxedo_ha", "_langly", "1NV65510N", "nlt56lorient", "drioutech", "rapid7", "OXITS", "caroworkshop", "KayleighB_SANS", "hack3core", "iansus", "YacineHebbal", "thegeeksjt1", "jasonish", "MyTechCommunity", "GhelSafo6", "marklinton", "F_kZ_", "flomicka17", "gal_lapid", "tranhuuphuochva", "ZikyHD", "kmkz_security", "pepito38100", "JeanphornLi", "hickling_thomas", "Dave2167", "nedforume", "DELLFrance", "SANSEMEA", "kfaali", "thomas_maurice", "bitcoinctf", "boolaz", "N0jj4", "alaurea", "droops38", "qdemouliere", "8mccm8", "JohnDoe24563614", "pstirparo", "xorred", "sn8doc", "shats1978", "Damian_Zelek", "layes2904", "TaliltO", "Kan1shka9", "Tech_Truth", "cinetimeapp", "Catalyst_b_01", "Neur0z0ne", "rabauken5", "A_H_Carpenter", "S_ith", "a_ssuresh", "fido_66", "MathildeLBJ", "d0kt0r", "geekjr", "riftman", "Slash868", "citronneur", "dikkenek65", "uta966", "s3cdev", "tar_gezed", "SharkN", "ZzzZacato", "___wr___", "giannihope", "Lanuom", "cedoxX", "CUS3CUR3D", "koubyr", "m_bertal", "robbyfux", "s4mb4rb3ry", "31415926535z", "omriher", "_sodaa_", "SecEvangelism", "Sunzag", "Scratoch13", "SniperX509", "bestitsource", "lumisec", "ZedFull", "aqarta", "CyberMesCouille", "csiroen", "IlanUzan", "HovikYerevan", "1fuckg", "securitybrew", "rezogot", "NemRaphMic", "cyralco", "MarieGuiteDufay", "sdesalas", "karzaziasmara", "sskkeeww", "s7v7ns", "Ericchen1106", "triflejs", "Andrew___Morris", "Risk_Cambridge", "hxnoyd", "moyuer12345", "veilleurh", "opoupel", "sylvander", "31is", "mosarof_bd", "jjajangjoakk", "eurozn", "FlxP0C", "moong1ider", "OWASPSonarQube", "jawahar11", "Ouaibs", "pkalnai", "singhharinder11", "JorgeOHiggins", "FecafootOfficie", "DrEricGrabowsky", "doduytrung", "Nonow_RedWolf", "_r04ch_", "ExperSecure", "explosec", "black_duck_sw", "cywilll", "remid0c", "MaxCNT", "ramesharma1973", "doctor_malware", "tofattila", "dprebreza", "OhMyTux", "OSDelivers", "m4thi3uf4Vr3", "fayejeff", "red21tech", "Loria_Nancy", "barryirwin", "v4nyl", "Gnppn", "SaberJendoubi", "manhack", "BootMe322", "julloa", "TiNico22", "sieurseguin", "dsecuma", "jmichel_p", "sndrptrs", "NeonCentury", "sidoyle", "virgile1945", "TejMouelhi", "Aztec_36", "olamotte33", "diggold", "Chemrid", "227363", "frzndgoash", "_Zakalwe", "infsec", "TheITGuyFr", "AnuInsight", "bornot_t", "2kdei", "WATCHDAWGMAMA", "hzmstar", "v1nc3re", "bonjour2410", "irvinHomem", "chrisnoisel", "clusif", "But1er", "0x94FA429D", "Overacloud", "espreto", "nmnhuq", "jhosley", "dcauquil", "aifsair", "HackersDoor", "__capone89__", "attackvector", "fugitifduck", "yusufarslanp", "dgatec", "m_demori", "TheWizBM", "jmvillaume", "arrogantpenguin", "Zipeod", "3mpatyy", "mineshk", "pisco", "booub", "netrunner504", "Spawnhack", "oisux", "IncidentHunter", "SecNewsTracker", "GanetheGreat", "cizky", "clickssl", "sicherheit_DE", "pheer_down", "WindMarc", "TCasalRibeiro", "cybere00143", "OctetBow", "zoomequipd", "_icewind", "DinhNhatAn", "Matteo_DeGiorgi", "Robert4787", "fercorvalan", "Malefactor8", "mjbroekman", "dotstar", "philiplbach", "higefox", "MilestoneSecure", "sxt", "4n68r", "william0420", "IdleWog", "a_ortalda", "aramosf", "FradiFrad", "RubiKobalt", "Pentest101MX", "ChrisGoettl", "nguvin", "ValeryMarchive", "hcdlf", "NickInfoSec", "EiQNetworks", "dominique_yang", "skisedr", "Ch1sh1rsk1", "jode1963", "EatherZhu", "fasm3837", "ckyvra", "lucianot54", "TuElite", "echo_radar", "Alphoxofficiel", "voksanaev", "TiRybak", "faruksari", "pr4jwal", "d_ni3l", "wpawlikowski", "Reversity", "cafepsy4startup", "Chublett", "KitarouSec", "abhuyan", "KevTheHermit", "kunbeyalouae", "PierreBONGRAND", "maciekkotowicz", "h4ckable", "makwys", "r00t0vi4", "virtkick", "deshmaL", "wixyvir", "RemiRaz", "Dusseul", "dysoco", "verovaleros", "CisGarrido", "C33Z4R", "minintech", "Bry_Campbell", "johanneslondon", "4sybix2", "Brain0verride", "johnysm17h", "NajihY", "h1romaruo", "parttimesecguy", "atawack", "ccoadvance", "memeavelo", "jibetr", "Scifisec", "AnonymouSpeak", "hackfest_ca", "BretPh0t0n", "nanderoo", "cortesi", "S0mna1H", "matt26th", "quotium", "reolik", "openiam", "bouallaga10", "subratsarkar", "SafestSneer", "pai9901", "DavidLWaterson", "ColasV1", "cramsenyer", "S_Team_Approved", "vNicoro", "define__tosh__", "ahmazingan", "chrystelchrys", "ryusecurity", "AITWebHosting", "ChaudharipawanP", "lcuguen", "DavidJ4RD1N", "ElcomSoft", "piotrkijewski", "RodrigueLeBayon", "speedtaskfr", "brodzfr", "cissouma_adama", "tontonsFappeurs", "HorusSec", "fab_tan01", "rodjafirs", "julien_luke", "yastanimeil", "romu1000", "ByteAtlas", "baiyunping333", "HiroProtag", "penthium2", "Expand_InfoSec", "teraliv_", "MimiiiX", "sach_mehta", "1nf0s3cpt", "torglut", "elisa_muller08", "nuomi", "Jeremy_747", "sjashc", "AquaZirius", "NazratatR", "maejoz", "xanuma11", "Ma_bon", "sekoia_fr", "miliekooky", "feedbrain", "mrbarrett", "Matrix_ling", "daniel_munsch", "j_NewTr0n", "dominichudon", "AAH2100", "arkhe_io", "Bl4ck_D4wn", "bjadamski", "phdjedi", "Bobetman", "AirFranceFR", "barbier_bernard", "AptiResearch", "GirlCodeAPage", "eureka77777", "BinKhatt4b", "entwanne", "OceanetTechno", "accentsoft", "passcovery", "Zekah", "FredzyPadzy", "ekinnee", "securityfreax", "dschaudel", "acidburn0zzz", "snashblog", "HamzaHsamih", "l3m0ntr33", "IreneAbezgauz", "fensoft", "Hjear", "nullaKhan", "_Cornichon_", "eldracote", "fx_flo", "m2nu3", "NicolasGUY_Site", "no_ossecure", "dis7ant", "aeseresin", "SecureHunterAM", "fgrenier", "olivierthebaud", "_x4n4_", "eon01", "OPSWAT", "seti321", "mojoLyon", "voxanette", "livebullshit", "KrovyMike", "casinthecloud", "CodeAndSec", "PCVirusRemoved", "MatheusSaccol", "aouadino", "jfvrxmbl", "RedBoool", "hispanglish", "cmingx", "hostiserver", "jberciano", "elpep", "StuAllard", "guillaumededrie", "CorsaireHarlock", "root9216", "ChrisBereng", "binTest2014", "AniemX", "routardz", "MlenaLenam", "sizzlersam", "iareronald", "bapt1ste", "xakyc", "melo_meli", "Cephurs", "mz_techwhiz", "dijoritsec", "pentesta", "samuelhermann", "orenelim", "Z0vsky", "zerobiscuit", "cryptoishard", "yeulett", "TSSentinel", "glachu87", "degolar", "zakmorris", "Linkurious", "Pdgbailey", "alextbrs", "ncrocfer", "vulnia_com", "RoxanLeca", "jeromesaiz", "pozkawa", "demonskiller974", "KalanMX", "BSI_ISO27001", "vguido2", "dvirus", "Hakin9", "RomainVergniol", "PhLengronne", "kanghtta", "Marl092", "MuSylvain", "HaxoGreen", "mattkowalski", "PierreEmpro", "sTorm_teK", "SergioWfr", "2removeviruscom", "BestDealCart", "Freddyflameapp", "0b1_kn0b", "netprimus", "monsieur841", "intelligencefr", "31petitponey", "meisgizmo", "ankit_anubhav", "link2kimson", "riusksk", "Bitcoin_Lord", "cbldatarecovery", "wlvis", "aulitdbg", "cjumbo", "f0rte2", "secuinfo28", "OsanaGodspower", "1Citoyengage", "mtth_bfft", "jeffthomasaero", "Johnok_", "nevilleadaniels", "lguezo", "HackSpark", "simasj", "Kofithep", "NiightlyCat", "jkpdinesh", "fullanalyst", "adel2k14", "OliCass", "Ignas_Nr1", "KarolisBartkevi", "iamthefrogy", "OlivierMenager", "konstanta7691", "TesfayGebreding", "ChristopheH00", "andbezh", "crlDr11", "AngoCharles", "zenithar", "pevma", "zackhimself", "JeredFromCMLP", "N1aKan", "iriqium", "MontagnierP", "ICTSpring", "twitxobz", "marinivezic", "DavidDoret", "ReverserRaman", "olsap8", "linuxiaa", "activity_black", "circl_l", "GuiLecerf", "ProfAudenard", "Nschermi", "vadorounet", "NateOSec", "abnev", "MichalKoczwara", "ondiny", "__ner0", "qiulihong", "B51404EE", "3lackSwan", "Dami1Paul", "TheBotnett", "TheseusMovement", "handyj", "mydeliriumz", "44ND0MS7UFF", "Path_finder_z", "8008135_", "venicequeen92", "Guruoner", "lessyv", "KLNikita", "Voksanaev_OSINT", "Jice_Lavocat", "SARCWV", "diegobolivar", "theosintguy", "robiocopAB", "Nemako1", "mutmut", "byone", "mtarral", "chris70f", "gargield", "LeopoldoAgr", "bZhDolphin", "suuperduupond", "cryptobioz", "VeilleSSI", "fast2001ak1", "DeepSpaceColony", "cedric_baillet", "Teffalis", "CyrilleFranchet", "Sabine_dA", "goldochoa794", "GardieLeGueux", "N__Sec", "BlueRabbit09", "securitymuppet", "r1hamon", "BonifasNestor", "h1rm", "Zauerfish", "nostarch", "queenwaldorff", "linda6096", "PietroDelsante", "DavisSec", "BlackPian0", "jbnet_fr", "jwgoerlich", "Sargerras", "0x89D0A74B", "netantho", "HuyTDo", "LEACSOPHIE", "BibChatillon", "navlys_", "imagineers7", "e_tachea", "nitinpatil999", "hardik_suri", "superzamp", "elogringer", "jcbld2", "norio567", "robnavrey", "Mumr1k", "happyf337", "suspiciouslow", "ReactivOn", "FedorIcy", "nicksciberras", "Naakos", "Ekimvontrier", "IftahYa", "Fractalog", "Game0verFlow", "Formind", "the_jam", "Sudhanshu_C", "crdbr", "cyber_sec", "matteverson", "rkervell", "Jayson_Grace", "AlineKav", "maximilianhils", "libfy", "arboretum_sas", "DoctorNoFI", "ravitiwari1989", "kevdantonio", "JackKin87812598", "_bughardy_", "phretor", "kryptpt", "BAH_Hacker", "steverigano", "BucklorVPN", "christobal600", "davidtouriste", "stevemcgregory", "frsecilio", "KurShf", "softwaresensei", "Zestryon", "AlmesalamJabor", "H_Inside_ec", "TristanTREVOUX", "0x0000EBFE", "cherepanov74", "a_de_pasquale", "kapravel", "AntiVirusMallo", "tdecanio", "sectroll", "mosesoche3", "zeitgeistse", "Homlett", "good_dad", "pickpocket001", "veerendragg", "rosako", "maaax78", "kaiyou466", "Seb_Net", "Newnioux", "evilbluechicken", "_Cryptosphere", "_gdie", "pourconvaincre", "hermit_hacker", "ESS_La_Pape", "XiaoTuoT9", "notacissp", "notacissp", "stephane_pernet", "unbalancedparen", "ennascimento", "d_launay", "N0ADM1N", "billal_hassan", "antoinedugogne", "jbuhler", "stanleyfmiles", "PeRamon76", "steward110", "asisctf", "fewdisc", "infosec4ngo", "__dxx__", "CNISMAG", "attrc", "nirouviere", "chiston", "janremi_e", "souillies", "GArchambaud", "sovietw0rm", "dvor4x", "sunl3vy", "benkow_", "agnes_crepet", "MsTeshi_", "Kartone", "securesearcher", "s1mon_p", "novirusthanks", "Phonesec", "korezian", "FrenchYeti", "webstack_nl", "guillaumeseren", "v2caen", "Whitey_chan", "jpcw_", "NeustaSCV", "scott_janezic", "RemiDof", "quentinlpt", "yaap_", "MacTweater", "IEMPROG", "angealbertini", "cr0nus_bin", "graeff6", "websec", "ThibaudBD", "Milegemiao", "BSeeing", "cymansys", "Whoisology", "bakabeyond", "teoseller", "danebrood", "El_Quiglador", "SteveGarf", "factoreal", "GSSGhana", "TheHackerFiles", "mobinja", "Transversal_IT", "Samyz666", "AbMalware", "skydge", "rts0dy", "charlesherring", "Ex_Strange", "paranoidbaker", "D1INT", "bonika18", "jahrome11", "n0rssec", "DMBisson", "itnetsec", "MTDOJSecurity", "xiaoheih8", "hackawa", "ibrahim_draidia", "p4p3r", "cteodor", "SSHNuke0", "gmillard", "AurelienCottetL", "bizcom", "muller_sec", "tergaljc", "milkmix_", "chaisetagada", "Netsquatch", "Securelist", "SecViews", "_Sec_C", "InsanePolicy", "da_philouz", "Kmarkk88", "secandro", "marknewsgeek", "WhiteHatRabbits", "DubourgP", "brucedang", "oueldz4", "BobbyLaulo", "jokerozen", "ShawoneYO", "_thieu_", "gud28", "Zaryosuke", "fataloror", "Mouhe", "geralddefoing", "jonsbh", "3aceaf6b12a648f", "_moloson_", "cbrocas", "JanetCSIRT", "ceprevost", "fagamartin", "tim_maliyil", "gg0nzal3z", "clabourdette", "insitusec", "pvrego", "yongicobay", "Baaasto", "_alb3rt0_", "0xKarimz", "MisterCh0c", "barcode", "arkam_hzv", "sljrobin", "OlDll", "lazy_daemon", "HacklabESGI", "courbette2", "electr0sm0g", "FliegenEinhorn", "ESET_France", "espritpervers", "morganhotonnier", "dw33z1lP", "menkhus", "markymclaughlin", "C4t0ps1s", "righettod", "BossHiltoon", "trollab_org", "network18276620", "asv_tech", "tseligkas", "northvein", "JershMagersh", "HeleneChance", "Rahmatyanuarsya", "ChevalDeTrolls", "kriss_dek", "cmatthewbrooks", "valerieCG", "winSRDF", "Pr1v4t3z0n3", "MouloudAitKaci", "lorenzo2472", "pentagramz", "worreschk", "Lucas3677", "adriengnt", "frameforward", "loris_voinea", "EMSST_DE", "k0st", "yaba", "Andre_Sponge", "zdayl", "secdocs", "ghpophh", "Tib_Tac", "AbelWike", "Baadrov", "kolleanv", "_dup_", "ThinkTankDiff", "clusiraqui", "xabean", "evj", "GaelMuller", "Roaming_One", "rosisura", "Ragvelsec", "mandraquex3000", "zirkkam", "Jak03_", "jbscarva", "rj_chap", "Emulex", "micha_cjo", "m0narch_", "matthieugarin", "Thomas_Jomea", "Wookieshaver", "JohnathanNYC", "iidrissoui", "pwyl61", "Dark_Puzzle", "bockcay", "deletom", "tmakkonen", "DamnedKiwi", "TAHASAID2", "HastutiYuanita", "hazard_fish", "bluefrostsec", "p_coupriaux", "DuanHork1", "LamaliF_", "bpoinsot", "Licop", "techblogspics", "Mr_Fredo", "r_em_y", "WhooisWhoo", "marcdov", "0x3af", "kiirtanrosario", "BaptisteMalguy", "bitcoinsdouble", "Ledoux_JP", "bortzmeyer", "watchguard", "lysimachas", "JeromeNotin", "c0rent1b", "hadrio", "Sherry_Art", "ttwye", "cmpxchg8", "Pat_Ventuzelo", "soycmb", "s4vgR", "oemailrecovery", "Asuwiel", "seancataldo", "swallen62", "wprieto", "CardNotPresent", "NJWILL01", "harrjd", "ashpool", "ILoveMyTux", "TonyLeGeek", "planbwarehouse", "CathCervoni", "FreddyGrey", "0xM3R", "getCountly", "SecurityGuy62", "ArthurUrv", "Moosehyde", "fabien_gasser", "blackthorne", "nkokkoon", "__emil", "sebast_marseill", "broisy", "sam_djari", "fsnormand", "MirMuza", "devpsc", "LeCapsLock", "Leslie_Lavigne", "SmetPierrick", "jamal972", "PierreAllee", "sn___8", "ZhengOlivier", "stephane_deraco", "epelboin", "cmfml", "ThetaRayTeam", "lefterispan", "DubarrySylvain", "irish_ninja_73", "bedoyadaniel2", "ElCherubin", "twallutis", "brunocassol", "g0ul4g", "uberalles666", "AmahouaGeorge", "scls19fr", "ftwads", "cchristoscc", "___Arod", "nicolasvillatte", "BakkenCoin", "pjhartlieb", "mjf4c3", "malwarenews", "azrulOracle", "aured_0x2747ff", "beewebsec", "lenaing", "derecwan1", "El_Tonioo", "ThierrySoulard", "xamcec", "ThingsSecurity", "bosjr", "Brihx_", "Kariboupseudo", "bluetouff", "commu_npn", "pingpingya", "meniga_l", "StosseFlorian", "bobcat133", "antonio_cuomo", "david_billard", "r00tapple", "Ciccio_87XX", "blocklist", "qu1tus", "kleenec", "lexsi", "RosKran", "javel_le_miroir", "jumbo_ninja", "gcouprie", "quentinmaire", "ravear2", "TripwireInc", "cillianlyons", "jyria", "Yaogwai", "DhiaLite", "_haplo__", "prayas_prayas", "surrealiz3", "z3ndrag0n", "ahmad_kifre", "LMVACATIONS", "ababooks", "toma3775", "mpbailey1911", "rontol", "queenmafalda", "almassry21", "carl_chenet", "vratiskol", "deesse_k", "f1329a", "netrusion", "Mitzwei", "SPQRF", "juni71", "l_pecheur", "sk_buff", "NemanNadia", "R0ns3n", "thecigale34", "GardanneMS", "Omerta_IT", "pbeyssac", "savon_noir", "alexstapleton", "raphaelmansuy", "tais9", "dugasmark", "MalformityLabs", "vivelesmoocs", "6433617468", "zertox1", "tic_le_polard", "PhilippeNael", "_m4tux", "b1ll228", "Valri7", "Fortinet", "fmarmond", "laurent_cor", "ottimorosi", "pedri77", "dzurm", "itespressofr", "matt_ibz", "oallaire", "cloudgravity", "logicus", "jeetjaiswal22", "AxelrodG", "GH_MickaelGIRA", "t_desmoulins", "cschneider4711", "darksider9", "SppSophie", "caar2000", "Ta9ifni", "FrenchKey_fr", "Brocie", "audricalba", "PierreSec", "_get_sandre", "Soufiane_Joumar", "IT_SICHERHEIT24", "marnickv", "marco_preuss", "saidmoftakhar", "F5_France", "seculert", "nico_reymond", "VirtualScale3", "ArchiFleKs", "benborges_", "netstaff", "blackswanburst", "cccure", "anderson1diaz", "h4ck1t4", "louisaoasi", "verac_m", "fredrik9990", "guignol78", "Cym13", "cryptax", "k0ro_Bzh", "pinkflawd", "Irthaal", "MakInformatique", "aseemjakhar", "gmagery", "Nirylis", "hugo_glez", "PANZERBARON", "20_cent_", "Synacktiv", "zonedinteret", "Rulio739", "cceresola", "viren024", "t_toyota", "maralamtakam", "ielmatani", "fredfraces", "aoighost", "PowZerR", "Luchien14", "Gexecho", "c_est_bath", "0xDeva", "SymbolsShatter", "S3C0de", "Kujman5000", "carlanlanlan", "SteveClement", "tomsmaily", "yoga_vinyasa", "seakingWD", "darthvadersaber", "GreeniTea_Break", "borstie66", "Boisnou44", "aliappolo", "l88493425", "dise2s", "buz_tweets", "corkami", "_0x4a0x72", "mascuwatch", "DIGITSLLC", "InfosecNewsBot", "mbenlakhoua", "RedHatNL", "kamalsdotme", "mkevels", "Fred_Mazo", "SamuelHassine", "VaesTim", "arnaudsoullie", "virtualgraffiti", "Y0no", "BinarySecurity", "snipeyhead", "ante_gulam", "siedlmar", "commial", "StephaneLechere", "Ron91111", "heliotgray", "SopraSteriaSec", "rvofdoom", "daerosjax", "SnoopWallSecure", "ronin3510", "MxTellington", "m0rphd", "TheUglyStranger", "0x3e3c", "RichardJWood", "fr54fr54", "amstramgram8", "stravis_", "cyberdefensemag", "cedricpernet", "GNU__Linux", "Vivet_Lili", "j_schwalb", "fred104_at_TW", "Solulz", "Narendra_ror", "mike820324", "AmauryBlaha", "specialgifts_1", "martelclem", "EXEcrimes", "cha0sgame", "w3map", "LibreSoftwareFr", "laurenthl", "spydurw3b", "posixmeharder", "Itsuugo", "kfalconspb", "Logeirs", "Atredis", "sowmiyatwits", "Akheros_Corp", "aur0n1", "happyoussama", "Dunne3", "serphen", "informatrucX", "The_Crazy3D", "florent_viel", "phn1x", "JJTonnel", "cguiriec", "hackplayers", "rackcel", "manicsurfers", "mark_ed_doe", "overnath1", "gradetwo", "BehindFirewalls", "xGeee", "unsocialsysadm", "Sixelasco", "R1tch1e_", "x0mF", "TechIQ_ISRussia", "robjamison", "SyMangue", "DamienPierson", "faryadR", "AriOkio", "genieyo", "KitPloit", "tominformatique", "cryptopathe", "IsChrisW", "thepurpledongle", "__Obzy__", "rand0muser35", "securebizz", "belowring0", "SilverSky", "jiesteban", "dt_secuinfo", "esetglobal", "clauzan_", "xjbkxking", "CuriositySec", "nickkarras", "nigirikaeshi", "Inteligenciasmx", "dannyyadron", "dan_kuykendall", "rig_L", "dougser182", "CCLGroupLtd", "ProDestiny1040", "oktarinen", "_robinrd", "SWAMPTEAM", "kaluche_", "turcottemaxime", "kokail", "mokhony", "ProteasWang", "L140CJ", "LymaCharlie", "public_bug", "mattgiannetto", "FabriceCLERC", "yuange75", "quyendoattt", "kennethdavid", "lopu61", "Ibrahimous", "viruswiki", "Stephane_MORICO", "m0m0lepr0", "DarrelRendell", "TunisLul", "nejmpotter", "CyberSheepdog", "Kavika888", "poona_t", "NANGLARDCh", "ibr4him2011", "0pc0deFR", "On4r4p", "ikonspirasi", "hurricanelabs", "KAI2HT003", "corte_quentin", "BRITCHIEN", "B1gGaGa", "hackers_conf", "shab4z", "rosemaryb_", "GuilhemCharles", "23_BU573DD_23_", "gvalc1", "slashdevsda", "osm_be", "TheMrigal", "MalwareAnalyzer", "rpiccio", "MaguiMagoo", "mushrxxm", "l__D0", "philpraxis", "noarland", "H00b3n", "emapasse", "netsecurity1", "Hectaman", "skeep3r", "doulien", "mastercruzader", "blaster69270", "MmeAPT", "ameyersurlenet", "dstmx", "RuthyYou_Me", "EthanCrosse", "d4v3nu11", "juneisjune", "jesperjurcenoks", "BraeburnLadny", "DavidIsal3", "_fwix_", "ark1nar", "CryptoPartyFI", "lpeno", "collo20123", "lifegeek_co", "FYLAB", "maisouestcharli", "isithran", "yhzkl", "azediv", "espritlibreinfo", "alex_kun", "hxteam", "BSONetwork", "kali_linux_fr", "IceAnonym", "xeip1ooBiD", "SamiAlanaz1", "cyrilril", "Minipada", "Julien_Legras", "PratheushRaj", "THYrex55", "CalvinKKing", "T3hty", "Bigou_de", "Maijin212", "RATBORG", "Thus0", "montagnetata", "AntoinePEREIR19", "helsayed78", "ak4t0sh", "MarcoPo87022565", "raybones", "DroschKlaus", "Fyyre", "ErwanLgd", "undaVerse", "ltmat", "jorgemieres", "BitdefenderFR", "Joel_Havermans", "AlfBet1", "CyberSploit", "simon_s3c", "archoad", "alexisdanizan", "cryptomars", "n_arya0", "dgiry", "pedrolastiko", "juanferocha", "_8B_", "nordicsecconf", "SophosFrance", "teo_teosha", "Lircyn", "jordangrossemy", "mamie_supernova", "totol__", "Azenilion", "LaurentSellin", "hinozerty", "PyRed7", "kr0ch0", "wolog", "legumx", "e2del", "VaValkyr", "RobinDavid1", "Apprenti_Sage", "PConchonnet", "LucDELPHA", "Guillaume_Lopes", "vm666", "Tinolle", "pollux7", "Ralita_Jamala", "tixlegeek", "_Mussat_", "TwBastien", "quatrashield", "Tinolle1955", "defloxe", "idnomic", "iboow38", "BabigaBirregah", "Julllef", "secuip", "morganeetmarie", "FightCensors_fr", "vprly", "rommelfs", "_nt1", "micheloosterhof", "MattNels", "QuanTechResume", "rshaker2", "joe_rogalski", "naviduett", "enriquerivera80", "HackMiamiRadio", "openminded_c", "HiDivyansh", "kyREcon", "NotThatAmir", "aliikinci", "_Zen_Ctrl", "UCDCCI", "lisalaposte", "iLebedyantsev", "Zen_neZ_", "inetopenurla", "Jeremy_Kirk", "uBaze", "0xfnord", "und3t3ct3d", "MichaelSlawski", "1ight35", "Ax0_85", "PirateBoxCamp", "Berenseke", "OlivierRaulin", "WTFproverbes", "adamkashdan", "GaylordIT", "_gabfry_", "security_sesha", "balasrilakshmi", "secnight", "autobotx2", "ThreatSim", "canavaroxum", "mvdevnull", "RecordedFuture", "StorageChannel", "bmaprovadys", "mrozieres", "K3nnyfr", "infomirmo", "eth0__", "AlMahdiALHAZRED", "wyk91", "crdflabs", "n1ngc0de", "mitp0sh", "8VW", "ElMoustache", "pbortoluzzi", "free_man_", "calhoun_pat", "aknova", "oleavr", "Vinssos", "bugwolf", "openwiresec", "yasinsurer", "codeluux", "jain_ak", "hnt3r", "vessial", "Mid_Tux", "IgorCarron", "XWaysGuide", "machn1k", "etiennebaudin", "the_mandarine", "spy4man", "nProtect_Online", "JeroenLambrecht", "360Tencent", "zforensics", "dell81404780", "julienroyere", "Dejan_Kosutic", "NeoAntivirusUSA", "randiws", "Kentsson", "jmdossantos", "Xserces", "william9555", "PraveenCruz", "chezlespanafs", "malk0v", "0x0d0084abdec6d", "josephwshaw", "NaxoneZ", "Bourguignon", "David_RAM0S", "pierrebrunetti", "SiafuTeam", "succedam", "Korbik", "_Kitetoa_", "_Sn0rkY", "vxradius", "Tp0rt", "laks316", "Holmez_hood", "OlivierMOREIRA", "3sOx13", "OzzPlopoO", "dreeck7", "net_security_fr", "altolabs", "visiblerisk", "rockyd", "borjalanseros", "ForensicsDaily", "grehack", "Intrinsec", "jon1012", "checkfx", "metalprfssr", "maldevel", "SPoint", "Alcuinn", "pentest_swissky", "zamokarim", "tracid56", "3615RTEL", "FredGOUTH", "hesconference", "srleks", "CarbonBlack_Inc", "Turnerwjr", "Art29C", "digital2real", "Bsfog", "allurl", "TorretoGCM", "OsanaGussy", "Qutluch", "tiye2003", "patatatrax", "ErkkiPasi", "miaouPlop", "AlbinK_reel_0ne", "TaibiD", "0xVinC_Dev", "Olzul_", "NTeK33", "elfmazter", "dremecker", "shutdown76", "loxiran_", "kaiserhelin", "binaryz0ne", "fradasamar", "Wagabow", "HackSysTeam", "PKPolyEnquete", "r0mda", "Jl_N_", "AbelRossignol", "0xcd80", "dj_tassilo", "BenoitMaudet", "Xst3nZ", "FChaos", "hootsuite", "sci3ntist", "djabs_barney", "houssemthenoble", "baronscorp", "Intrusio", "gowthamsadasiva", "secknology", "nullcon", "michelcazenave", "Breizh_nono", "kartoch", "Tony_DEVR", "jaganm0han", "milovisho", "pierre_alonso", "Moto_MIA", "AlineBsr", "HackaServer", "Karstik1", "JAldersonCyber", "_gwae", "cryptf", "miguelraulb", "opexxx", "johndoe31337", "DubourgPaul", "ahmanone", "sukebett", "AZobec", "hightur", "lecoq_r", "StephaneG22", "shaneflooks", "johnvd123", "Denit0_o", "aojald", "JosiasAd", "miis_osint", "nasserdelyon", "SACHAVUKOVIC", "Atchissonnymous", "pa1ndemie", "ljo", "Jo_S_himself", "_antaked", "Luzark_", "black_pearl01", "beuhsse", "chr1s", "The_APT1_Team", "__pims__", "_SaxX_", "Bruno_Mahler", "t4rtine", "SandeepNare", "JFF_csgo", "thinkofriver", "_RC4_", "N0Px90", "ARUNPREET1", "dariamarx", "hardwareActus", "lapindarkk", "mrtrick", "shipcod3", "TDKPS", "arpalord", "kerguillec_paul", "MduqN", "heggak", "Maxou56800", "512banque", "fr0gSecurity", "speugniez", "ashwinpatil", "JosselinLeturcq", "barryp792", "Ched_", "Paul_Playe", "boreally", "esthete", "OlivierBarachet", "Securonix", "PRONESTA_FR", "Ponyc0rn", "Dkavalanche", "jvzelst", "oli_adl", "zwerglori", "tvdeynde", "mhamroun", "pensource", "datumrich", "g4dbn", "JussiPeralampi", "malc0de", "karimyabani", "gadolithium", "MennaEssa", "plaixeh", "gl11tch", "whtbread", "anton_chuvakin", "PhillipWylie", "AmiMitnick", "nasete", "Asim2010khan", "SteyerP", "mubix", "TheHackersNews", "okamalo", "simonlorent", "nico248000", "MobiquantTech", "Lita_Amaliaxo", "o0tAd0o", "sc_obf", "0p3nS3c001M", "nicoladiaz", "rattis", "rcsec", "MrTrustico", "ranmalw", "michaellgraves", "MDALSec", "_Reza__", "charles__perez", "fo0_", "ntech10", "airaudj", "florentsegouin", "HerrGuichard", "fabien_lorch", "amina_belkhir", "vloquet", "_Quack1", "Regiteric", "flavia_marzano", "piconbier", "NoSuchCon", "p3rry_ornito", "Blackploit", "T0mFr33", "SInergique", "_c_o_n_t_a_c_t_", "d3b4g", "Tazdrumm3r", "ActiVPN", "SilentGob", "tranche_d_art", "bl4sty", "mercevericat", "MickaelDorigny", "Flo354", "sambrain94", "Diaz__Daniel", "Lying_Iguana", "AlexNogard1", "w0ltt", "FraneHa", "culley", "Cyberarms", "alberror", "Clint_Z", "planet_shane", "melphios", "precisionsec", "0_issueIE", "cowboysec", "PanimLtda", "jhaldesten", "gnusmas2", "Schiz0phr3nic", "cabusar", "HackBBS", "Wechmanchris", "0F1F0F1F", "demon117", "TrendMicroFR", "fieryc0der", "number3to4", "RobInfoSecInst", "MinhTrietPT", "und3rtak3r", "iefuzzer", "0xkha", "Orqots", "theodorosc", "ec_mtl", "shellprompt", "instruder", "cpierrealain", "iCyberFighter", "ufleyder", "rameshmimit", "a88xss", "dotlike", "matonis", "gbillois", "varmapano", "Botconf", "st3phn", "YBrisot", "rh_ahmed", "x_p0ison_x", "ph_V", "CryptX2", "m0nster847", "fcoene", "Tobias_L_Emden", "ifontarensky", "qqwwwertyuiop", "C3cilioCP", "freemonitoring", "__ek0", "StefSteel", "X01VVD01X", "JC_SoCal", "rchatsiri", "itamartal", "irciverson", "ksaibati", "bindshell_", "dudusx9", "binnie", "GI_Steve", "RssiRuniso", "mnajem", "_n3m3sys_", "geeknik", "stuntlc", "giorgioshelleni", "Zebulle59", "ourwebz", "lostcalamity", "NytroRST", "xtremesecurity", "KODOQUE", "kashifsohail", "NicolasLevain", "_Anyfun", "BZH_SSI", "xxTh4mUZxx", "mgaulton", "MeutedeLoo", "jlucori", "MathieuAnard", "fabm16", "JanneFI", "kasiko2005", "kalin0x", "TimelessP", "_malcon_", "agentsecateur", "littlemac042", "futex90", "Zapper9", "ITrust_France", "jacko_twit", "hectoromhe", "ticxio", "tlsn0085", "n0wl1", "Zwordi", "lostinsecurity", "ArxSys", "SecSavvy", "HadiBoul", "hackconsulting", "Yen0p", "rbidule", "Kuncoro_AdiP", "C4p7ainCh0i", "MasterScrum", "Xoib", "BiDOrD", "ktinoulas", "shenril", "SedonaCyberLink", "Ark_444", "binaryreveal", "walter_kemey", "FMDINFORMATIQUE", "ludorocknroll", "_sygus", "laurenceforaud", "Cyber_yick", "JeanLoupRichet", "WarOnPrivacy", "sriharirajv", "thomdi", "aurl_ro", "_psaria", "DozOv", "sud0man", "zipzap0007", "dum0k", "chrisikermusic", "emmanuel_f_f", "Nbblrr", "EmilioFilipigh", "SepeztDalv", "Unix_XP", "Mo_hand", "jere_mil", "FadelHamza", "barbara_louis_", "MarcLebrun", "patrikryann", "coruble", "LiddoTRiTRi", "mturtle", "NeeKoP", "0xU4EA", "s3clud3r", "drambaldini", "jeancreed1", "_JLeonard", "RJ45HotPlugger", "presentservices", "BSSI_Conseil", "Araneae_", "JKryancho", "hanson4john", "coldshell", "ackrst", "DrWebFrance", "sysdream", "fredmilesi", "GltGvi", "dj0_os", "KickBhack", "yochum", "PatriceAuffret", "Turblog", "comintonline", "ghostelmago", "argoprowler", "hixe33", "PierreBienaime", "amaximciuc", "SRAVANKUTTU1", "AntiMalwares", "paqmanhd", "siri_urz", "bahraini", "metaflows", "tfaujour", "lagrange_m", "shocknsl", "commonexploits", "mynumbersfr", "APPC2", "coolness76", "osospeed", "quentin_ecce", "Numendil", "pci0", "mbriol", "diver_dirt", "t4L", "engelfonseca", "_vin100", "leejacobson_", "set314", "gcheron_", "joselecha", "securityworld", "BradPote", "RocketMkt", "yadlespoir", "SeedNuX", "vkluch", "FabriceSimonet", "talfohrt", "MykolaIlin", "EHackerNews", "EHackerNews", "apauna", "kasimerkan", "WhiteKnight32KS", "Evild3ad79", "penpyt", "whitehorse420", "0xVK", "Sug4r7", "UtuhWibowo", "lamoustache", "_goh", "valdesjo77", "gleborek", "Hi_T_ch", "B2bEnfinity", "megra_", "dankar10", "soccermar", "alvarado69", "Spartition", "Matthi3uTr", "yoogihoo", "Veracode", "it4sec", "kylemaxwell", "abriancea", "lupotx", "PhishLuvR", "AurelieSweden", "tsl0", "inkystitch", "DimitriDruelle", "fambaer65", "Queseguridad", "Infosec_skills", "Fabiothebest89", "CabinetB", "tacticalflex", "r0bertmart1nez", "rootkitcn", "SourceFrenchy", "subhashdasyam", "powertool2", "Y_Z_J", "SecurityWire", "fbyme", "ethicalhack3r", "l10nh3x", "arnaud_fontaine", "Murasakiir", "JubertEdouard", "CharlotteEBetts", "Di0Sasm", "Erebuss", "ibenot", "r1chev", "snake97200", "imrudyo", "MarioHarjac", "psorbes", "fredack76", "SecurityTube", "cyberguerre", "Korben", "jryan2004", "jeremy_richard", "Robert_Franko", "WasatchIT", "BradleyK_Baker", "JoseNFranklin", "JohnF_Martin", "jbfavre", "Top_Discount", "OtaLock", "0x1983", "shadd0r", "FabienSoyez", "EskenziFR", "robertthalheim", "ejobbycom", "_Tr00ps", "helmirais", "ArmandILeedom", "Harry_Etheridge", "neurodeath", "spaceolive", "Serianox_", "BestITNews", "mtanji", "NicolasJaume", "jabberd", "KyrusTech", "passivepenteste", "bouyguestelecom", "nono2357", "jcran", "Milodios", "outsourcemag", "kaleidoscoflood", "xiarch", "GJ_Edwards", "RS_oliver", "maxime_tz", "JA25000", "cymbiozrp", "Marruecos_Maroc", "fishnet_sec", "armitagej", "J_simpsonCom", "StevenJustis", "ISSA_France", "kasperskyfrance", "bigz_math", "Peterc_Jones", "hfloch", "HaDeSss", "ElMhaydi", "Cyberprotect", "jrfrydman", "tomchop_", "TravisCornell", "Xartrick", "minml5e", "zast57", "Tenkin1", "aahm", "randyLkinyon", "NetSecurityTech", "ssiegl_", "f_caproni", "RobertSchimke", "WalliserQueen", "caiet4n", "Barbayellow", "defane", "pafsec", "LongoJP", "JasmyneRoze", "osterbergmedina", "khossen", "TwitSecs", "f4kkir", "action09", "Taron__", "holyhot1", "han0tt", "SecurityCourse1", "_nmrdn", "DI_Forensics", "vap0rx", "lilojulien", "ouroboros75", "schippe", "ak1010", "fabien_duchene", "rbee33", "onialex64", "eero", "ScreamingByte", "prasecure991", "pentestit", "flgy", "laith_satari", "waleedassar", "aanval", "vfulco", "4and6", "deados", "EtienneReith", "negotrucky", "freesherpa", "moohtwo", "initbrain", "rodrigobarreir", "PunaiseLit", "Malwarebytes", "aristote", "jennjgil", "RonGula", "_Debaser_", "andersonmvd", "Eeleco", "_plo_", "56_fj", "EpoSecure", "v0ld4m0rt", "tgouverneur", "DebStuben", "G4N4P4T1", "Yxyon", "_bratik", "Diacquenod", "ABC_Pro", "vhutsebaut", "ximepa_", "virtualabs", "irixbox", "Korsakoff1", "tricaud", "TheDataBreach", "Herdir", "fbardea", "oduquesne", "thecyberseb", "krzywix", "Nomade91", "just_dou_it", "cizmarl", "brix666Canadian", "Paul_da_Silva", "xme", "fAiLrImSiOnN", "l0phty", "rssil", "thomasfld", "cwroblew", "PavelDFIR", "Aryaa__", "Patchidem", "EightPaff", "N_oRmE", "barbchh", "mcherifi", "NWsecure", "crowley_eoin", "0x5eb", "ElChinzo", "k_sec", "MarkMcRSA", "rattle1337", "a804046a", "botnets_fr", "garfieldtux", "Cubox_", "MaKyOtOx", "AccelOps", "adula", "bsdaemon", "toastyguy", "kongo_86", "Fly1ngwolf", "TigzyRK", "bartblaze", "syed_khaled", "jhadjadj", "crazyws", "silentjiro", "y0m", "kapitanluffy", "lcheylus", "aNaoy", "KelvinLomboy", "Mandiant", "ProjectxInfosec", "danielvx", "Tris_Acatrinei", "kasperskyuk", "noktec", "SalesNovice", "Tishrom", "FaudraitSavoir", "sravea", "bricolobob", "_saadk", "calebbarlow", "balabit", "spamzi", "Tif0x", "quantm1366", "nyusu_fr", "DFIRob", "SigBister", "MehdiElectron", "saracaul", "emi_castro", "markloisea", "sanguinarius_Bt", "briankrebs", "ubersec", "nmatte90", "k3rn3linux", "jibranilyas", "alienvault", "harunaydnlogl", "lhausermann", "WorldWatchWeb", "jamesejr7", "kafeine", "razaina", "Koios53b", "AlliaCERT", "tbmdow", "SamTeffa", "veeeeep", "_sinn3r", "dalerapp", "Ylujion", "adesnos", "Lapeluche", "eveherna", "qgrosperrin", "udgover", "MonaZegai", "kutioo", "UrSecFailed", "gcaesar", "Steve___Wood", "ForensicDocExam", "wopot", "sibiace_project", "cyberwar", "sandrogauci", "amarjitinfo", "fromlidje", "iseezeroday", "gallypette", "The_Silenced", "JGoumet", "SecMash", "never_crack", "sioban44", "0xerror", "josoudsen", "SensiGuard", "jollyroger1337", "nigroeneveld", "geocoulouvrat", "sysnetpro", "kriptus_com", "SmartInfoSec", "HackingDojo", "Bertr4nd", "Javiover", "TaPiOn", "reboot_film", "pryerIR", "savagejen", "Doethwal", "i_m_ca", "Hexacorn", "JeromeSoyer", "wallixcom", "vanovb", "POuranos", "l_ballarin", "lestutosdenico", "nicklasto", "Ballajack", "mks10110", "wireheadlance", "C_Obs", "E_0_F", "k3170Makan", "vltor338", "T1B0", "iunary", "dvdhein", "braor", "sunblate", "SeguridadMartin", "CQCloud", "bri4nmitchell", "DanGarrett97", "vietwow", "isvoc", "zsecunix", "gertrewd", "alexandriavjrom", "nathimog", "Chongelong", "s0tet", "Psykotixx", "Karion_", "sinbadsale", "nowwz", "yodresh", "BlackyNay", "0xBADB", "yeec_online", "paco_", "pretorienx", "TrC_Coder", "creativeoNet", "Fou1nard", "7h3rAm", "ChanoyuComptoir", "essachin", "Stonesoft_FR", "caltar", "Panda_Security", "tkolsto", "firejoke", "R1secure", "c_APT_ure", "DavidGueluy", "unohope", "aspina", "CodeCurmudgeon", "H_Miser", "eromang", "arbornetworks", "gl707", "sundarnut", "iNem0o", "agevaudan", "YungaPalatino", "D3l3t3m3", "shafigullin", "camenal", "AskDavidChalk", "cthashimoto", "enatheme", "zandor13", "SeTx_X", "loosewire", "itech_summit", "iMHLv2", "aaSSfxxx", "Actualeet", "rmkml", "TeamSHATTER", "Asmaidovna", "JobProd_DOTNET", "4n6s_mc", "Geeko_forensic", "ericfreyss", "aboutsecurity", "Sourcefire", "treyka", "o0_lolwut_0o", "meikk", "dphrag", "patrickmcdowell", "JC_DrZoS", "chiehwenyang", "DudleySec", "buffer_x90", "halilozturkci", "badibouzi", "vgfeit", "SafeNetFR", "Ivan_Portilla", "megatr0nz", "slvrkl", "binsleuth", "james__baud", "HoffmannMich", "lreerl", "kyprizel", "kabel", "Jipe_", "PhysicalDrive0", "g4l4drim", "fschifilliti", "htbridge", "ebordac", "r00tbsd", "zesquale", "hardik05", "dragosr", "wimremes", "legna29A", "_calcman_", "yanisto", "Yayer", "C134nSw33p", "thgkr", "Hydraze", "I_Fagan", "TechBrunchFR", "andreglenzer", "rafi0t", "PagedeGeek", "stackOver80", "Creativosred", "hss4337", "Hat_Hacker", "ITVulnerability", "Redscan_Ltd", "BerSecLand", "p4r4n0id_il", "infiltrandome", "k_sOSe", "DCITA", "apektas", "twatter__", "ximad", "Thaolia", "stacybre", "Shiftreduce", "domisite", "CaMs2207", "halsten", "StrategicSec", "mrdaimo", "Sharp_Design", "gon_aa", "LostInRetrospec", "mrkoot", "SugeKnight4", "danhaagman", "deobfuscated", "AlanPhillips7", "diocyde", "spatcheso", "Xylit0l", "DustySTS", "g30rg3_x", "cbriguet", "_CLX", "DrM_fr", "ponez", "Kizerv", "yenos", "tactika", "Nelson_Thornes", "chri6_", "UnderNews_fr", "selectrealsec", "virusstopper", "chr1x", "follc", "rackta", "keysec", "TwisterAV", "w4rl0ck_d0wn", "agololobov", "2xyo", "ghostie_", "isguyra", "AFromVancouver", "malphx", "stackghost", "JPBICHARD", "NESCOtweet", "csananes", "fredraynal", "f4m0usb34u7y", "theAlfred", "x0rz", "zentaknet", "virtualite", "ITRCSD", "Yahir_Ponce", "eag1e5", "haxorthematrix", "switchingtoguns", "alchemist16", "DidierStevens", "ChristiaanBeek", "ibou9", "azerty728", "Yann2192", "insecurebyte", "MAn0kS", "Jolly", "googijh", "305Vic", "NKCSS", "0security", "0x58", "PR4GM4", "TyphoidMarty", "HTCIA", "jasc22", "knowckers", "mollysmithjj", "thE_iNviNciblE0", "kenneth_aa", "neox_fx", "thesmallbrother", "rebelk0de", "RomainMonatte", "WawaSeb", "unk0unk0", "trolldbois", "StopMalvertisin", "kakroo", "sebastiendamaye", "kjswick", "curqq", "KDPryor", "_x13", "7rl", "danphilpott", "mortensl", "extraexploit", "Ideas4WEB", "ZtoKER", "inuk_x", "sphackr", "0xjudd", "issuemakerslab", "FredLB", "vanjasvajcer", "MarioVilas", "sm0k_", "cowreth", "ncaproni", "cillianhogan", "dnoiz1", "0xroot", "ZenkSecurity", "threatpost", "ntsec2015", "nicolasbrulez", "PascalBrulez", "steevebarbea", "revskills", "unpacker", "sempersecurus", "jz__", "holesec", "JokFP", "Reversing4", "ekse0x", "the_s41nt", "DumpAnalysis", "ozamt", "Darkstack", "y0ug", "MatToufout", "matrosov", "crai", "aszy", "CERTXMCO", "agent_23_", "shydemeanor", "Aarklendoia", "angelodellaera", "OhItsIan", "NonAuxHausses", "ancrisso", "smaciani", "fdebailleul", "zohea", "nicolaslegland", "madgraph_ch", "Archlance", "Hainatoa", "_cuttygirl", "NicolasThomas", "reseau_unamipro", "widgetbooster", "lareponsed", "seb_godard", "ahmedfatmi", "kavekadmfr", "gitedemontagne", "rizzrcom", "Stefko001", "webpositif", "LucBernouin", "MangasTv", "FGRibrea", "marinemarchande", "twittconsultant", "Evangenieur", "greg32885", "hynzowebblog", "Twitchaiev", "SweatBabySweat_", "ovaxio", "PierreTran", "Mariegaraud", "cafesfrance", "populationdata", "Summy46", "sirchamallow1", "jpelie", "Technidog", "ju_lie", "blackwarrior", "cberhault", "julierobert", "sirchamallow", "xhark", "ga3lle", "Zebrure", "vitujc", "littlethom23", "DJKweezes","phantomJs","xss poc","xss mining","nethack","SSDLC","mongodb","@docker","security enthousiast","malware analyst","misp","grehack","bug bounty","security ninja","radare2","crime numérique","recurity labs","floss","osint","dfir","safe cracker","maltego","botconf","spot the feds","cell jamming","cell phone jamming","cell phone hack","scareware","PanguTeam","@McGrewSecurity","packetstormsecurity","input validation error","GhostShell","hoax","hoaxbuster","bugmenot","carbanak gang",".lua","VBS","unix","makefile","cmake","alice bob","un rootkit","linus torvalds","pirate box","template injection","ieee-security.org","internet archive","hacks archive","netcat","rsa securid","windows worm","mac worm","linux worm","lionsec","whonix","sudo ","shmoocon","ethereum","bootkit","backdooring","selling credentials","surveillance platform","Dns reflection amplification","CVE-2016","StressLinux","tomsrtbt","Tiny SliTaz","RIMiRadio","Nuclinux","NASLite","Linux Router Project","HVLinux","HAL91","Freesco","floppyfw","Coyote Linux","xPUD","VectorLinux","Toutankinux","Feather Linux","Embedded Debian","Chromium OS","BunsenLabs","antiX","Zorin OS","Zeroshell","Zenwalk","Zentyal","YunoHost","Ylmf OS","crypto entropy","Xubuntu","Xandros","Xange linux","WinLinux","VidaLinux","Ulteo","TurboLinux","Trustix","Trisquel","Trinux","TopologiLinux","Tiny Core Linux","SteamOS","SolusOS","SME Server","SliTaz GNU","Slax linux","Sabayon Linux","Rxart","ROSA linux","Puppy Linux","PrimTux","rom hack","Platypux","PinguyOS","Pardus","Parabola GNU","NuTyX","NUbuntu","Netrunner OS","Musix GNU","Maemo","MEPIS","Lunar Linux","Lubuntu","Linux Mint","Linux From Scratch","Linux xp","LinuxConsole","play on linux","linux wine","linux ps2","Linutop OS","Linspire","Kubuntu","Kororaa","Knoppix","Kanotix","KaOS linux","Kali linux","Kaella","IPCop","Hybryde Linux","HandyLinux","GoboLinux","Goblinx","Gnoppix","gNewSense","GeeXboX","Funtoo","Frugalware","Freespire","Freesco","Free-EOS","Foresight Linux","Flonix","fli4l","Elive","elementary OS","EduLinux","Edubuntu","DoudouLinux","Dreamlinux","Dragora GNU","DidJiX","Demudi Linux","Damn Vulnerable Linux","Damn Small Linux","Cubuntu","CrunchBang","Coyote Linux","Chakra","CentOS","Castle Linux","Calculate Linux","Caixa Mágica","CAELinux","BLAG 140","Bodhi Linux","BasicLinux","Baltix","BackTrack","Aurox","Aurox Live","Augustux","ASRI Edu","Asianux","Ark Linux","ArchBang","Aptosid","APODIO","Peanut Linux","CLinuxOS","PCLinuxOS","Mageia","Mandriva","Manjaro","openSUSE","Arch Linux","SUSE","Slackware","fedora","SSNs","gentoo","LSASS","bettercap","chiffrement","xml injection","method handles","alphabay","Java message service","netsec","server down","net neutrality","freebsd","debian","script-based","bugtrack","atilla.org","HackQuest.com","h@x0r","slyfx","cyberarmy","mod-x.co.uk","alph4net.free.fr","cyberjihad","globalsecuritymag.fr","Instant-Hack","dothazard.com","intrusio.fr","Tobozo","n-pn.fr","Ensimag hacking team","febel.fr","zataz","chan irc hack","forum de hack","hackateam.com","0x0ff","nuit du hack","hackademics","Honeynet","hackers convention","hacker contest","hacking contest","United Hackers Army","CTFTIME","EXPLOIT EXERCISES","pwn0.com","pwn0bots","REVERSING.KR","MICROCORRUPTION","SMASHTHESTACK","netgarage.org","pwnable.kr","OVERTHEWIRE","CTF365","hackerearth.com","seclists.org","the-hackfest.com","ctftime.org","itknowledgeexchange","hackingchinese.com","hacking-lab.com","insomnihack.ch","amanhardikar.com","dragonhacks.io","bases-hacking.org","www.trythis0ne.com","hackbbs.org","pen-testing.sans.org","codeforamerica.org","onecoincloud.eu","wechall.net","holidayhackchallenge.com","tunnelsup.com","root-me.org","canyouhack.it","2600","canyouhack.us","SlaveHack","Ethical Hacker Network","HellBound Hackers","devops","webgoat","Vicnum","The Butterfly Security Project","Security Shepherd","Mutillidae","McAfee HacMe","InsecureWebApp","igoat","Google Gruyere","Game of Hacks","exploitme","DVWA","Untrusted input","broken crypto","server side","Client Side Injection","Runtime Manipulation","Jailbreak Detection","third party libraries","Extension Vulnerabilities","DVIA","bWAPP","OWASP Bricks","EnigmaGroup","Moth hack","BodgeIt Store","keygen","haxor","Hackxor","HackThis!!","SlaveHack","Try2Hack","Highly Efficient Low Level Code","cloud hack","Hack Yourself First","Micro Contest","LOST Chall","Newbie Contest","Rankk","Hacker.org","Mibs Challenges","Hack This Site","Net Force","BrainQuest","InfoMirmo","Yashira","W3Challs","Root Me","Le Big Challenge","alphanet","Fatetek Challenges","Mod x","Hax.Tor","Bright Shadows","Dare Your Mind","RingZero Team","Mudge","Boris Floricic","Anakata","Richard Stallman","Dmitry Sklyarov","Roman Seleznev","Oxblood Ruffin","Leonard Rose","DilDog","Kevin Poulsen","homebrew","Knight Lightning","Dennis Moran","Robert Tappan Morris","Hector Monsegur","Gary Mckinnon","Fyodor hacker","Lord Digital","hagbard","Joybubbles","geohot","Acidus","Guccifer","nag screen","Bruce Fancher","Nahshon Even-Chaim","John Draper","Captain Crunch","RBCP","Loyd Blankenship","The Mentor","Mendax","Tflow","ioerror","Kayla","Phiber Optik","internet underground","linux underground","mac underground","Xbox Underground","YIPL","UGNazi","The Unknowns hack","Teso","TeslaTeam","RedHack","RedHack","PHIRM","NCPH","milw0rm","Masters of Deception","Mazafaka","Legion of Doom","Lizard Squad,","Level Seven","L0pht","Honker Union","Hackweiser","goatsec","globalHell","Equation Group","Global kOS","DawgPound","DERP","Decocidio","CyberVor","Dark0de","Cult of the Dead Cow","Croatian Revolution Hackers","Cicada 3301,","Chaos Computer Club","FinnSec Security","414s","Group5","netscape","pwnie awards","security researcher","BHUSA","pgp","encrypted mail","secure mail server","vBulletin","Apache Tomcat","Coldfusion","ASP.NET","Retina Report","Nessus Scan Report","SnortSnarf","mirc","LOGREP","Apache::Status","SQLiteManager","Tobias Oetiker","sets mode","wwwstat","Generated by phpSystem","mysql dump","phpWebMail","gnatsweb.pl","webedit","inurl:/","cgi-bin","Citrix","CVE","alice bot","sea hacker","chatter bot","automagically","Syrian Electronic Army","LulzSec","gray hat","Distributed denial of service","Denial of service","compiler","hook cheat","TWEAK cheat","trainer cheat","cracking team","DAEMON","CRLF","COMM MODE","CANONICAL","Ethical Hacking","Skidz","ascii art","blue hat ","defaced","Dictionary Attack","doxing tool","DOX tool","FUD","Fully undetectable","grey hat","IP Grabbing","backorifice","LOIC anonymous","Rainbow Table","rat trojan","Remote Administration Tool","ring3","ring2","ring0","viri","warez","vps","worm malware","turing test","sysadmin","SaaS","stack buffer overflow","CA cert","Hardware vulnerability","physical backdoor","Vuln:","Vuln","adblocker","Exploit framework","crypto party","ssh","Passphrase","Linux Distro","RFC","Hardcoded","hackintosh","Os X","P2P","cloud-based","Oracle java","IT guy","Encrypted Chat","VmWare","cyber police","AdGholas","malvertising","hadopi","cnil","golang","hacked by","piratage","Postgresql","Julian Assange","DNC","GNU","QRLJacking","kevin mitnick","csrf exploit","session hijack","darkweb",".onion","wikileaks","wlan","Wireless Local Area Network","wardriving","Wireless Access Point","wep","cyber security","Wpa2","blackhat","Shellcode","vpn","Virtual Machine","sandboxing","crypto currency","Full Disclosure","Tunneling","Gps spoofing","untrusted Certificate","ransomware","Trojan Horse","Transport Layer Security","Triple DES","Assembly language","Real hack","real programmmer","RFC","crack me","hack me","true hacker","security traffic Analysis","Tracking Cookie","tampered data","bluetooth crack","data breach","script kiddie","brute force","Symmetric Key","Surrogate Access","Raspberry pi","Arduino","Steganography","Spyware","mail bombing","jailbreak","YesCard","Skimming","Phreaking","cracking","malloc","data Sensitivity","Python exploit","ruby hack","security kernel","C++ exploit","reverse Engineering","Security Engineering","turbo pascal","ssl","hacking tool","php vulnerability","hackervoice","worms variant","DNS","Scatternet","cheval de troie","javascript exploit","Sandboxing","Rootkit","Bash script","windbg","rogue device","ollydbg","assembler code","ip spoofing","Rijndael","apache vulnerability","darkdao","repository","shodan","scammers","critical vulnerability","code injection","ICBM address","RFID security","paiement sans contact","RFID protocol","Radio Frequency Identification","Gbd ida","private key","pseudorandom","Proxy Agent","tor network","vpn open source","memory corruption","proxy list","proxychain","la quadrature du net","heap exploitation","stack cookies","Fuzzing","integer overflow","hackathon","api key","1337","Social-Engeneering Toolkit","port scanner","bluetooth protocol","bluetooth security","nmap","port scanning","Payload","Framework","port knocking","wireless attack","log files","router vulnerability","packet sniffer","phpmyadmin hack","open source","phbb hack","password attack","penetration technique","browser exploit","warberrypi ","wordpress exploit","binary memory","byod","router exploit","Cookie stuffing","Windows stack overflow","shell exploit","message digest","Cryptosystem","reverse shell","MitM","hardware keylogger","malicious code","hack team","mygot","myg0t","data intercept","gps hack","meterpreter","segfault","pastejacking","network takeover","Sphear phishing","key logger","key escrow","Kerberos","flood attack","go language","depassement de tampon","irc hack","ipsec","exec","system intrusion","ipv6","ipv4","Fake update","packet injection","bruteforcer","android vulnerability","linux vulnerability","ios vulnerability","artificial intelligence","windows vulnerability","main loop","hello world","audit tool","armitage","grep","disk encryption","frequency hopping","forward cipher","shitware","Firefox vulnerability","bypass firewall","file encryption","ssl tls","extranet","domaine name permutation","ftp security","fingerprint tool","rssi","visual analysis tool","end to end encryption","robots.txt","encrypted network","tinfoleak","infosec","encoding","voip security","EOF","electronic signature","egress filtering","eavesdropping","DEADBEEF","konami code","dmz","wireless scanner","decrypt","@th3j3st3r","wireless hack","data security","data integrity","network mapper","data encryption standard","data dump","incident response tool","defcon","cyber attack","web spider","cryptology","hash function","cryptographic","cryptanalysis","command injection","tool assisted speedrun","credential","cover coding","xref","key generation","network exploitation","network attack","local pentest","COMSEC","CVS","common vulnerabilities","internet of things","misconfiguration","collision hash","internet of shit","cloud computing","clear text","checksum","bytes","joomla vulnerability","sqli","data leak","users passwords","blackbox hack","IRC network","Critical patch","playstation jailbreak","banner grabbing","xbox jailbreak","backdoor infosec","hexadecimal","privacy windows","authentication token","authentication protocol","audit framework","open source security tool","file signature","BSides","antispyware","chelsea manning","QR code infosec","anonymous","advanced persistent threats","pirate bay","advanced encryption standard","admin account","add-on security","ad hoc network","hacked site","defaced","bypass login","cryptography","phishing infosec","honeypot","hacking","ddos","malware","rfid","patch flaw","SocialEngineering","0day","cross site scripting","cyber security","install backdoor","forensic","blind sql injection","local file inclusion","privilege escalation","hacker attack","request forgery","metasploit","password","sql injection","privilege elevation","drupal vulnerability","chinese hacker","penetration testing","header injection","pentest","man in the middle","man in the browser","remote access","java security","buffer overflow","keylog","nuke script","darknet","russian hacker","remote exploit","israel hack","ransomware","trojan","botnet","snowden","nsa","blackhat","whitehat","hacktivist","printer exploit"]

Keywordsave = Keywords

random.shuffle(Keywords)

Following = ["Joorem", "scapy3k", "m00zh33", "asmistruth", "ekeefe3457", "caleb_fenton", "iHeartMalware", "nakincharly", "jduck", "ivspiridonov", "pxlsec", "justinsteven", "ArnaudDlms", "msmakhlouf", "mistamark", "catalyst256", "Flo354", "jaime_parada", "FestChemFaisant", "jetbrains", "boolaz", "mattblaze", "valorcz", "scrscanada", "benoit_ampea", "leroiborgne", "TomRagFR", "guedo", "Mo7sen", "matt_gourd", "pyconfr", "drefanzor", "5683Monkey", "Mina_Vidar", "onabortnik", "AndyDeweirt", "Cryptie_", "pmdscully", "coldshell", "acervoise", "2Dennis", "jamespugjones", "clementoudot", "roidelapluie", "robertfliege", "maartenvhb", "hm1ch", "AndyWilliamsCEO", "woanware", "Info_Assure", "Cryptomeorg", "jjtmlat", "mmu_man", "theglongo", "laure_delisle", "kiirtanrosario", "carelvanrooyen", "MarioAudet", "kalyparker", "hgabignon", "Mekhalleh", "thomassiebert", "brendonfeeley", "netrusion", "alliesuz", "Iglocska", "kittychix", "ErrataRob", "addelindh", "REhints", "USCERT_gov", "JeromeTripia", "akochkov", "sroberts", "__eth0", "DavidJBianco", "CYINT_dude", "swannysec", "fumfel", "switchcert", "GovCERT_CH", "ochsenmeier", "infosecaddict", "s0nk3y", "certbund", "stefj", "Creased_", "ISC2_Las_Vegas", "nullandnull", "h3x2b", "LockyBOT", "ShramanACK", "GrehackConf", "espie_openbsd", "chicagoben", "ringo_ring", "theosint", "paulRchds", "octal", "d_lanm", "ruhrsec", "dSebastien", "SchwaigBag", "ForensicMaggie", "unicorn_engine", "keystone_engine", "jmariocadavid", "brentmdev", "SwiftOnSecurity", "wallofsheep", "vartraghan", "ChristianHeimes", "bbaskin", "ddouhine", "jvitard", "AndreGironda", "noetite", "dafthack", "sneakdotberlin", "MISPProject", "freddy1876", "ydklijnsma", "B_Stivalet", "M4ximeOlivier", "DilTown", "jeroenvda", "nguvin", "CertSNCF", "darrellbohatec", "julienmaladrie", "skywodd", "WikiJM", "sneakymonk3y", "cool_breeze26", "antonivanovm", "Conducteur_RER", "LPA_infogerance", "Blueelvis_RoXXX", "cyb3rops", "smaret", "amaelle_g", "cnoanalysis", "ovidiug", "AZobec", "evematringe", "kvandenbrande", "in_threat", "davidbizeul", "benkow_", "py3k", "bountyfactoryio", "ciunderhill", "matthew_d_green", "elibendersky", "g0ul4g", "randal_olson", "slabetoule", "bettercap", "goldshtn", "VXShare", "futex90", "evilsocket", "ZIMPERIUM", "MalwareTechBlog", "X_Cli", "seblw", "CobbleAndFrame", "KyanKhoFan", "letsencrypt", "yaniv_see", "Palamida_Inc", "geek_king", "FLesueur", "lexoyo", "pwissenlit", "odzhancode", "_g3nuin3", "obilodea", "bambenek", "0xf4b", "tbarabosch", "mgschrenk", "RMLLsec16", "Bugcrowd", "_bobbysmalls", "anoufriev", "Pat_Ventuzelo", "ITSecX", "teoseller", "bradarndt", "cl0udmaker", "herrcore", "cudeso", "lignesNetU_SNCF", "iansus", "mboman", "sqlinjwiki", "gregflanagan22", "tiix_wtf", "metaconflict", "nlavielle", "trailofbits", "KraftCERT", "ClausHoumann", "RobertoQuinones", "Unixity", "unmanarc", "JulienPorschen", "fel1x", "WadeAlcorn", "EricRZimmerman", "L4g4", "maciekkotowicz", "aojald", "AndreasRades", "pidgeyL", "ClsHackBlog", "iseezeroday", "cmatthewbrooks", "mynameisv_", "shenril", "FSecure_IoT", "scotthworth", "YoannFranco", "FredHilbert", "DTCyberSec", "valentijn", "jiboutin", "arangodb", "yprez", "gN3mes1s", "flcarbone", "pello", "julientouche", "joancalvet", "lehtior2", "SchwarzonSec", "docker", "MongoDB", "ElasticNews", "daniel_bilar", "pentest_swissky", "josephzho", "williballenthin", "FabienMarin", "tais9", "1o57", "QubesOS", "Zerodium", "mrjmad", "iSECPartners", "ioCassie", "sylvainbruyere", "PyBaltimore", "jms_dot_py", "rrogier", "robtlee", "volatility", "XTaran", "actudefense", "sleuthkit", "0x4n6", "moong1ider", "hns_platform", "amicaross", "iotcert", "ckyvra", "CORELANSL", "dzogrim", "0xygate", "Canonical", "ubunt", "ubuntucloud", "tsouvignet", "MalwareMustDie", "sdkddk", "sehque", "asdfg232323x", "Master_of_OSINT", "_Stroumph", "lopessecurity", "DebeurePatrice", "FredericJacobs", "Nima_Nikjoo", "thierryzoller", "MarieGMoe", "MS_Ignite", "EC3Europol", "smllmp", "moyix", "ENCS_Julien", "decalage2", "a_de_pasquale", "PhilippePotin", "philippeveys", "EuropeanSeC2015", "Vircom_Inc", "stRiksVindicta", "_GRRegg", "doegox", "XipiterSec", "ikravets", "Paulaumas", "MissMooc", "tacticalmaid", "cloudgravity", "_haplo__", "PyViv", "augouard", "airpair", "UKOSINT", "jusafing", "litalasher", "TestingSaaS", "SiliconArmada", "ILLUMINATEDBE", "ryan_liang", "Python_Agent", "lepicerienum", "cybersecscar", "Linschn", "KaganKongar", "brian_warehime", "Smarttech01", "Kym_Possible", "papygeek", "etiennelb", "pvergain", "cybereason", "MAAWG", "R1tch1e_", "Fast_IR", "StratosphereIPS", "JusticeRage", "stephaneguillon", "Ahugla", "DigiFoRRensics", "ywilien", "4bestsecurity", "Data88Geek", "ptit_pigeon", "DirtNeMeSiA", "yararules", "PatriceAuffret", "KirstyM_SANS", "XavierGorce", "CommitStrip", "HarlinAtWork", "DanbecBeck", "moxie", "hut8uk", "jean_sylvain", "pierre_alonso", "HECFBlog", "CyberWarfaRRe", "pythontrending", "PythonArsenal", "wirehead2501", "theintercept", "loot_myself", "fbOpenSource", "dcuthbert", "0wosk", "sim0nx", "djm6809", "d4rw1nk5", "_JLeonard", "ge0__", "hackingteam", "pix", "ClaireNaudeix", "NuHarbor", "42wim", "NRabrenovic", "SunnyWear", "tuxedo_ha", "nlt56lorient", "OXITS", "hacks4pancakes", "OrientDB", "KayleighB_SANS", "David_RAM0S", "hack3core", "infsec", "citizenlab", "jasonish", "MyTechCommunity", "CorsaireHarlock", "comptoirsec", "SANSEMEA", "monkeylearn", "cecyf_coriin", "spacerog", "jack_daniel", "StaceyBanks", "ihackedwhat", "doar_e", "anthonykasza", "pstirparo", "xorred", "kartoch", "F_kZ_", "Damian_Zelek", "mrozieres", "FirefoxNightly", "enigma0x3", "NCSCgov", "fasm3837", "AbouDjaffar", "Neur0z0ne", "A_H_Carpenter", "bcrypt", "Place_Beauva", "MathildeLBJ", "Charlie_Hebdo_", "skydge", "ceprevost", "s3cdev", "ncrocfer", "gcouprie", "cedoxX", "spamhaus", "omriher", "robbyfux", "_sodaa_", "SecEvangelism", "bestitsource", "Brett_Shavers", "lumisec", "HovikYerevan", "securitybrew", "MarkDiStef", "AndreaBarisani", "triflejs", "Andrew___Morris", "redteamsblog", "Risk_Cambridge", "Bry_Campbell", "sylvander", "marianmerritt", "pkalnai", "ErsatzAusDirect", "kar1nekks", "diodesign", "MaartenVDantzig", "Loria_Nancy", "julloa", "TiNico22", "N1aKan", "HorusSec", "2kdei", "Melusine_2", "bornot_t", "franceortelli", "v1nc3re", "SHG_Nackt", "WebBreacher", "chrisnoisel", "WEareTROOPERS", "dcauquil", "o0tAd0o", "DynResearch", "ZeroNights", "Burp_Suite", "GDataSoftwareAG", "mgualtieri", "Robert4787", "mjbroekman", "Le_Loop", "catchthewhistle", "m_c_scappa", "4n68r", "pymnts", "tryolabs", "yrougy", "NickInfoSec", "EiQNetworks", "FuturistGirl", "GI_Steve", "pr4jwal", "wpawlikowski", "Reversity", "repmovsb", "matthias_kaiser", "patchguard", "Cyber_FR", "AntiBotnet", "AntibotFR", "deresz666", "virtkick", "r00t0vi4", "Dusseul", "dysoco", "randileeharper", "unix_root", "johanneslondon", "BretPh0t0n", "nanderoo", "Maijin212", "cortesi", "slashdevsda", "DavidLWaterson", "ColasV1", "Yen0p", "Newnioux", "lorenzo2472", "presentservices", "piotrkijewski", "TextMining_r", "brodzfr", "adriengnt", "Whitey_chan", "MrsRel1k", "ElcomSoft", "FioraAeterna", "TordueGniale", "AquaZirius", "lezero1", "DhiaLite", "KnockItOff", "alexcpsec", "dhubbard858", "miliekooky", "feedbrain", "mrbarrett", "el_killerdwarf", "bethlogic", "_r04ch_", "Silou_Atien", "Bobetman", "GirlCodeAPage", "jeromesaiz", "selil", "fumeursdepipe", "pipegazette", "accentsoft", "Zekah", "iamevltwin", "sarahjeong", "Joh4nn_", "dckovar", "eldracote", "SecureHunterAM", "OPSWAT", "casinthecloud", "CodeAndSec", "MontagnierP", "ArchC0N", "raffaelmarty", "jocondeparodie", "natashenka", "Suricata_IDS", "rootkovska", "imrim", "aurelsec", "melo_meli", "Pdgbailey", "TheRealSpaf", "Pe_CERT", "HaxoGreen", "KevTheHermit", "nevilleadaniels", "tuxpanik", "kmkz_security", "HackSpark", "d0znpp", "CamilleRoux", "IOCBucketFeed", "FeministPics", "nolimitsec", "ChristopheH00", "OliCass", "konstanta7691", "zenithar", "pevma", "zackhimself", "ReverserRaman", "DavidDoret", "nsmfoo", "lisachwinter", "abnev", "MichalKoczwara", "__ner0", "perefouras", "SandG_", "cases_l", "maradydd", "dguido", "KLNikita", "Voksanaev_OSINT", "SARCWV", "theosintguy", "mompontet", "stachli", "t4rtine", "faittus", "node5", "malware_traffic", "marinivezic", "qb_irma", "r1hamon", "queenwaldorff", "PietroDelsante", "DavisSec", "jwgoerlich", "OpenCryptoAudit", "Daniel_Lerch", "CloudFlare", "LEACSOPHIE", "HuyTDo", "annatroberg", "Cephurs", "noog", "robnavrey", "Mumr1k", "ruchequiditoui", "Secure4Me", "Ekimvontrier", "Game0verFlow", "the_jam", "emd3l", "EdwardTufte", "AlineKav", "maximilianhils", "FraneHa", "Malwared_", "DoctorNoFI", "miguelraulb", "phretor", "JeromeNotin", "NS_Radio", "andreasdotorg", "StamusN", "cherepanov74", "0x0000EBFE", "XI_Research", "mobinja", "bigezy_", "IForkin", "maaax78", "funoverip", "dijoritsec", "raistolo", "__dxx__", "nirouviere", "attrc", "MathildeLemee", "agnes_crepet", "TuxDePoinsisse", "securesearcher", "novirusthanks", "Armelle_b", "FradiFrad", "binitamshah", "MalwareSigs", "neelmehta", "mbedtls", "BSeeing", "SSTIC2014", "SteveGarf", "CERT_UK", "EKwatcher", "gmillard", "bizcom", "levigundert", "gbozic", "SecViews", "_Sec_C", "katsudon45", "MaliciaRogue", "brucedang", "ESET_France", "JanetCSIRT", "cbrocas", "_moloson_", "tim_maliyil", "insitusec", "pvrego", "0xKarimz", "20_cent_", "muller_sec", "LESSYves", "mixIT_lyon", "lazy_daemon", "FliegenEinhorn", "NadAchouiLesage", "dw33z1lP", "gnsivagnanam", "righettod", "northvein", "JershMagersh", "Space_Origin", "kriss_dek", "winSRDF", "Pr1v4t3z0n3", "EMSST_DE", "AbelWike", "_dup_", "Mectoob", "VirginieMartin_", "ThinkTankDiff", "Exploratology", "reedox", "xabean", "evj", "CastermanBD", "PierreSec", "satyanadella", "IrisClasson", "fidh_fr", "Sabine_dA", "ktinoulas", "jmichel_p", "CathCervoni", "FreddyGrey", "windyoona", "nkokkoon", "cndint", "sebast_marseill", "broisy", "cci_forensics", "arnaudsoullie", "devpsc", "ZhengOlivier", "pypi", "lefterispan", "twallutis", "ashk4n", "caromonnot", "verovaleros", "dt_secuinfo", "gnulinuxmag", "ShadyK8em0", "Pcap2Bubbles", "jyria", "Seifreed", "marnickv", "carl_chenet", "f1329a", "CharlotteTicot", "soaj1664ashar", "NemanNadia", "cookworkingFR", "capstone_engine", "savon_noir", "StephCaradec", "mc_naves", "ExoticVPS", "Uneheuredepeine", "efFRONTees", "securityfreax", "inliniac", "aseemjakhar", "pinkflawd", "hugo_glez", "aoighost", "Tinolle1955", "SplunkSec", "_SaxX_", "Kujman5000", "tomsmaily", "corkami", "mkevels", "evacide", "VincentCespedes", "Fred_Mazo", "laurenceforaud", "starbuck3000", "aloria", "Y0no", "UNIQPASS", "siedlmar", "sehnaoui", "0x3e3c", "RichardJWood", "Natsakay", "DamDamOfficial", "canariproject", "ShettyShet", "adamkashdan", "johalbrecht", "Vivet_Lili", "j_schwalb", "snipeyhead", "Ptit_Cheminot", "CommanderKarrie", "martelclem", "RevDrProxy", "w3map", "spydurw3b", "ViolaineDomon", "kfalconspb", "Itsuugo", "Venomanceress", "phn1x", "Mar_Lard", "Trojan7Sec", "mark_ed_doe", "gradetwo", "ccomb", "KitPloit", "cryptopathe", "IsChrisW", "CuriositySec", "SilverSky", "esetglobal", "ohm2013", "PirateOrg", "ubuntufr", "kennethdavid", "mvjanus", "lopu61", "Ibrahimous", "viruswiki", "m0m0lepr0", "DarrelRendell", "CyberSheepdog", "Iznogoud1984", "AdrienneCharmet", "poona_t", "quota_atypique", "ibr4him2011", "EFF", "mikesiko", "KAI2HT003", "hurricanelabs", "B1gGaGa", "hackers_conf", "Ludo_z", "rosemaryb_", "23_BU573DD_23_", "DeepInTheCode", "CatatanSiNovel", "osm_be", "adofo", "moutane", "mageia_org", "MalwareAnalyzer", "MaguiMagoo", "13h15", "tixlegeek", "emapasse", "cceresola", "Hectaman", "RCMelick", "Seczoneco", "mastercruzader", "blaster69270", "EthanCrosse", "tr0p0sphere", "d4v3nu11", "jennymangos", "MmeAPT", "jesperjurcenoks", "ThomasCadene", "CryptoPartyFI", "lifegeek_co", "MacForensicsLab", "alex_kun", "hxteam", "kali_linux_fr", "hugofortier", "xeip1ooBiD", "Minipada", "_fwix_", "ak4t0sh", "_batou_", "simonroses", "vulnexsl", "Joel_Havermans", "AlMahdiALHAZRED", "archoad", "cryptomars", "n_arya0", "KrollOntrack_FR", "juanferocha", "pedrolastiko", "nordicsecconf", "teo_teosha", "PyRed7", "posixmeharder", "tdjfr", "2vanssay", "mamie_supernova", "_8B_", "cryptax", "legumx", "FredGOUTH", "Apprenti_Sage", "FlorentCBD", "r00tapple", "_Quack1", "vm666", "Tinolle", "poulpita", "Netzob", "pollux7", "jordangrossemy", "PConchonnet", "s3clud3r", "mvdevnull", "PirateBoxCamp", "HiDivyansh", "Julllef", "quatrashield", "defloxe", "sekoia_fr", "secuip", "hedgehogsec", "FightCensors_fr", "vprly", "andrewallen", "Nipponconnexion", "IMAD_A", "MattNels", "micheloosterhof", "QuanTechResume", "metabrik", "Guillaume_Lopes", "rommelfs", "rshaker2", "agelastic", "openminded_c", "andymccurdy", "rgacogne", "OlivierRaulin", "Berenseke", "_gabfry_", "GaylordIT", "security_sesha", "secnight", "autobotx2", "ThreatSim", "snare", "davymourier", "Navo_", "K3nnyfr", "infomirmo", "eth0__", "psael", "crdflabs", "8VW", "clabourdette", "openleaders", "okamalo", "valerieCG", "ElMoustache", "calhoun_pat", "Mlle_Krikri", "44CON", "aknova", "courrierinter", "Vinssos", "bugwolf", "TAMannerud", "charlesherring", "codeluux", "quinnnorton", "sensepost", "glennzw", "Bulbeuse", "fygrave", "oleavr", "JeroenLambrecht", "etiennebaudin", "machn1k", "nProtect_Online", "Dejan_Kosutic", "mattst0rey", "randiws", "JamieCaitlin", "Kentsson", "Securityartwork", "walter_kemey", "NUMAparis", "itean", "csec", "ViolentPython", "EasilyMisread", "pierrebrunetti", "SiafuTeam", "Korbik", "_Sn0rkY", "_Kitetoa_", "SylviaBreger", "annso_", "homakov", "altolabs", "tomaszmiklas", "ForensicsDaily", "borjalanseros", "jon1012", "DerbyCon", "1nf0s3cpt", "mozsec", "checkfx", "abarutchev", "maldevel", "HackerHalted", "MduqN", "free_man_", "tracid56", "3615RTEL", "srleks", "CarbonBlack_Inc", "placardobalais", "fradasamar", "digital2real", "Art29C", "Skhaen", "bgpranking", "mmangen", "Izura", "Pot2Miel", "varmapano", "instruder", "iefuzzer", "MinhTrietPT", "0F1F0F1F", "demon117", "Wechmanchris", "Cyberarms", "AlexNogard1", "Diaz__Daniel", "MickaelDorigny", "tranche_d_art", "SilentGob", "bl4sty", "d3b4g", "_c_o_n_t_a_c_t_", "T0mFr33", "p3rry_ornito", "piconbier", "HaileyMcK", "florentsegouin", "nicoladiaz", "MobiquantTech", "esthete", "Ched_", "speugniez", "Maxou56800", "mydeliriumz", "thinkofriver", "_RC4_", "malwr", "shutdown76", "loxiran_", "kaiserhelin", "Wagabow", "PhillipDeVille1", "bdnewsnet", "binaryz0ne", "Bitchcraftx", "HackSysTeam", "monachollet", "BenoitMaudet", "dj_tassilo", "0xcd80", "Jl_N_", "AbelRossignol", "r0mda", "Xst3nZ", "martin_leni", "schwartzen", "fluproject", "Glytches", "SecShoggoth", "Botcrawl", "whitehatsec", "b3h3m0th", "kroudo", "armitagehacker", "LauraChappell", "jonoberheide", "mruef", "ESET", "CoderW3x", "mozhacks", "ryandotsmith", "shellf", "RolfRolles", "aaronportnoy", "Myne_us", "dan_kuykendall", "pentesting101", "samykamkar", "hannibals", "0xFFFFFFFE", "OWASP_feed", "gmuReversing", "pedramamini", "veorq", "_MC_", "shmoocon", "Tony_DEVR", "rayet_etawhid", "SeTx_X", "OISFoundation", "1ns0mn1h4ck", "milovisho", "francoisgaspard", "AlineBsr", "kyank", "HackaServer", "ren0_a", "alex_lanstein", "fredmilesi", "DubourgPaul", "getpy", "ruxcon", "Ch1nT4n", "Atchissonnymous", "JosiasAd", "nasserdelyon", "ljo", "Luzark_", "black_pearl01", "beuhsse", "chr1s", "Yaogwai", "james__baud", "SandeepNare", "Mitsukarenai", "debian", "elinormills", "ticxio", "StefSteel", "Horgh_rce", "LucPernet", "OSSIRFrance", "phdays", "hardwareActus", "LaNMaSteR53", "Evild3ad79", "shipcod3", "mrtrick", "TDKPS", "laramies", "kmx2600", "alexgkirk", "secbydefault", "Dkavalanche", "Securonix", "Abzin0", "jvzelst", "zfasel", "truesecbe", "olesovhcom", "CERTXMCO_veille", "fr0gSecurity", "hiddenillusion", "FIC_Obs", "MxTellington", "SteyerP", "bindshell_", "securitymoey", "rcsec", "hn9", "MrTrustico", "rattis", "nico248000", "queenmafalda", "0p3nS3c001M", "deesse_k", "_Reza__", "idobiradio", "hesconference", "charles__perez", "ntech10", "rapha_86", "HerrGuichard", "amina_belkhir", "fabien_lorch", "cambronnetwit", "hashcat", "flavia_marzano", "Blackploit", "alisoncroggon", "planet_shane", "tottenkoph", "precisionsec", "exoticliability", "d_olex", "RobInfoSecInst", "und3rtak3r", "iCyberFighter", "Digital4rensics", "X01VVD01X", "__ek0", "qqwwwertyuiop", "C3cilioCP", "Tobias_L_Emden", "ph_V", "fcoene", "YBrisot", "jeffreydoty", "CryptX2", "m0nster847", "rh_ahmed", "x_p0ison_x", "manicode", "alberror", "jacko_twit", "MeutedeLoo", "MathieuAnard", "jlucori", "kalin0x", "sec_reactions", "ifontarensky", "_malcon_", "hectoromhe", "ITrust_France", "tlsn0085", "Botconf", "ArxSys", "sam_et_max", "dariamarx", "melangeinstable", "MasterScrum", "Xoib", "Cyberwarzonecom", "DCLSearch", "binaryreveal", "rbidule", "JeanLoupRichet", "dildog", "jedisct1", "meteorjs", "Unix_XP", "LiddoTRiTRi", "brutelogic", "IamNirajKashyap", "0xU4EA", "Blackmond_", "xavieralabart", "gabeygoh", "ksaibati", "hanson4john", "schaaaming", "BSSI_Conseil", "blackswanburst", "Zythom", "ackrst", "fede_k", "yochum", "hackademics_", "AntiMalwares", "PierreBienaime", "reverse4you_org", "tfaujour", "awoe", "jmo0__", "JulesPolonetsky", "wseltzer", "csoghoian", "XSSVector", "quentin_ecce", "engelfonseca", "t4L", "diver_dirt", "mbriol", "jsaqqa", "pci0", "Numendil", "coolness76", "osospeed", "WhiteKnight32KS", "ArnoReuser", "Sug4r7", "DefconRussia", "valdesjo77", "penpyt", "0xVK", "whitehorse420", "MalwarePorn", "VTVeteran", "_vin100", "kasimerkan", "MaxTraxBeats", "apauna", "EHackerNews", "MykolaIlin", "talfohrt", "FabriceSimonet", "vkluch", "SeedNuX", "yadlespoir", "BradPote", "RocketMkt", "joselecha", "culleyetc", "securityworld", "gcheron_", "leejacobson_", "ACPerrigaud", "kantinseulement", "set314", "Cryptoki", "glesysab", "MISCRedac", "shocknsl", "n1k0", "UtuhWibowo", "drambaldini", "gleborek", "_goh", "Hi_T_ch", "BradleyK_Baker", "jeremy_richard", "jryan2004", "Robert_Franko", "cyberguerre", "fredack76", "psorbes", "MarioHarjac", "imrudyo", "snake97200", "r1chev", "iHackers", "HamonV", "Di0Sasm", "CharlotteEBetts", "arnaud_fontaine", "Murasakiir", "___Alex____", "fbyme", "SecurityWire", "powertool2", "Y_Z_J", "Fr333k", "subhashdasyam", "heydonovan", "SourceFrenchy", "CabinetB", "Fabiothebest89", "virtualgraffiti", "Infosec_skills", "Queseguridad", "DimitriDruelle", "inkystitch", "Olivier_Tetard", "AurelieSweden", "lupotx", "abriancea", "it4sec", "yoogihoo", "Matthi3uTr", "Spartition", "soccermar", "dankar10", "boobmad", "tsl0", "fambaer65", "rootkitcn", "tacticalflex", "msftsecresponse", "GreatDismal", "thedarktangent", "ryanlrussell", "securityerrata", "virustotal", "83147Fadilla", "0x1983", "OtaLock", "suffert", "JohnF_Martin", "drericcole", "linuxacademyCOM", "JoseNFranklin", "cuckoosandbox", "robertthalheim", "ejobbycom", "EskenziFR", "FabienSoyez", "shadd0r", "Plaxo", "_Tr00ps", "helmirais", "spaceolive", "Harry_Etheridge", "neurodeath", "BestITNews", "dr_morton", "Serianox_", "NicolasJaume", "mtanji", "jabberd", "KyrusTech", "bouyguestelecom", "canavaroxum", "MRicP", "jcran", "Milodios", "CompuSecure", "outsourcemag", "Z0vsky", "kaleidoscoflood", "xiarch", "bxsays", "climagic", "CrySySLab", "GJ_Edwards", "RS_oliver", "Laviero", "_rbertin", "rik_ferguson", "reconmtl", "maxime_tz", "TravisCornell", "simpletonbill", "JA25000", "cymbiozrp", "Marruecos_Maroc", "qbihet", "fishnet_sec", "armitagej", "J_simpsonCom", "StevenJustis", "ISSA_France", "kasperskyfrance", "bigz_math", "Peterc_Jones", "schtipoun", "hfloch", "Pianographe", "ElMhaydi", "Cyberprotect", "jrfrydman", "tomchop_", "pmburea", "sans_isc", "Vigdis_", "DigitSecr", "minml5e", "zast57", "Tenkin1", "aahm", "randyLkinyon", "NetSecurityTech", "taviso", "0xcharlie", "SophosLabs", "ssiegl_", "f_caproni", "RobertSchimke", "WalliserQueen", "caiet4n", "Barbayellow", "Taron__", "davfi_france", "calibersecurity", "INTERPOL_Cyber", "spiwit", "casperjs_org", "haguec", "pafsec", "defane", "LongoJP", "JasmyneRoze", "osterbergmedina", "khossen", "TwitSecs", "f4kkir", "action09", "han0tt", "security4all", "SecureTips", "erocarrera", "_WPScan_", "SecurityCourse1", "sdxtech", "_nmrdn", "sdxcentral", "DI_Forensics", "vap0rx", "ZeBeZeBa", "lilojulien", "ouroboros75", "schippe", "fabien_duchene", "ielmatani", "onialex64", "eero", "ScreamingByte", "prasecure991", "jpgaulier", "CrowdStrike", "flgy", "EtienneReith", "laith_satari", "deados", "vfulco", "waleedassar", "aanval", "4and6", "negotrucky", "freesherpa", "moohtwo", "initbrain", "rodrigobarreir", "Malwarebytes", "maschinetreiber", "Puckel_", "jennjgil", "AndrivetSeb", "zuko_uno", "andersonmvd", "okhin", "Eeleco", "CNIL", "elvanderb", "_plo_", "FastFig", "hackerbus", "56_fj", "Xartrick", "exploitid", "v0ld4m0rt", "tgouverneur", "DebStuben", "RonGula", "thotcon", "G4N4P4T1", "Yxyon", "_bratik", "Diacquenod", "Majin_Boo", "vhutsebaut", "stephane1point0", "Urkraftv", "_Debaser_", "ximepa_", "irixbox", "coolx28", "Korsakoff1", "Regiteric", "botherder", "Hakin9", "Herdir", "fbardea", "oduquesne", "thecyberseb", "krzywix", "thezdi", "glasg0ed", "Nomade91", "clabman", "just_dou_it", "cizmarl", "brix666Canadian", "_Egwene_", "fAiLrImSiOnN", "l0phty", "thomasfld", "PavelDFIR", "virustotalnews", "leonquiroga", "phanubhai", "Aryaa__", "EightPaff", "N_oRmE", "barbchh", "mcherifi", "NWsecure", "crowley_eoin", "k8em0", "sysdream", "ElChinzo", "k_sec", "ikoniaris", "MarkMcRSA", "rattle1337", "a804046a", "botnets_fr", "garfieldtux", "Cubox_", "MaKyOtOx", "AccelOps", "dummys1337", "w4kf", "toastyguy", "kongo_86", "Fly1ngwolf", "malwarel", "TigzyRK", "syed_khaled", "jhadjadj", "Patchidem", "crazyws", "tlk___", "malekal_morte", "silentjiro", "Erebuss", "fzcorp", "LucianoHuck", "FireEye", "PwnieAwards", "secureideas", "MarcusSachs", "cactiix", "bannedit0", "crypt0ad", "taosecurity", "aNaoy", "KelvinLomboy", "geekjr", "SANSPenTest", "kapitanluffy", "_rootcon_", "ProjectxInfosec", "ryanaraine", "SeraphimsPhoto", "lspitzner", "noktec", "NoraGaspard", "MsMaggieMayhem", "Tishrom", "FaudraitSavoir", "sravea", "bricolobob", "Mandiant", "DarkReading", "securityninja", "_saadk", "calebbarlow", "philpraxis", "spamzi", "MehdiElectron", "Tif0x", "TMSteveChen", "quantm1366", "NeeKoP", "nyusu_fr", "ph0b", "_argp", "SharpeSecurity", "offsectraining", "thegrugq", "seanhn", "marciahofmann", "ihackbanme", "pirhoo", "collinrm", "DFIRob", "felixaime", "cBekrar", "StevenVanAcker", "vierito5", "saracaul", "NTarakanov", "S1D_", "sabineblanc", "Amelicm", "Vie_de_Metro", "emi_castro", "SigBister", "laura_anne182", "markloisea", "ubersec", "Hugotoutseul", "k3rn3linux", "harunaydnlogl", "SpiderLabs", "lhausermann", "vltor338", "WorldWatchWeb", "jamesejr7", "kafeine", "rmogull", "razaina", "Koios53b", "MinuteSexe", "w3af", "ateixei", "AlliaCERT", "JalelTounsi", "Medsiha", "JonathanSalwan", "mubix", "kylemaxwell", "sagemath", "tbmdow", "SamTeffa", "lukeburnett", "veeeeep", "agonzaca", "travisgoodspeed", "markrussinovich", "cesarcer", "_sinn3r", "dalerapp", "Ylujion", "Lapeluche", "eveherna", "OrLiraz", "qgrosperrin", "udgover", "MonaZegai", "adesnos", "window", "gcaesar", "UrSecFailed", "kutioo", "malwarediaries", "n0secure", "obs_media_num", "Steve___Wood", "emgent", "HackingUpdate", "iDefense", "wopot", "nullcon", "sibiace_project", "aramosf", "cyberwar", "sandrogauci", "silviocesare", "HostExploit", "Dreamk36", "33022", "amarjitinfo", "owasp", "th3j35t3r", "fromlidje", "rybolov", "kerouanton", "Nathanael_Mtd", "gallypette", "CipherLaw", "CrimsonKaamos", "The_Silenced", "JGoumet", "BlantonBache", "threatintel", "hackinparis", "never_crack", "0xerror", "sioban44", "josoudsen", "SensiGuard", "hustlelabs", "hackerzvoice", "jollyroger1337", "geocoulouvrat", "PastebinLeaks", "p4r4n0id_il", "anton_chuvakin", "sysnetpro", "nigroeneveld", "MoonSols", "cryptoron", "hackinthebox", "l33tdawg", "HITBSecConf", "kriptus_com", "pbeyssac", "Paterva", "SmartInfoSec", "HackingDojo", "CERTFI", "Bertr4nd", "leducentete", "aanetgeek", "infosecmafia", "Javiover", "reboot_film", "pryerIR", "DeepEndResearch", "aris_ada", "savagejen", "Doethwal", "0xde1", "agent0x0", "btabaka", "justinbiebiere", "i_m_ca", "Hexacorn", "JeromeSoyer", "wallixcom", "secuobsrevuefr", "vanovb", "POuranos", "l_ballarin", "lestutosdenico", "nicklasto", "Ballajack", "mks10110", "afrocyberpunk", "quarkslab", "balabit", "wireheadlance", "C_Obs", "k3170Makan", "siddhi_salunke", "E_0_F", "T1B0", "stelauconseil", "Lady_Kazya", "siri_urz", "M86Labs", "Onthar", "mbenlakhoua", "jeremiahg", "hdmoore", "iunary", "dvdhein", "braor", "sunblate", "SeguridadMartin", "CQCloud", "bri4nmitchell", "vietwow", "Dinosn", "isvoc", "eLearnSecurity", "DarkCoderSc", "SwiftwayNet", "nathimog", "gertrewd", "alexandriavjrom", "moneyfreeparty", "ntdebugging", "OWNI", "CERT_Polska_en", "commonexploits", "Chongelong", "Asher_Wolf", "s0tet", "Psykotixx", "Karion_", "sinbadsale", "nowwz", "yodresh", "BlackyNay", "0xBADB", "yeec_online", "paco_", "Parasoft", "pretorienx", "TrC_Coder", "creativeoNet", "0x6D6172696F", "SecurityXploded", "Fou1nard", "7h3rAm", "ChanoyuComptoir", "ioerror", "avivra", "Stonesoft_FR", "manhack", "mwrinfosecurity", "caltar", "asintsov", "corbierio", "Panda_Security", "benhawkes", "chrisrohlf", "ethicalhack3r", "tkolsto", "firejoke", "R1secure", "Urbanplaytime", "indi303", "c_APT_ure", "CodeCurmudgeon", "DavidGueluy", "unohope", "aspina", "DanGarrett97", "EnergySec", "H_Miser", "arbornetworks", "eromang", "telecomix", "ForensicDocExam", "gl707", "agevaudan", "YungaPalatino", "D3l3t3m3", "shafigullin", "Jhaddix", "baYannis", "camenal", "AskDavidChalk", "cthashimoto", "enatheme", "zandor13", "loosewire", "artem_i_baranov", "jvanegue", "nudehaberdasher", "aaSSfxxx", "Actualeet", "dUAN78", "Asmaidovna", "rmkml", "JobProd_DOTNET", "4n6s_mc", "Tris_Acatrinei", "Geeko_forensic", "AlanOnSecurity", "t_toyota", "ericfreyss", "aboutsecurity", "barryirwin", "no_name_here", "Safer_Online", "o0_lolwut_0o", "meikk", "coryaltheide", "paulfroberts", "patrickmcdowell", "RCELabs", "sergiohernando", "JC_DrZoS", "chiehwenyang", "snfernandez", "dakami", "DudleySec", "EddyWillems", "SANSInstitute", "buffer_x90", "internot_", "AmazinQuote", "nikemax2007", "swept", "halilozturkci", "badibouzi", "SafeNetFR", "treyka", "Ivan_Portilla", "megatr0nz", "slvrkl", "bortzmeyer", "binsleuth", "zed_0xff", "fluxfingers", "BEESECURE", "circl_l", "certbe", "defcon", "brucon", "syn2cat", "Metlstorm", "tryks_", "AusCERT", "lreerl", "sud0man", "kyprizel", "kabel", "Jipe_", "PhysicalDrive0", "HoffmannMich", "jaysonstreet", "g4l4drim", "j0emccray", "fuuproject", "htbridge", "ebordac", "zesquale", "KalkulatorsPro", "dragosr", "Holistic_Steph", "legna29A", "ESETResearch", "_calcman_", "aristote", "DrewHintz", "Imperva", "Yayer", "C134nSw33p", "thgkr", "Hydraze", "y0m", "Heurs", "honeymole", "andreglenzer", "TechBrunchFR", "epelboin", "rafi0t", "PagedeGeek", "stackOver80", "Creativosred", "routardz", "ITVulnerability", "Hat_Hacker", "CyberwarForum", "kalptarunet", "Redscan_Ltd", "BerSecLand", "cabusar", "infiltrandome", "ccc", "biosshadow", "r0bertmart1nez", "yanisto", "k_sOSe", "TheCyberLawyer", "DCITA", "apektas", "Viss", "twatter__", "ximad", "EmergingThreats", "ochsff", "9bplus", "Thaolia", "raganello", "evebugs", "eastdakota", "stacybre", "Shiftreduce", "BitdefenderFR", "domisite", "CaMs2207", "IKARUSANTIVIRUS", "StrategicSec", "Jagdale63", "mrdaimo", "opexxx", "marcusjcarey", "esignoretti", "leonward", "Sourcefire", "binarydom", "timecoderz", "Phonoelit", "_snagg", "Sharp_Design", "s_kunk", "gon_aa", "mrkoot", "FSEMEA", "saleh__alsanad", "S21secSecurity", "SugeKnight4", "danhaagman", "sl4ke", "openSUSE", "debiansecurity", "debianfr", "AlanPhillips7", "7safe", "_CLX", "DrM_fr", "Securelist", "csananes", "yenos", "Agarri_FR", "tactika", "Nelson_Thornes", "chri6_", "MarcoFigueroa", "UnderNews_fr", "edasfr", "selectrealsec", "chr1x", "voyagesbooster", "follc", "rackta", "Jaxov", "isguyra", "AFromVancouver", "w4rl0ck_d0wn", "infosecmedia", "steevebarbea", "Zap0tek", "NESCOtweet", "niCRO", "nono2357", "Emeaudroide", "fredraynal", "corelanc0d3r", "xanda", "mov_ebp_esp", "binnie", "theAlfred", "Securitycadets", "patrikrunald", "snowfl0w", "GadixCRK", "kahusecurity", "reversemode", "hackinfo", "t0ka7a", "switchingtoguns", "zecurion", "NKCSS", "Yahir_Ponce", "eag1e5", "ghdezp", "komrod", "Paul_da_Silva", "torproject", "abuse_ch", "alchemist16", "ibou9", "azerty728", "Baptiste_Lorber", "Yann2192", "RichardDOwens", "2gg", "MAn0kS", "rssil", "f4m0usb34u7y", "PR4GM4", "TyphoidMarty", "picikeen", "thE_iNviNciblE0", "kenneth_aa", "HacKanCuBa", "teamcymr", "neox_fx", "openhackday", "thesmallbrother", "MFMokbel", "jeromesegura", "WawaSeb", "trolldbois", "curqq", "danphilpott", "ProjectHoneynet", "KDPryor", "extraexploit", "mortensl", "UNICRI", "cowreth", "macteca", "HackerTheDude", "cedricpernet", "stefant", "issuemakerslab", "cillianhogan", "carlLsecurity", "SecuObs", "googijh", "haroonmeer", "dum0k", "virusbtn", "gcluley", "StopMalvertisin", "sbrabez", "VirusExperts", "deobfuscated", "pentestmexico", "mrbellek", "fpaget", "richinseattle", "0xjudd", "gamamb", "smoothimpact", "zsecunix", "FredLB", "andremoul", "TeamSHATTER", "milkmix_", "IOActive", "Xylit0l", "chetwisniewski", "angealbertini", "marco_preuss", "Fyyre", "dyngnosis", "SecurityIsSexy", "defendtheworld", "Satyendrat", "knowckers", "sabina_datc", "TaPiOn", "in_reverse", "ChadChoron", "dshaw_", "vanjasvajcer", "malphx", "EskimoNerd", "ncaproni", "7rl", "cthevenet", "sphackr", "unk0unk0", "hEx63", "sempersecurus", "inuk_x", "GotoHack", "justinlundy_", "kenjisam", "borrett", "__emil", "shu_tom", "Y0Z4M", "bartblaze", "danielvx", "BlackHatEvents", "DustySTS", "ZtoKER", "netrap", "zmworm", "goretsky", "tametty", "0x58", "jbfavre", "recriando", "revskills", "cbriguet", "munmap", "irciverson", "professor__x", "JPBICHARD", "amaximciuc", "hss4337", "dphrag", "seanxcore", "group51", "fschifilliti", "bik3te", "rajats", "_Blade81", "deroko_", "asc3tic", "__x86", "jasc22", "MarioVilas", "SSL_Europa", "xorlgr", "philmuncaster", "OracleSecurity", "HTCIA", "SecMash", "arnaud_thurudev", "lcheylus", "ccg", "jfug", "ghostie_", "TheUglyStranger", "Shinegrl", "hXffm", "TheNexusDI", "Kizerv", "bojanz", "rebelk0de", "iMHLv2", "insecurebyte", "kakroo", "WasatchIT", "Ange1oC", "GiveUThePinger", "airaudj", "kjswick", "Ideas4WEB", "TwisterAV", "TheHackerFiles", "neosysforensics", "fbinc355", "kasperskyuk", "diocyde", "EncryptStick", "b1nary0", "RomainMonatte", "SalesNovice", "radware", "SUPER_Security", "Nattl", "missuniverse110", "perdrum", "coresecblog", "steaIth", "mikko", "infosecbulletin", "J4ckP4rd", "__Obzy__", "CERT_mx", "alexlevinson", "CyberAdvisorsMN", "I_Fagan", "mike_fabrico", "dannysla", "virusstopper", "ChristiaanBeek", "toucansystem", "alvarado69", "adula", "Denis_Akkavim", "hardik05", "305Vic", "itech_summit", "mollysmithjj", "keysec", "nmatte90", "_x13", "binit92", "sebastiendamaye", "ITRCSD", "TheDataBreach", "ntsec2015", "PascalBrulez", "JokFP", "x0rz", "threatpost", "PiotrBania", "ozamt", "41414141", "msuiche", "forensikblog", "fjserna", "mdowd", "milw0rm", "str0ke", "metasploit", "i0n1c", "antic0de", "gattaca", "CyberSploit", "hack_l", "XSSniper", "Sysinternals", "DumpAnalysis", "zentaknet", "DidierStevens", "egyp7", "malwaredb", "ubuntusecurity", "isaudit", "bsdaemon", "milojh", "Myst3rie", "0security", "Sorcier_FXK", "nicolasbrulez", "MatToufout", "virtualabs", "CertSG", "esizkur", "dysternis", "paradoxengine", "filipebalestra", "h2hconference", "berendjanwever", "0vercl0k", "matrosov", "sirdarckcat", "edskoudis", "pentestit", "securityshell", "rapid7", "r00tbsd", "g0tmi1k", "int_0x80", "newroot", "dt0r", "0xroot", "alienvault", "cyphunk", "fail0verflow", "qualys", "ModSecurity", "fo0_", "Veracode", "McAfee_Labs", "XSSExploits", "beefproject", "deepsec", "vthreat", "voidspace", "secviz", "googlehacking", "Openwall", "j00r", "2xyo", "analyzev", "hernano", "windsheep_", "ptracesecurity", "infernosec", "anthonymckay", "virtualite", "_decius_", "aircrackng", "jz__", "DeviantZero", "Darkstack", "aramh", "dynsec", "hackerschoice", "packet_storm", "csima", "nickharbour", "digistam", "fmarmond", "Ixia_ATI", "EncryptedBeader", "monstream00", "Hacksawz20", "jcanto", "biopunk", "ZenkSecurity", "inj3ct0r", "wifihack", "toolcrypt", "lexsi", "aszy", "CyberCrime101", "sstic", "VerSprite", "y0ug", "80211EL", "gollmann", "holesec", "ispadawan", "mortman", "agololobov", "Raaka_elgupo", "selenakyle", "Immunityinc", "SecMailLists", "Reversing4", "wimremes", "headhntr", "codeengn", "xkcdrss", "fbz", "mmurray", "IPv4Countdown", "davesan", "etcpasswd", "paulsbohm", "iagox86", "PainSecurity", "AcroMace", "haxorthematrix", "rfidiot", "rootlabs", "FluxReiners", "dsancho66", "drehca", "StephanChenette", "TiffanyRad", "thomas_wilhelm", "ChrisJohnRiley", "3ricj", "KristinPaget", "_MDL_", "SecBarbie", "halsten", "bluetouff", "n0fate", "Hfuhs", "HackBBS", "greyunderscore", "mwrlabs", "ThreatHunting", "stacythayer", "Carlos_Perez", "mj0011_sec", "kees_cook", "kyawzinko", "malwaregroup", "TomRittervg", "opcode0x90", "jorgemieres", "OpenMalware", "shingara", "manu2342", "commodon", "lonervamp", "cwroblew", "marklucovsky", "ZeroDayLab", "verbosemode", "malc0de", "DavidBruant", "Jolly", "jaybeale", "SteveClement", "singe", "eQuiNoX__", "JohnnyLong", "skipp", "vnsec", "sudeeppatil", "stackghost", "Neitsa", "sirjaz", "iseclab", "AdobeSecurity", "TinKode", "ekse0x", "evdokimovds", "peterkruse", "foxgrrl", "vessial", "leonyson", "Kleissner", "Nullthreat", "hackerfantastic", "EnRUPT", "WIRED", "al3x", "ShellGhostCode", "Eicar", "pod2g", "yelsink", "shakacon", "hackerkaraoke", "carnal0wnage", "sansforensics", "xme", "Pentesting", "SecurityTube", "stfn42", "g30rg3_x", "SPoint", "vloquet", "CERTXMCO", "exploitsearch", "qobaiashi", "ak1010", "sanguinarius_Bt", "ponez", "uglypackets", "dnoiz1", "xRuFI0x", "the_s41nt", "kernelpool", "TheHackersNews", "unpacker", "THEdarknet", "angelinaward", "crai", "endrazine", "ESETNA", "agent_23_", "Aarklendoia", "NoSuchCon", "shydemeanor", "joernchen", "astera", "angelodellaera", "tricaud", "stalkr_", "MarketaIrglova", "Glen_Hansard", "TheSwellSeason", "kriggins", "lennyzeltser", "villys777", "briankrebs", "ortegaalfredo", "kpyke", "TalosSecurity", "p0bailey", "msksecurity", "VUPEN", "PremiereFR", "DOFUSfr", "ActuSF", "OhItsIan", "ma_r_ie", "wecho", "Fluorette", "Maitre_Eolas", "NonAuxHausses", "NosVillesUrba", "smaciani", "newsoft", "emiliengirault", "abionic", "luizdiastwit", "PureFMRadio", "ValeryBonnea", "_protoculture", "nmap", "LP_LaPresse", "sylv1_sec", "grebert", "fdebailleul", "antirootkit", "ionomusic", "nicolaslegland", "manga_news", "wikileaks", "vlaavlaa", "OneLouderApps", "GouZ", "attackvector", "madgraph_ch", "kalilinux", "exploitdb", "Archlance", "KazeFrance", "NicolasThomas", "Hainatoa", "QuentinLafon", "GreatSongnet", "KredMarketing", "Ivanlef0", "_cuttygirl", "KuroTweet", "asi_all", "spyworld_act", "HootsuiteMobile", "reseau_unamipro", "widgetbooster", "lareponsed", "CooperHenry", "mushroommag", "geekact", "MarianneleMag", "seb_godard", "kavekadmfr", "ahmedfatmi", "geekbooster", "gitedemontagne", "capucine11", "rizzrcom", "Stefko001", "webpositif", "grevedutgv", "LucBernouin", "bakabeyond", "MangasTv", "parapigeon", "quoimaligne", "FGRibrea", "twittconsultant", "marinemarchande", "sebastiensimon", "SweatBabySweat_", "Twitchaiev", "hynzowebblog", "greg32885", "Evangenieur", "AirFranceFR", "tweeterp4n", "boloms", "exploracoeurexp", "moderateur", "crouzet", "Capucine_Cousin", "egadenne", "jlgodard", "DelcourtTonkam", "oli2be", "iSebastien", "digsby", "ovaxio", "lapunaise", "PierreTran", "NicolasCatard", "xhark", "blackwarrior", "MathieuBruc", "populationdata", "Garnier08", "cafesfrance", "sirchamallow1", "naro", "Technidog", "Summy46", "gamesandgeeks", "Korben", "Mariegaraud", "eogez", "jpelie", "mthldv", "DavidAbiker", "philippe_lagane", "ju_lie", "sirchamallow", "cberhault", "ouifm", "stagueve", "Romain", "julierobert", "ChrisLefevre", "SimonRobic", "pressecitron", "Zebrure", "AwdioI", "Inzecity", "ga3lle", "lisalaposte", "20Minutes", "Veronica", "LePost", "google", "vitujc", "littlethom23", "EstherBrumme", "Awdio", "DJKweezes","kimberleykerza", "SGdrakop", "0xj3r3my", "Joorem", "SmileBzh", "davinciforensic", "slambynews", "ACKSYNjACKSYN", "MatthiasEckhart", "getInfoSec", "m00zh33", "wizkidnc", "asmistruth", "Achilli3st", "ccbethompson", "mobiussys", "fear_index", "sairammuraly", "ediot2", "AldebranKft", "JeffProd", "ObjectRocket", "TimBenedet", "nakincharly", "Alex_Stormrage", "NetScaler", "security_feeds", "unsignedjuice", "rikterskale", "CodeMorse5", "mistamark", "AFI_Sydney", "apokrif1", "DFIRtraining", "jaime_parada", "criznash", "fran62130", "usrAnonymous", "staybeyond_rckz", "rezor59", "Serenoxis", "jorge_princee", "Master_0098", "DemetrioMilea", "AlM4hdiALHAZRED", "IshanGirdhar", "GIP_GENOPOLE_IT", "WeAreAPT69", "iamlus3r", "iamWLFX", "Polyconseiltech", "magiknono", "valorcz", "SethHanford", "JeremyGibb", "LaServietSky", "CharlieVedaa", "InYoFaceWithMe", "ween7", "kevinott38", "KMagajne", "pejacquier", "SciaticNerd", "Harwood_Tom", "InfoSecurityTop", "_gau_rav", "KibanaTopNews", "_SWEXXX_", "benoit_ampea", "leroiborgne", "guedo", "TomRagFR", "matt_gourd", "jmaguayosanchez", "ht_adrian", "Adrien_Thua", "drefanzor", "javib51", "thierrybxl", "gweltaz_K", "eightzerobits", "c0rtezhill", "onabortnik", "AndyDeweirt", "Cryptie_", "philophobia78", "pmdscully", "p1d630n", "SalonEuronaval", "coffjack", "erusted", "2Dennis", "GithubTopNews", "EdPiette", "roidelapluie", "OSINTSolutions", "clementoudot", "0xrb", "NaykiSec", "terredelamattre", "roadwander", "InfoSecRick", "eugeneteo", "White_Kernel", "monkeylearn", "hoangcuongflp", "Jokar898", "nelson_40net", "maartenvhb", "glesysab", "davidsonjrg", "f_kifli", "peta909", "virusbtn", "RobMarmo", "TayVip", "AndyWilliamsCEO", "Antr4ck", "hm1ch", "_Gof_", "Twat181", "ClPython", "tanguya", "c0rehe110", "the_moorbs", "fybugail", "useris20x", "HelloCreme", "1RicardoTavares", "sl4ke", "mlorcy56", "0xshellcode", "pecb_e", "TechVidRoulette", "LowellLedin", "HuaweiTopNews", "XCtzn", "dunaxiwezili", "SB03165440", "RobertStrugger", "jmarklove", "Fil573", "RakeshM16071987", "gb_master", "theglongo", "BeaCantwell", "neu5ron", "lud0bar", "hehafatasep", "hj751", "louisdurufle", "j15allroad", "carelvanrooyen", "dagon202", "diruscon", "mike_lee777", "MarioAudet", "kalyparker", "hgabignon", "had3s_security", "had3s_security", "sosa9722", "Two_CV", "CODEX_NUL", "FournierRico", "somar404", "yassine_lemmo", "_0x1c0x13_", "brendonfeeley", "Iglocska", "Sach7009", "sourceforit_1", "holoxanohuky", "Intralapino", "FloSwiip", "hoip", "Rinaldi3Ste", "khungbo33", "beberlacrapule", "rezor5958", "gnooline", "evematringe", "ThreatMetrix", "JeremyDumez", "emojieface", "exp_data", "JeromeTripia", "ccsplit", "blobbels", "codemonkeysam", "alangeneva", "neilbulala", "fumfel", "swannysec", "cipherthink", "cestunnombidon", "nolaforensix", "s0nk3y", "DigitalMktgMvn", "ReTweetSecNews", "AliAndani", "6_1zM0", "Otis_oO", "michaeljuergens", "fengfeifirst", "RealtyConcepts2", "stefj", "MyInfo91851314", "Creased_", "ISC2_Las_Vegas", "eshardNews", "raelalaoui", "wiref4lcon", "talentwang", "MrSeal_", "drfreezev2", "kalikatech", "icanhaspii", "allmovie_yt", "malik_almeus", "micespargiliere", "__ITI__", "remy2310", "h3x2b", "stevelord", "satreix", "_Paulo_", "Siriu5B", "house_of_peen", "ShramanACK", "processgeek", "skouax", "pwn4bacon", "sudcode83", "bbbcbccc", "BilbonMickael1", "OfficialMdub", "GrehackConf", "WhiteRabbit_sh", "tenacioustek", "chicagoben", "hackthepanda", "joseison", "Ac0uSeC", "PmaMgp", "manwefm", "d_lanm", "arturferreira", "moleeye81", "Rolland79Sylvie", "ForensicMaggie", "SchwaigBag", "dSebastien", "D_Veug", "mrmrinthemix", "rahul292009", "Eagainn", "brentmdev", "anatolye", "gregjnimmo", "romalegr", "AdacisNews", "threat_wizard", "_JulioGG", "dkrasa", "webexpert851", "b1gtang", "Bolyons29", "evanwagner", "Simon_Kenin", "BlueCollarCyber", "lynchan79", "EXPERT_SI", "SuRi_CSGO", "StopRacismDotCa", "kalebcrusos1998", "kc1redor", "DorisJenkinse", "ddouhine", "bambylamalice", "psavezx", "daves_espia", "A2iFeignies", "Xaaly_MX", "TharunSYadla", "lild4d", "xECK29x", "CyberSecuFR", "hackermill", "B4rC0", "aboutcambodiatr", "sonnybrunson", "ItsMedaBen", "brinhosa", "ax0us", "CDSMarine", "atfeliz", "NeonPint", "Flechemortelle", "fnkym0nky", "shakethemalware", "krausedw", "Y4nn1x", "Mixedmedia", "JulienLhe", "Fabi_Behling", "Spraid_Tech", "JacobDjWilson", "denvercyber", "AndreGironda", "kwartik", "tajveudiroukoi", "mansano_bruno", "da5ch0", "AdAstra247", "MSFT_Business", "Ntech63", "noetite", "nveys", "mahendrat", "fengjixuchui123", "JeanBernardYATA", "jeromesegura", "dafthack", "sneakdotberlin", "MhmtYY", "what000if", "ater49", "ironmano1", "CryptoWeb_fr", "DBAppUS", "RhinoSecurity", "eric_capuano", "Ptrck91", "Dehgaldino", "bricotux", "ypottany", "z0rk13", "mendel129", "freddy1876", "infoinvest20", "Julien_Bernard", "elearnindustry", "lukemks", "MacD750", "PITCHYH", "lucasoft_co_uk", "David_0xEB", "MrSundance1", "Cyber_Stevalys", "TheHitchhik3r", "DFIRMonk", "ricardoteixas", "ContactNystek", "rfayol", "sknuutin", "SecurityMagnate", "rcvinjanampati", "dem4ster", "B_Stivalet", "DigitalAntonius", "MozDevNet", "t3b0g025", "vilarojasjose", "BSidesZurich", "pejupej", "my_name_is_fer", "001sec", "kpr", "achrefezzahroun", "MFPHPodcast", "SuzeanneSpeir", "p00pw", "genma", "holmium8", "vvh1t3Cr0w", "IP_x_0n", "orwelllabs", "dainless", "KevinCardinali", "asfakian", "BK_Info_sec", "MaliciaRogue", "n_idir", "ElBritishZP", "DilTown", "M4ximeOlivier", "Requiem_fr", "Zilux", "DelabarreLuis", "jeroenvda", "newsoft", "jfbaillette", "Cyber_IR_UK", "Hil18de", "Brett_Shavers", "_evilMalwr", "st123ss", "GregTampa", "yodoesp", "testjampes", "s3scand0r", "hakim_sd", "moritan", "mickbmt", "lagomm", "VPinsembert", "chiagarad", "SocialPlanneur", "TheAlecJustice", "FinancialCrypto", "c_williams321", "steffenbauch", "YvesRosaire", "pirytuni", "darrellbohatec", "marc_cizeron", "SogetiHighTech1", "davidkoepi", "malwarescare", "edaboud", "Luno", "mal9i", "garyhak2009", "OracleDBTopNews", "ashraful_rajon4", "GTBen59", "ralphymoto", "AnarchistDalek", "Squidblacklist", "defsecnsattack", "dudeslce", "BoisselFrederic", "sgelisli", "espie_openbsd", "AliSniffer", "SSHROCKS", "Emeline_Martine", "Chacal73768683", "cyresity", "sneakymonk3y", "TheFireGhost", "soslicknick96", "azamhassan91", "digtlulz", "s3c_info", "cool_breeze26", "NahsiY", "pishumahtani", "ChargeParity", "MllePark3r", "michaeldacosta", "sp33dfreak_", "Jacques_Guittet", "LPA_infogerance", "Blueelvis_RoXXX", "BullShit21568", "LincolnKberger", "0slazy", "nsmfoo", "mangtahir79", "__s_yo", "secanalyste", "Yggdr4sill", "diallomed", "smaret", "M_Shafeeq_", "vartraghan", "Raphzer", "kimtibo", "WikiJM", "8luewaffle", "taziden", "decalage2", "amaelle_g", "ad_minwiki", "cnoanalysis", "davide_paltri", "p4r4d0x86", "jv16PowerTools", "GDataFrance", "AlxPrx", "den_n1s", "digitaltwisters", "LazyConsultant", "lucmbele", "MKlein_Dev", "Juanx02Jp532786", "MichaelJohn_DE", "mrjvsec", "brunofusaro", "dctrjns", "EnoCarlos", "TurboSecurity", "ovidiug", "DevSec_", "MarshellMelo", "pramaniksudipta", "TatyanaHaid", "DEGORCE10", "chaima27898388", "lehollandaisv", "tamzac", "bolomacosmoura", "kmonticolo", "KJanton", "GuilhemSAVEL", "sn0wm4k3r", "sourcecode1esme", "SpoonB0y", "NicolasWolf", "SFPwN", "SilkySmoOth___", "QuentinBrusa", "slim404", "Metalliqueuse", "YannRoques", "Li06ly", "skswati", "Tanium", "kosogistan", "gael_oyono", "cl0udmaker", "IESommet", "BenoitJeannet", "letexploitfly", "ba0216", "kl0x41dgs", "BugBountyZone", "consultortesis1", "Alexplzstandup", "Cybermarius1", "ciunderhill", "lubian_29", "csabaharmath", "abosalahps", "frhak", "randal_olson", "twp_zero", "slabetoule", "NRhasovic", "chaign_c", "bettercap", "omer2008", "InProvadys", "No0b_lol_lol", "llazzaro", "_datadesire_", "MacR0bins", "_bl4de", "grufbot", "jbillochon", "kafeimai", "d3vil7", "DaCloudVPN", "ghdezp", "JeromeGranger", "w0mbt", "_k3nj", "pr9try", "KesselSec", "didonadezuk", "sevenyears3", "WenheX", "samiallani", "SimonBuq", "RegnierJeremy", "seblw", "secelements", "J7Pepper", "juckly06", "tbillaut", "magicianc57", "Yannayli", "SecurityIT_Nick", "MalwrNinja", "aprimotore", "lipeandarair", "jusk217", "SerenityFluff", "rodneyrojas8", "jtrombley90", "CannaUE", "EtudesGamma", "HierundieWeber", "Nekyz_", "rpsanch", "XSpyderSC", "Prasadsofficial", "diorjad0re", "lec668", "5borographics", "volkovin", "cyberkryption", "KimMayans", "jackchou51706", "jgrmnprz", "jdreano", "yaniv_see", "ct_expo", "alice_smith_tes", "0net0all", "kakakacool", "AsymTimeTweeter", "Dylan_TROLES", "ccfis", "Aguilo_Network", "r_dacted", "Hani_Khasawneh", "Palamida_Inc", "geek_king", "Ubikuity", "FLesueur", "thetechhouseuk", "obilodea", "ocument", "pwissenlit", "odzhancode", "BF00d", "_g3nuin3", "MlckhA", "bambenek", "0xf4b", "sureshbangra26", "KRAJECKI3", "ni9ter", "Forensicbox", "kolinstw", "tbarabosch", "rajats", "infolec1", "skaveo_sys", "sigalpes", "CDNetworks_Euro", "0o_An0n_o0", "luxtrust", "patlaforge", "bvalentincom", "ClusirNdf", "crypto36", "enxi0", "Sev6rapian", "lea_linux", "polo46", "niarkme", "BrunoVasta", "robinlaude", "ITNOG2", "KanorUb", "neimad75", "Gros_Fail", "_st0m_", "YoussefHTTPCS", "shaunwheelhouse", "_scarscarscar_", "BreizhGab", "kernullist", "LG_CTIG", "xavier_pernot", "RandomAdversary", "katniss1982back", "plemaire_", "Bugcrowd", "share_in_blue", "msmakhlouf", "pyq881120", "pegabiz", "_bobbysmalls", "chmod750", "MarcelMonfort", "infosecaddict", "mathanrajtk", "snak3pli77ken", "BnjmnDvd90", "taiyyib", "forenslut", "pyth0n_Sky", "MJ_Webroot", "ZeNetPlumber", "hachedece", "pialfg_md", "Nozz_", "robot_sec", "AelCourtea", "Saasar", "ypqFNEbaXvug", "tsuMenethil", "marcfredericgo", "StephaneVinter", "mano_nwl", "_Skylane", "MaaaadderHatter", "StevenRThomson", "herrcore", "arachnobob666", "sivaltino", "unmanarc", "DRX_Sicher", "likeitcool", "SleuthKid", "Peter2E0", "sHaxo19", "justinlundy_", "_Bike_Maker_", "Z3ttabytee", "DavinsiLabs", "cudeso", "zbetcheckin", "shortdudey123", "brambleeena", "_pronto_", "tlansec", "zaheenhafzer", "ustayready", "SecurityITGirl", "Shikata_ga_naii", "mboman", "CheckandSecure", "2w1s78ed", "AidBenA", "DPeschet", "niph_", "AharonEtengoff", "_dracu_", "xtoddx", "cimfor_l", "metaconflict", "tiix_wtf", "rambusinc", "ShoppingstroyR", "gregflanagan22", "prats84", "joegumke", "RobertoQuinones", "Unixity", "anassadikii", "JanMartijn", "secaggr", "MotherOfTweet", "wget42", "kptnpez", "FireBounty", "jamver", "minouch290463", "EricRZimmerman", "Anthony_Jarrier", "sharadmalmanchi", "peakotin", "librab103", "TFFdeC", "argevise", "LiadMz", "rotue", "AllisonsFitness", "cyber_kaser", "VincentBA44", "JulienPorschen", "L4g4", "lsb42", "_yapoc", "r_o_b_e_r_t_1", "_jw415_", "xhamstercom", "suqdiq", "rukovrst", "InfosecTurdFerg", "IOActive", "Bangs96M", "aquavoo", "HamzaHamzabl", "con_figure", "thatinfosecrec", "0xs3c", "nullx31", "4sche", "vlad_bordian", "AndreasRades", "antoniozekic", "ClsHackBlog", "ztzandre", "fullblownsec", "memosalah83", "MorganSALLEY", "ZollTech", "JimmyPommerenke", "fegoffinet", "faradaysec", "pseudonyme_ovb", "castor1337", "FSecure_IoT", "TLSv12", "Malwerewolf", "mvktheboss", "scotthworth", "Pjboor", "Bryan8700", "FredHilbert", "malware_traffic", "eddelac", "braindrain", "thd_kh", "DTCyberSec", "mugundhanbalaji", "cybert0x", "DanielRufde", "ImeldaNallela", "01Beep10", "dbarzin", "TheSIEMGuy", "MReveilhac", "pythontrending", "Ma3rsK", "DONIERMEROZ", "jiboutin", "tuxpanik", "eax64", "ValBouin", "danmichelucci", "kohldampfer", "PishranGroup", "yprez", "esskaso", "rgacogne", "La_venel", "SonyHaze", "AdrienDotFAY", "SonuSnjain31", "qboudard", "mleccha", "yosetto", "Zizounnette", "redarowxsj", "HardlyHaki", "flcarbone", "pello", "thenoax", "Beto4891", "EinatSoudry", "monstertobeast", "AFreeTeaCup", "ed_santillanes", "x0velin", "code_injected", "HotnetInfo", "GGdie", "melazzouzi", "rostomgtr", "HannenAk", "osdefsec", "jesljesl", "SchwarzonSec", "EMHacktivity", "bcastets", "exp10t", "daggerconf", "Sk5ll3D", "g00dies4", "lzskiss", "anubis_pt", "StanKj", "ramala1993", "wazak2k2", "Adoveo", "jykegrunt1", "DanCimpean", "FairFred", "maypopp_fr", "kcobrien42", "GitM8", "kob_248", "Othebaud", "wtaatp80", "MallDarth", "Malwaredev", "PravinWakle", "KhepriX", "fparis22", "i0nAy", "FrankStrasbourg", "alexandrosilva", "dondecuman35", "AESATIS", "vxroot", "sh33psy", "ggranjus", "cdagouat", "StaticJobsLLC", "mrjmad", "e3amn2l", "NHenaff", "bradbonomo", "jcanto", "martinez_brain", "sylvainbruyere", "FuraxFox", "crmunoz27", "nikos_alashiass", "PyBaltimore", "PhilGros", "asstalldiop", "endprism", "YohanniAllyscar", "rrogier", "benjaminvialle", "JChaubet", "titan391", "ITsecurityBabe", "christian_j06", "RubixLabsFr", "_m4g", "420investholdng", "Sh4d0wS4int", "UnhappyCISO", "Sysaddict", "mickeander", "TrustNCS", "BillBaker20", "jvitard", "over2393", "baudry64", "Vaelio", "actudefense", "gowaskAlice", "amicaross", "rnaitom", "Th3N1nj4", "RemoteViews", "vivien_fraysse", "Jerswift8Swift", "WokenRabbit", "Pentestylesnake", "md5hashtag", "0x4n6", "MMSmolarz", "jimbobnet", "AbidHabib12", "CYINT_dude", "henridebrus", "HrycIvona", "Cyber4Sight", "ITConnect_fr", "kmut", "MariusRisko", "CecurityCorps", "tux0t", "_Diskett", "davidbizeul", "0x66757279", "PrOjEcTHaCkErs", "ForestrialBook", "PVynckier", "T_0x1c", "0x1cT", "jfsimoni1", "Dnucna", "neilujh", "philoogillet", "Kiwhacks", "Eng_Balfagih", "AlexandreSieira", "VishnuGorantla", "SD_Intelligence", "Kettei__", "CORELANSL", "Rathodlalji27", "0xygate", "sevreche", "tsouvignet", "tguillemois", "MiN2RIEN", "VidAlban", "johanfuentesf", "clement_michel", "lesblaguesduduc", "xgsinfosec", "Julien_Gamba", "touelfe", "JonahLupton", "StartUpsSecure", "ZadYree", "alexandre_grec", "Fl0u_", "BertrandTFilms", "_nicolasmichel", "krierjon", "sehque", "Master_of_OSINT", "Sr_Shohag7", "Mescal_Hzv", "dervyshe", "Conix_Groupe", "scorpions786", "lapadorjee", "rdtdyd", "paineTesteur", "JeremyBesseyre", "goldProsperity", "mh_mamun93", "bibin57110", "_Stroumph", "Erwan_Sec", "TCqnt", "_p3r1k0_", "DebeurePatrice", "HoudiniOctopus", "kachulec", "lsb42A", "OxFemale", "samibourami", "bzhinfosec", "amin_qul", "Bx3mf", "Yacine_att", "A5chy", "_tennc", "ja99", "k0z1can", "Nima_Nikjoo", "AKAlrajih", "thierryzoller", "ddtseb", "MarieGMoe", "MS_Ignite", "fadbab", "Inox3_", "mz23in", "ChatironT", "fredsonic75", "The_NeTpSyChO", "brentwrisley", "jeffman78", "ThomVess", "1nf0s3cp1mp", "JP0x1F", "catalyst256", "lukaszfr", "aomanzanera", "MStingleyTX", "moustik01", "cyberroad_e", "ENCS_Julien", "lestextesR", "0x4c1d", "BoiteNoireKill", "raj883759", "JulienDev4Dream", "fafar", "tweet_josselyn", "PhilippePotin", "MartolodArBed", "TristanBertin", "philippeveys", "Vircom_Inc", "EuropeanSeC2015", "alxmyst", "2e325c3750f6466", "BertrandToulon", "stRiksVindicta", "ynirk", "_GRRegg", "OTBRecruiting", "cyb3rops", "BurgTechSol", "FrancoisSopin", "drake92s5", "EdenCySec", "ednv8", "totoiste", "ksecondlab", "linkbruttocane", "GYH_iwo", "igniteflow", "_m0rphine", "kevlabourdette", "mgualtieri", "wago42", "MissMooc", "2vanssay", "Lord0ftheWar", "Dr_penal", "CihanYuceer", "Drapher", "tomeetomy", "nmbazgir", "myimran", "zllitt", "samsec", "max_r_b", "Sbgs80", "lai132888", "jeremiemathon", "Fla_ke", "Fr33Tux", "airpair", "MichalStaruch", "cyberaco", "flopgun", "Jean_Dalat", "Someone780", "aldoestebanpaz", "EricFRC", "TuunLa", "UKOSINT", "Gimli130", "Aka_Spiderweak", "ykerignard", "reversaur", "Balltheabove", "skorochkp", "SiliconArmada", "TestingSaaS", "pkitools", "s0crat", "jusafing", "litalasher", "Share_Link_FR", "JackRybinski", "saraell1", "urlvoid", "jsgrenon", "Prash_rgv", "ILLUMINATEDBE", "Flo_nivette", "ryan_liang", "rashiduln", "raghimi", "Crypt0_M3lon", "ITNsec", "zeveDM", "Python_Agent", "ewager", "bi7dr0p", "HPxpat", "LodiHensen", "lepicerienum", "ztormhouse", "GummoXXX", "Cleverdawn", "cam3r0n9", "cybersecscar", "17_dallet", "SecuInsider", "Linschn", "ldebackere", "anarcho_voyo", "Fayd_1", "brian_warehime", "KaganKongar", "The_Tick", "JevyLux2", "Shaunsaravanas", "E_Setuid", "papygeek", "etiennelb", "WhilelM", "pvergain", "Novettasol", "cybereason", "VindexTech", "devasundar_a", "madpowah", "fdomartins", "w4l3XzY3", "NeoCertified", "lliknart31", "datwittak", "jaurieres", "tux92", "Ahugla", "Evex_1337", "golgotte44", "m4xr4y", "StratosphereIPS", "Azca_tp", "servicellpasto", "LordAbitbol", "chrisdoman", "UndiesClothing", "fbouy", "poulpita", "hiubiah", "rlgrd", "M3te0r_Wave", "lauMarot", "WarpDelabass", "pluckljn", "sonkite225", "ArmatureTech", "DigiFoRRensics", "mrtuxi", "MGMonty66", "ywilien", "BouDiop1", "nigabeyna", "Data88Geek", "domen_bexo", "maher275", "KirstyM_SANS", "andrewbrinded", "yararules", "nolimitsec", "adarshaj", "vsantola", "Random_Lyceen", "lllmine1", "HarlinAtWork", "DanbecBeck", "spridel11", "Sorcier_FXK", "666_tweet", "BronzeAgee", "wide_nicopus", "jcpraud", "SecIT_Summit", "hut8uk", "jean_sylvain", "imrim", "CyberWarfaRRe", "HECFBlog", "V_Gourvennec", "dev_mess", "les_oscars", "blair_strang", "mariasans81", "rifec", "bigmuse85", "sec_joao", "cedriccazenave", "Joel__Gros", "chokami", "fygrave", "XXXnoflagXXX", "4securitytweet", "Geclaaaw", "AuffretI", "0wosk", "vtcreative", "kerhuon", "todbox", "Rogsis1", "sim0nx", "jkimmusyoka23", "noopzen", "_julesi", "flavio2012Toic", "DerdniK", "igor51", "yzileo", "hyp_h5p", "d4rw1nk5", "julientouche", "ClaireNaudeix", "NuHarbor", "sdkddk", "lfm421", "tomyang9", "e4b816", "TTAVTest21", "Davidforense", "aasifrafiq", "pologtijaune", "jreen85", "ICOexchange", "dginio", "armazicum", "marcmilligan", "8bd130498da745a", "Natwayzee", "jerome7528", "k_y0p", "NRabrenovic", "Security_Sleuth", "SunnyWear", "rezor59robert", "sysinsider", "tuxedo_ha", "_langly", "1NV65510N", "nlt56lorient", "drioutech", "rapid7", "OXITS", "caroworkshop", "KayleighB_SANS", "hack3core", "iansus", "YacineHebbal", "thegeeksjt1", "jasonish", "MyTechCommunity", "GhelSafo6", "marklinton", "F_kZ_", "flomicka17", "gal_lapid", "tranhuuphuochva", "ZikyHD", "kmkz_security", "pepito38100", "JeanphornLi", "hickling_thomas", "Dave2167", "nedforume", "DELLFrance", "SANSEMEA", "kfaali", "thomas_maurice", "bitcoinctf", "boolaz", "N0jj4", "alaurea", "droops38", "qdemouliere", "8mccm8", "JohnDoe24563614", "pstirparo", "xorred", "sn8doc", "shats1978", "Damian_Zelek", "layes2904", "TaliltO", "Kan1shka9", "Tech_Truth", "cinetimeapp", "Catalyst_b_01", "Neur0z0ne", "rabauken5", "A_H_Carpenter", "S_ith", "a_ssuresh", "fido_66", "MathildeLBJ", "d0kt0r", "geekjr", "riftman", "Slash868", "citronneur", "dikkenek65", "uta966", "s3cdev", "tar_gezed", "SharkN", "ZzzZacato", "___wr___", "giannihope", "Lanuom", "cedoxX", "CUS3CUR3D", "koubyr", "m_bertal", "robbyfux", "s4mb4rb3ry", "31415926535z", "omriher", "_sodaa_", "SecEvangelism", "Sunzag", "Scratoch13", "SniperX509", "bestitsource", "lumisec", "ZedFull", "aqarta", "CyberMesCouille", "csiroen", "IlanUzan", "HovikYerevan", "1fuckg", "securitybrew", "rezogot", "NemRaphMic", "cyralco", "MarieGuiteDufay", "sdesalas", "karzaziasmara", "sskkeeww", "s7v7ns", "Ericchen1106", "triflejs", "Andrew___Morris", "Risk_Cambridge", "hxnoyd", "moyuer12345", "veilleurh", "opoupel", "sylvander", "31is", "mosarof_bd", "jjajangjoakk", "eurozn", "FlxP0C", "moong1ider", "OWASPSonarQube", "jawahar11", "Ouaibs", "pkalnai", "singhharinder11", "JorgeOHiggins", "FecafootOfficie", "DrEricGrabowsky", "doduytrung", "Nonow_RedWolf", "_r04ch_", "ExperSecure", "explosec", "black_duck_sw", "cywilll", "EdatMaxfield", "remid0c", "MaxCNT", "ramesharma1973", "doctor_malware", "tofattila", "dprebreza", "OhMyTux", "OSDelivers", "m4thi3uf4Vr3", "fayejeff", "red21tech", "Loria_Nancy", "barryirwin", "v4nyl", "Gnppn", "SaberJendoubi", "manhack", "BootMe322", "julloa", "TiNico22", "sieurseguin", "dsecuma", "jmichel_p", "sndrptrs", "NeonCentury", "sidoyle", "virgile1945", "TejMouelhi", "Aztec_36", "olamotte33", "diggold", "Chemrid", "227363", "frzndgoash", "_Zakalwe", "infsec", "TheITGuyFr", "AnuInsight", "bornot_t", "2kdei", "WATCHDAWGMAMA", "hzmstar", "v1nc3re", "bonjour2410", "irvinHomem", "chrisnoisel", "clusif", "But1er", "0x94FA429D", "Overacloud", "espreto", "nmnhuq", "jhosley", "dcauquil", "aifsair", "HackersDoor", "__capone89__", "attackvector", "fugitifduck", "yusufarslanp", "dgatec", "m_demori", "TheWizBM", "jmvillaume", "arrogantpenguin", "Zipeod", "3mpatyy", "mineshk", "pisco", "booub", "netrunner504", "Spawnhack", "oisux", "IncidentHunter", "SecNewsTracker", "GanetheGreat", "cizky", "clickssl", "sicherheit_DE", "pheer_down", "WindMarc", "TCasalRibeiro", "cybere00143", "OctetBow", "zoomequipd", "_icewind", "DinhNhatAn", "Matteo_DeGiorgi", "Robert4787", "fercorvalan", "Malefactor8", "mjbroekman", "dotstar", "philiplbach", "higefox", "MilestoneSecure", "sxt", "4n68r", "william0420", "IdleWog", "a_ortalda", "aramosf", "FradiFrad", "RubiKobalt", "Pentest101MX", "ChrisGoettl", "nguvin", "ValeryMarchive", "hcdlf", "NickInfoSec", "EiQNetworks", "dominique_yang", "skisedr", "Ch1sh1rsk1", "jode1963", "EatherZhu", "fasm3837", "ckyvra", "lucianot54", "TuElite", "echo_radar", "Alphoxofficiel", "voksanaev", "TiRybak", "faruksari", "pr4jwal", "d_ni3l", "wpawlikowski", "Reversity", "cafepsy4startup", "Chublett", "KitarouSec", "abhuyan", "KevTheHermit", "kunbeyalouae", "PierreBONGRAND", "maciekkotowicz", "h4ckable", "makwys", "r00t0vi4", "virtkick", "deshmaL", "wixyvir", "RemiRaz", "Dusseul", "dysoco", "verovaleros", "CisGarrido", "C33Z4R", "minintech", "Bry_Campbell", "johanneslondon", "4sybix2", "Brain0verride", "johnysm17h", "NajihY", "h1romaruo", "parttimesecguy", "atawack", "ccoadvance", "memeavelo", "jibetr", "Scifisec", "AnonymouSpeak", "hackfest_ca", "BretPh0t0n", "nanderoo", "cortesi", "S0mna1H", "matt26th", "quotium", "reolik", "openiam", "bouallaga10", "subratsarkar", "SafestSneer", "pai9901", "DavidLWaterson", "ColasV1", "cramsenyer", "S_Team_Approved", "vNicoro", "define__tosh__", "ahmazingan", "chrystelchrys", "ryusecurity", "AITWebHosting", "ChaudharipawanP", "lcuguen", "DavidJ4RD1N", "ElcomSoft", "piotrkijewski", "RodrigueLeBayon", "speedtaskfr", "brodzfr", "cissouma_adama", "tontonsFappeurs", "HorusSec", "fab_tan01", "rodjafirs", "julien_luke", "yastanimeil", "romu1000", "ByteAtlas", "baiyunping333", "HiroProtag", "penthium2", "Expand_InfoSec", "teraliv_", "MimiiiX", "sach_mehta", "1nf0s3cpt", "torglut", "elisa_muller08", "nuomi", "Jeremy_747", "sjashc", "AquaZirius", "NazratatR", "maejoz", "xanuma11", "Ma_bon", "sekoia_fr", "miliekooky", "feedbrain", "mrbarrett", "Matrix_ling", "daniel_munsch", "j_NewTr0n", "dominichudon", "AAH2100", "arkhe_io", "Bl4ck_D4wn", "bjadamski", "phdjedi", "Bobetman", "AirFranceFR", "barbier_bernard", "AptiResearch", "GirlCodeAPage", "eureka77777", "BinKhatt4b", "entwanne", "OceanetTechno", "accentsoft", "passcovery", "Zekah", "FredzyPadzy", "ekinnee", "securityfreax", "dschaudel", "acidburn0zzz", "snashblog", "HamzaHsamih", "l3m0ntr33", "IreneAbezgauz", "fensoft", "Hjear", "nullaKhan", "_Cornichon_", "eldracote", "fx_flo", "m2nu3", "NicolasGUY_Site", "no_ossecure", "dis7ant", "aeseresin", "SecureHunterAM", "fgrenier", "olivierthebaud", "_x4n4_", "eon01", "OPSWAT", "seti321", "mojoLyon", "voxanette", "livebullshit", "KrovyMike", "casinthecloud", "CodeAndSec", "PCVirusRemoved", "MatheusSaccol", "aouadino", "jfvrxmbl", "RedBoool", "hispanglish", "cmingx", "hostiserver", "jberciano", "elpep", "StuAllard", "guillaumededrie", "CorsaireHarlock", "root9216", "ChrisBereng", "binTest2014", "AniemX", "routardz", "MlenaLenam", "sizzlersam", "iareronald", "bapt1ste", "xakyc", "melo_meli", "Cephurs", "mz_techwhiz", "dijoritsec", "pentesta", "samuelhermann", "orenelim", "Z0vsky", "zerobiscuit", "cryptoishard", "yeulett", "TSSentinel", "glachu87", "degolar", "zakmorris", "Linkurious", "Pdgbailey", "alextbrs", "ncrocfer", "vulnia_com", "RoxanLeca", "jeromesaiz", "pozkawa", "demonskiller974", "KalanMX", "BSI_ISO27001", "vguido2", "dvirus", "Hakin9", "RomainVergniol", "PhLengronne", "kanghtta", "Marl092", "MuSylvain", "HaxoGreen", "mattkowalski", "PierreEmpro", "sTorm_teK", "SergioWfr", "2removeviruscom", "BestDealCart", "Freddyflameapp", "0b1_kn0b", "netprimus", "monsieur841", "intelligencefr", "31petitponey", "meisgizmo", "ankit_anubhav", "link2kimson", "riusksk", "Bitcoin_Lord", "cbldatarecovery", "wlvis", "aulitdbg", "cjumbo", "f0rte2", "secuinfo28", "OsanaGodspower", "1Citoyengage", "mtth_bfft", "jeffthomasaero", "Johnok_", "nevilleadaniels", "lguezo", "HackSpark", "simasj", "Kofithep", "NiightlyCat", "jkpdinesh", "fullanalyst", "adel2k14", "OliCass", "Ignas_Nr1", "KarolisBartkevi", "iamthefrogy", "OlivierMenager", "konstanta7691", "TesfayGebreding", "ChristopheH00", "andbezh", "crlDr11", "AngoCharles", "zenithar", "pevma", "zackhimself", "JeredFromCMLP", "N1aKan", "iriqium", "MontagnierP", "ICTSpring", "twitxobz", "marinivezic", "DavidDoret", "ReverserRaman", "olsap8", "linuxiaa", "activity_black", "circl_l", "GuiLecerf", "ProfAudenard", "Nschermi", "vadorounet", "NateOSec", "abnev", "MichalKoczwara", "ondiny", "__ner0", "qiulihong", "B51404EE", "3lackSwan", "Dami1Paul", "TheBotnett", "TheseusMovement", "handyj", "mydeliriumz", "44ND0MS7UFF", "Path_finder_z", "8008135_", "venicequeen92", "Guruoner", "lessyv", "KLNikita", "Voksanaev_OSINT", "Jice_Lavocat", "SARCWV", "diegobolivar", "theosintguy", "robiocopAB", "Nemako1", "mutmut", "byone", "mtarral", "chris70f", "gargield", "LeopoldoAgr", "bZhDolphin", "suuperduupond", "cryptobioz", "VeilleSSI", "fast2001ak1", "DeepSpaceColony", "cedric_baillet", "Teffalis", "CyrilleFranchet", "Sabine_dA", "goldochoa794", "GardieLeGueux", "N__Sec", "BlueRabbit09", "securitymuppet", "r1hamon", "BonifasNestor", "h1rm", "Zauerfish", "nostarch", "queenwaldorff", "linda6096", "PietroDelsante", "DavisSec", "BlackPian0", "jbnet_fr", "jwgoerlich", "Sargerras", "0x89D0A74B", "netantho", "HuyTDo", "LEACSOPHIE", "BibChatillon", "navlys_", "imagineers7", "e_tachea", "nitinpatil999", "hardik_suri", "superzamp", "elogringer", "jcbld2", "norio567", "robnavrey", "Mumr1k", "happyf337", "suspiciouslow", "ReactivOn", "FedorIcy", "nicksciberras", "Naakos", "Ekimvontrier", "IftahYa", "Fractalog", "Game0verFlow", "Formind", "the_jam", "Sudhanshu_C", "crdbr", "cyber_sec", "matteverson", "rkervell", "Jayson_Grace", "AlineKav", "maximilianhils", "libfy", "arboretum_sas", "DoctorNoFI", "ravitiwari1989", "kevdantonio", "JackKin87812598", "_bughardy_", "phretor", "kryptpt", "BAH_Hacker", "steverigano", "BucklorVPN", "christobal600", "davidtouriste", "stevemcgregory", "frsecilio", "KurShf", "softwaresensei", "Zestryon", "AlmesalamJabor", "H_Inside_ec", "TristanTREVOUX", "0x0000EBFE", "cherepanov74", "a_de_pasquale", "kapravel", "AntiVirusMallo", "tdecanio", "sectroll", "mosesoche3", "zeitgeistse", "Homlett", "good_dad", "pickpocket001", "veerendragg", "rosako", "maaax78", "kaiyou466", "Seb_Net", "Newnioux", "evilbluechicken", "_Cryptosphere", "_gdie", "pourconvaincre", "hermit_hacker", "ESS_La_Pape", "XiaoTuoT9", "notacissp", "notacissp", "stephane_pernet", "unbalancedparen", "ennascimento", "d_launay", "N0ADM1N", "billal_hassan", "antoinedugogne", "jbuhler", "stanleyfmiles", "PeRamon76", "steward110", "asisctf", "fewdisc", "infosec4ngo", "__dxx__", "CNISMAG", "attrc", "nirouviere", "chiston", "janremi_e", "souillies", "GArchambaud", "sovietw0rm", "dvor4x", "sunl3vy", "benkow_", "agnes_crepet", "MsTeshi_", "Kartone", "securesearcher", "s1mon_p", "novirusthanks", "Phonesec", "korezian", "FrenchYeti", "webstack_nl", "guillaumeseren", "v2caen", "Whitey_chan", "jpcw_", "NeustaSCV", "scott_janezic", "RemiDof", "quentinlpt", "yaap_", "MacTweater", "IEMPROG", "angealbertini", "cr0nus_bin", "graeff6", "websec", "ThibaudBD", "Milegemiao", "BSeeing", "cymansys", "Whoisology", "bakabeyond", "teoseller", "danebrood", "El_Quiglador", "SteveGarf", "factoreal", "GSSGhana", "TheHackerFiles", "mobinja", "Transversal_IT", "Samyz666", "AbMalware", "skydge", "rts0dy", "charlesherring", "Ex_Strange", "paranoidbaker", "D1INT", "bonika18", "jahrome11", "n0rssec", "DMBisson", "itnetsec", "MTDOJSecurity", "xiaoheih8", "hackawa", "ibrahim_draidia", "p4p3r", "cteodor", "SSHNuke0", "gmillard", "AurelienCottetL", "bizcom", "muller_sec", "tergaljc", "milkmix_", "chaisetagada", "Netsquatch", "Securelist", "SecViews", "_Sec_C", "InsanePolicy", "da_philouz", "Kmarkk88", "secandro", "marknewsgeek", "WhiteHatRabbits", "DubourgP", "brucedang", "oueldz4", "BobbyLaulo", "jokerozen", "ShawoneYO", "_thieu_", "gud28", "Zaryosuke", "fataloror", "Mouhe", "geralddefoing", "jonsbh", "3aceaf6b12a648f", "_moloson_", "cbrocas", "JanetCSIRT", "ceprevost", "fagamartin", "tim_maliyil", "gg0nzal3z", "clabourdette", "insitusec", "pvrego", "yongicobay", "Baaasto", "_alb3rt0_", "0xKarimz", "MisterCh0c", "barcode", "arkam_hzv", "sljrobin", "OlDll", "lazy_daemon", "HacklabESGI", "courbette2", "electr0sm0g", "FliegenEinhorn", "ESET_France", "espritpervers", "morganhotonnier", "dw33z1lP", "menkhus", "markymclaughlin", "C4t0ps1s", "righettod", "BossHiltoon", "trollab_org", "network18276620", "asv_tech", "tseligkas", "northvein", "JershMagersh", "HeleneChance", "Rahmatyanuarsya", "ChevalDeTrolls", "kriss_dek", "cmatthewbrooks", "valerieCG", "winSRDF", "Pr1v4t3z0n3", "MouloudAitKaci", "lorenzo2472", "pentagramz", "worreschk", "Lucas3677", "adriengnt", "frameforward", "loris_voinea", "EMSST_DE", "k0st", "yaba", "Andre_Sponge", "zdayl", "secdocs", "ghpophh", "Tib_Tac", "AbelWike", "Baadrov", "kolleanv", "_dup_", "ThinkTankDiff", "clusiraqui", "xabean", "evj", "GaelMuller", "Roaming_One", "rosisura", "Ragvelsec", "mandraquex3000", "zirkkam", "Jak03_", "jbscarva", "rj_chap", "Emulex", "micha_cjo", "m0narch_", "matthieugarin", "Thomas_Jomea", "Wookieshaver", "JohnathanNYC", "iidrissoui", "pwyl61", "Dark_Puzzle", "bockcay", "deletom", "tmakkonen", "DamnedKiwi", "TAHASAID2", "HastutiYuanita", "hazard_fish", "bluefrostsec", "p_coupriaux", "DuanHork1", "LamaliF_", "bpoinsot", "Licop", "techblogspics", "Mr_Fredo", "r_em_y", "WhooisWhoo", "marcdov", "0x3af", "kiirtanrosario", "BaptisteMalguy", "bitcoinsdouble", "Ledoux_JP", "bortzmeyer", "watchguard", "lysimachas", "JeromeNotin", "c0rent1b", "hadrio", "Sherry_Art", "ttwye", "cmpxchg8", "Pat_Ventuzelo", "soycmb", "s4vgR", "oemailrecovery", "Asuwiel", "seancataldo", "swallen62", "wprieto", "CardNotPresent", "NJWILL01", "harrjd", "ashpool", "ILoveMyTux", "TonyLeGeek", "planbwarehouse", "CathCervoni", "FreddyGrey", "0xM3R", "getCountly", "SecurityGuy62", "ArthurUrv", "Moosehyde", "fabien_gasser", "blackthorne", "nkokkoon", "__emil", "sebast_marseill", "broisy", "sam_djari", "fsnormand", "MirMuza", "devpsc", "LeCapsLock", "Leslie_Lavigne", "SmetPierrick", "jamal972", "PierreAllee", "michael_yip", "sn___8", "ZhengOlivier", "stephane_deraco", "epelboin", "cmfml", "ThetaRayTeam", "lefterispan", "DubarrySylvain", "irish_ninja_73", "bedoyadaniel2", "ElCherubin", "twallutis", "brunocassol", "g0ul4g", "uberalles666", "AmahouaGeorge", "scls19fr", "ftwads", "cchristoscc", "___Arod", "nicolasvillatte", "BakkenCoin", "pjhartlieb", "mjf4c3", "malwarenews", "azrulOracle", "aured_0x2747ff", "beewebsec", "lenaing", "derecwan1", "El_Tonioo", "ThierrySoulard", "xamcec", "ThingsSecurity", "bosjr", "Brihx_", "Kariboupseudo", "bluetouff", "commu_npn", "pingpingya", "meniga_l", "StosseFlorian", "bobcat133", "antonio_cuomo", "david_billard", "r00tapple", "Ciccio_87XX", "blocklist", "qu1tus", "kleenec", "lexsi", "RosKran", "javel_le_miroir", "jumbo_ninja", "gcouprie", "quentinmaire", "ravear2", "TripwireInc", "cillianlyons", "jyria", "Yaogwai", "DhiaLite", "_haplo__", "prayas_prayas", "surrealiz3", "z3ndrag0n", "ahmad_kifre", "LMVACATIONS", "ababooks", "toma3775", "mpbailey1911", "rontol", "queenmafalda", "almassry21", "carl_chenet", "vratiskol", "deesse_k", "f1329a", "netrusion", "Mitzwei", "SPQRF", "juni71", "l_pecheur", "sk_buff", "NemanNadia", "R0ns3n", "thecigale34", "GardanneMS", "Omerta_IT", "pbeyssac", "savon_noir", "alexstapleton", "raphaelmansuy", "tais9", "dugasmark", "MalformityLabs", "vivelesmoocs", "6433617468", "zertox1", "tic_le_polard", "PhilippeNael", "_m4tux", "b1ll228", "Valri7", "Fortinet", "fmarmond", "laurent_cor", "ottimorosi", "pedri77", "dzurm", "itespressofr", "matt_ibz", "oallaire", "cloudgravity", "logicus", "jeetjaiswal22", "AxelrodG", "GH_MickaelGIRA", "t_desmoulins", "cschneider4711", "darksider9", "SppSophie", "caar2000", "Ta9ifni", "FrenchKey_fr", "Brocie", "audricalba", "PierreSec", "_get_sandre", "Soufiane_Joumar", "IT_SICHERHEIT24", "marnickv", "marco_preuss", "saidmoftakhar", "F5_France", "seculert", "nico_reymond", "VirtualScale3", "ArchiFleKs", "benborges_", "netstaff", "blackswanburst", "cccure", "anderson1diaz", "h4ck1t4", "louisaoasi", "verac_m", "fredrik9990", "guignol78", "Cym13", "cryptax", "k0ro_Bzh", "pinkflawd", "Irthaal", "MakInformatique", "aseemjakhar", "gmagery", "Nirylis", "hugo_glez", "PANZERBARON", "20_cent_", "Synacktiv", "zonedinteret", "Rulio739", "cceresola", "viren024", "t_toyota", "maralamtakam", "ielmatani", "fredfraces", "aoighost", "PowZerR", "Luchien14", "Gexecho", "c_est_bath", "0xDeva", "SymbolsShatter", "S3C0de", "Kujman5000", "carlanlanlan", "SteveClement", "tomsmaily", "yoga_vinyasa", "seakingWD", "darthvadersaber", "GreeniTea_Break", "borstie66", "Boisnou44", "aliappolo", "l88493425", "dise2s", "buz_tweets", "corkami", "_0x4a0x72", "mascuwatch", "DIGITSLLC", "InfosecNewsBot", "mbenlakhoua", "RedHatNL", "kamalsdotme", "mkevels", "Fred_Mazo", "SamuelHassine", "VaesTim", "arnaudsoullie", "virtualgraffiti", "Y0no", "BinarySecurity", "snipeyhead", "ante_gulam", "siedlmar", "commial", "StephaneLechere", "Ron91111", "heliotgray", "SopraSteriaSec", "rvofdoom", "daerosjax", "SnoopWallSecure", "ronin3510", "MxTellington", "m0rphd", "TheUglyStranger", "0x3e3c", "RichardJWood", "fr54fr54", "amstramgram8", "stravis_", "cyberdefensemag", "cedricpernet", "GNU__Linux", "Vivet_Lili", "j_schwalb", "fred104_at_TW", "Solulz", "Narendra_ror", "mike820324", "AmauryBlaha", "specialgifts_1", "martelclem", "EXEcrimes", "cha0sgame", "w3map", "LibreSoftwareFr", "laurenthl", "spydurw3b", "posixmeharder", "Itsuugo", "kfalconspb", "Logeirs", "Atredis", "sowmiyatwits", "Akheros_Corp", "aur0n1", "happyoussama", "Dunne3", "serphen", "informatrucX", "The_Crazy3D", "florent_viel", "phn1x", "JJTonnel", "cguiriec", "hackplayers", "rackcel", "manicsurfers", "mark_ed_doe", "overnath1", "gradetwo", "BehindFirewalls", "xGeee", "unsocialsysadm", "Sixelasco", "R1tch1e_", "x0mF", "TechIQ_ISRussia", "robjamison", "SyMangue", "DamienPierson", "faryadR", "AriOkio", "genieyo", "KitPloit", "tominformatique", "cryptopathe", "IsChrisW", "thepurpledongle", "__Obzy__", "rand0muser35", "securebizz", "belowring0", "SilverSky", "jiesteban", "dt_secuinfo", "esetglobal", "clauzan_", "xjbkxking", "CuriositySec", "nickkarras", "nigirikaeshi", "Inteligenciasmx", "dannyyadron", "dan_kuykendall", "rig_L", "dougser182", "CCLGroupLtd", "ProDestiny1040", "oktarinen", "_robinrd", "SWAMPTEAM", "kaluche_", "turcottemaxime", "kokail", "mokhony", "ProteasWang", "L140CJ", "LymaCharlie", "public_bug", "mattgiannetto", "FabriceCLERC", "yuange75", "quyendoattt", "kennethdavid", "lopu61", "Ibrahimous", "viruswiki", "Stephane_MORICO", "m0m0lepr0", "DarrelRendell", "TunisLul", "nejmpotter", "CyberSheepdog", "Kavika888", "poona_t", "NANGLARDCh", "ibr4him2011", "0pc0deFR", "On4r4p", "ikonspirasi", "hurricanelabs", "KAI2HT003", "corte_quentin", "BRITCHIEN", "B1gGaGa", "hackers_conf", "shab4z", "rosemaryb_", "GuilhemCharles", "23_BU573DD_23_", "gvalc1", "slashdevsda", "osm_be", "TheMrigal", "MalwareAnalyzer", "rpiccio", "MaguiMagoo", "mushrxxm", "l__D0", "philpraxis", "noarland", "H00b3n", "emapasse", "netsecurity1", "Hectaman", "skeep3r", "doulien", "mastercruzader", "blaster69270", "MmeAPT", "ameyersurlenet", "dstmx", "RuthyYou_Me", "EthanCrosse", "d4v3nu11", "juneisjune", "jesperjurcenoks", "BraeburnLadny", "DavidIsal3", "_fwix_", "ark1nar", "CryptoPartyFI", "lpeno", "collo20123", "lifegeek_co", "FYLAB", "maisouestcharli", "isithran", "yhzkl", "azediv", "espritlibreinfo", "alex_kun", "hxteam", "BSONetwork", "kali_linux_fr", "IceAnonym", "xeip1ooBiD", "SamiAlanaz1", "cyrilril", "Minipada", "Julien_Legras", "PratheushRaj", "THYrex55", "CalvinKKing", "T3hty", "Bigou_de", "Maijin212", "RATBORG", "Thus0", "montagnetata", "AntoinePEREIR19", "helsayed78", "ak4t0sh", "SecureThinking", "MarcoPo87022565", "raybones", "DroschKlaus", "Fyyre", "ErwanLgd", "undaVerse", "ltmat", "jorgemieres", "BitdefenderFR", "Joel_Havermans", "AlfBet1", "CyberSploit", "simon_s3c", "archoad", "alexisdanizan", "cryptomars", "n_arya0", "dgiry", "pedrolastiko", "juanferocha", "_8B_", "nordicsecconf", "SophosFrance", "teo_teosha", "Lircyn", "jordangrossemy", "mamie_supernova", "totol__", "Azenilion", "LaurentSellin", "hinozerty", "PyRed7", "kr0ch0", "wolog", "legumx", "e2del", "VaValkyr", "RobinDavid1", "Apprenti_Sage", "PConchonnet", "LucDELPHA", "Guillaume_Lopes", "vm666", "Tinolle", "pollux7", "Ralita_Jamala", "tixlegeek", "_Mussat_", "TwBastien", "quatrashield", "Tinolle1955", "defloxe", "idnomic", "iboow38", "BabigaBirregah", "Julllef", "secuip", "morganeetmarie", "FightCensors_fr", "vprly", "rommelfs", "_nt1", "micheloosterhof", "MattNels", "QuanTechResume", "rshaker2", "joe_rogalski", "naviduett", "enriquerivera80", "HackMiamiRadio", "openminded_c", "HiDivyansh", "kyREcon", "NotThatAmir", "aliikinci", "_Zen_Ctrl", "UCDCCI", "lisalaposte", "iLebedyantsev", "Zen_neZ_", "inetopenurla", "Jeremy_Kirk", "uBaze", "0xfnord", "und3t3ct3d", "MichaelSlawski", "1ight35", "Ax0_85", "PirateBoxCamp", "Berenseke", "OlivierRaulin", "WTFproverbes", "adamkashdan", "GaylordIT", "_gabfry_", "security_sesha", "balasrilakshmi", "secnight", "autobotx2", "ThreatSim", "canavaroxum", "mvdevnull", "RecordedFuture", "StorageChannel", "bmaprovadys", "mrozieres", "K3nnyfr", "infomirmo", "eth0__", "AlMahdiALHAZRED", "wyk91", "crdflabs", "n1ngc0de", "mitp0sh", "8VW", "ElMoustache", "pbortoluzzi", "free_man_", "calhoun_pat", "aknova", "oleavr", "Vinssos", "bugwolf", "openwiresec", "yasinsurer", "codeluux", "jain_ak", "hnt3r", "vessial", "Mid_Tux", "IgorCarron", "XWaysGuide", "machn1k", "etiennebaudin", "the_mandarine", "spy4man", "nProtect_Online", "JeroenLambrecht", "360Tencent", "zforensics", "dell81404780", "julienroyere", "Dejan_Kosutic", "NeoAntivirusUSA", "randiws", "Kentsson", "jmdossantos", "Xserces", "william9555", "PraveenCruz", "chezlespanafs", "malk0v", "0x0d0084abdec6d", "josephwshaw", "NaxoneZ", "BourguignonC", "errachidia", "David_RAM0S", "pierrebrunetti", "SiafuTeam", "succedam", "Korbik", "_Kitetoa_", "_Sn0rkY", "vxradius", "Tp0rt", "laks316", "Holmez_hood", "OlivierMOREIRA", "3sOx13", "OzzPlopoO", "dreeck7", "net_security_fr", "altolabs", "visiblerisk", "rockyd", "borjalanseros", "ForensicsDaily", "grehack", "Intrinsec", "jon1012", "checkfx", "metalprfssr", "maldevel", "SPoint", "Alcuinn", "pentest_swissky", "zamokarim", "tracid56", "3615RTEL", "FredGOUTH", "hesconference", "srleks", "CarbonBlack_Inc", "Turnerwjr", "Art29C", "digital2real", "Bsfog", "allurl", "TorretoGCM", "OsanaGussy", "Qutluch", "tiye2003", "patatatrax", "ErkkiPasi", "miaouPlop", "AlbinK_reel_0ne", "TaibiD", "0xVinC_Dev", "Olzul_", "NTeK33", "elfmazter", "sardinimouspip", "dremecker", "shutdown76", "loxiran_", "kaiserhelin", "binaryz0ne", "fradasamar", "Wagabow", "HackSysTeam", "PKPolyEnquete", "r0mda", "Jl_N_", "AbelRossignol", "0xcd80", "dj_tassilo", "BenoitMaudet", "Xst3nZ", "FChaos", "hootsuite", "sci3ntist", "djabs_barney", "houssemthenoble", "baronscorp", "Intrusio", "gowthamsadasiva", "secknology", "nullcon", "michelcazenave", "Breizh_nono", "kartoch", "Tony_DEVR", "jaganm0han", "milovisho", "pierre_alonso", "Moto_MIA", "AlineBsr", "HackaServer", "Karstik1", "JAldersonCyber", "_gwae", "cryptf", "miguelraulb", "opexxx", "johndoe31337", "DubourgPaul", "ahmanone", "sukebett", "AZobec", "hightur", "lecoq_r", "StephaneG22", "shaneflooks", "johnvd123", "Denit0_o", "aojald", "JosiasAd", "miis_osint", "nasserdelyon", "SACHAVUKOVIC", "Atchissonnymous", "pa1ndemie", "ljo", "Jo_S_himself", "_antaked", "Luzark_", "black_pearl01", "beuhsse", "chr1s", "The_APT1_Team", "__pims__", "_SaxX_", "Bruno_Mahler", "t4rtine", "SandeepNare", "JFF_csgo", "thinkofriver", "_RC4_", "N0Px90", "ARUNPREET1", "dariamarx", "hardwareActus", "lapindarkk", "mrtrick", "shipcod3", "TDKPS", "arpalord", "kerguillec_paul", "MduqN", "heggak", "Maxou56800", "512banque", "fr0gSecurity", "speugniez", "ashwinpatil", "JosselinLeturcq", "barryp792", "Ched_", "Paul_Playe", "boreally", "esthete", "OlivierBarachet", "Securonix", "PRONESTA_FR", "Ponyc0rn", "Dkavalanche", "jvzelst", "oli_adl", "zwerglori", "tvdeynde", "mhamroun", "pensource", "datumrich", "g4dbn", "JussiPeralampi", "malc0de", "karimyabani", "gadolithium", "MennaEssa", "plaixeh", "gl11tch", "whtbread", "anton_chuvakin", "PhillipWylie", "AmiMitnick", "nasete", "Asim2010khan", "SteyerP", "mubix", "TheHackersNews", "okamalo", "simonlorent", "nico248000", "MobiquantTech", "Lita_Amaliaxo", "o0tAd0o", "sc_obf", "0p3nS3c001M", "nicoladiaz", "rattis", "rcsec", "MrTrustico", "ranmalw", "michaellgraves", "MDALSec", "_Reza__", "charles__perez", "fo0_", "ntech10", "airaudj", "florentsegouin", "HerrGuichard", "fabien_lorch", "amina_belkhir", "vloquet", "_Quack1", "Regiteric", "flavia_marzano", "piconbier", "NoSuchCon", "p3rry_ornito", "Blackploit", "T0mFr33", "SInergique", "_c_o_n_t_a_c_t_", "d3b4g", "Tazdrumm3r", "ActiVPN", "SilentGob", "tranche_d_art", "bl4sty", "mercevericat", "MickaelDorigny", "Flo354", "sambrain94", "Diaz__Daniel", "Lying_Iguana", "AlexNogard1", "w0ltt", "FraneHa", "culley", "Cyberarms", "alberror", "Clint_Z", "planet_shane", "melphios", "precisionsec", "0_issueIE", "cowboysec", "PanimLtda", "jhaldesten", "gnusmas2", "Schiz0phr3nic", "cabusar", "HackBBS", "Wechmanchris", "0F1F0F1F", "demon117", "TrendMicroFR", "fieryc0der", "number3to4", "RobInfoSecInst", "MinhTrietPT", "und3rtak3r", "iefuzzer", "0xkha", "Orqots", "theodorosc", "ec_mtl", "shellprompt", "instruder", "cpierrealain", "iCyberFighter", "ufleyder", "rameshmimit", "a88xss", "dotlike", "matonis", "gbillois", "varmapano", "Botconf", "st3phn", "YBrisot", "rh_ahmed", "x_p0ison_x", "ph_V", "CryptX2", "m0nster847", "fcoene", "Tobias_L_Emden", "ifontarensky", "qqwwwertyuiop", "C3cilioCP", "freemonitoring", "__ek0", "StefSteel", "X01VVD01X", "JC_SoCal", "rchatsiri", "itamartal", "irciverson", "ksaibati", "bindshell_", "dudusx9", "binnie", "GI_Steve", "RssiRuniso", "mnajem", "_n3m3sys_", "geeknik", "stuntlc", "giorgioshelleni", "Zebulle59", "ourwebz", "lostcalamity", "NytroRST", "xtremesecurity", "KODOQUE", "kashifsohail", "NicolasLevain", "_Anyfun", "BZH_SSI", "xxTh4mUZxx", "mgaulton", "MeutedeLoo", "jlucori", "MathieuAnard", "fabm16", "JanneFI", "kasiko2005", "kalin0x", "TimelessP", "_malcon_", "agentsecateur", "littlemac042", "futex90", "Zapper9", "ITrust_France", "jacko_twit", "hectoromhe", "ticxio", "tlsn0085", "n0wl1", "Zwordi", "lostinsecurity", "ArxSys", "SecSavvy", "HadiBoul", "hackconsulting", "Yen0p", "rbidule", "Kuncoro_AdiP", "C4p7ainCh0i", "MasterScrum", "Xoib", "Izura", "BiDOrD", "ktinoulas", "shenril", "SedonaCyberLink", "Ark_444", "binaryreveal", "walter_kemey", "FMDINFORMATIQUE", "ludorocknroll", "_sygus", "laurenceforaud", "Cyber_yick", "JeanLoupRichet", "WarOnPrivacy", "sriharirajv", "thomdi", "aurl_ro", "_psaria", "DozOv", "sud0man", "zipzap0007", "dum0k", "chrisikermusic", "emmanuel_f_f", "Nbblrr", "EmilioFilipigh", "SepeztDalv", "Unix_XP", "Mo_hand", "jere_mil", "FadelHamza", "barbara_louis_", "MarcLebrun", "patrikryann", "coruble", "LiddoTRiTRi", "mturtle", "NeeKoP", "0xU4EA", "s3clud3r", "drambaldini", "jeancreed1", "_JLeonard", "RJ45HotPlugger", "presentservices", "BSSI_Conseil", "Araneae_", "JKryancho", "hanson4john", "coldshell", "ackrst", "DrWebFrance", "sysdream", "fredmilesi", "GltGvi", "dj0_os", "KickBhack", "yochum", "PatriceAuffret", "Turblog", "comintonline", "ghostelmago", "argoprowler", "hixe33", "PierreBienaime", "amaximciuc", "SRAVANKUTTU1", "AntiMalwares", "paqmanhd", "siri_urz", "bahraini", "metaflows", "tfaujour", "lagrange_m", "shocknsl", "commonexploits", "mynumbersfr", "APPC2", "coolness76", "osospeed", "quentin_ecce", "Numendil", "pci0", "mbriol", "diver_dirt", "t4L", "engelfonseca", "_vin100", "leejacobson_", "set314", "gcheron_", "joselecha", "securityworld", "BradPote", "RocketMkt", "yadlespoir", "SeedNuX", "vkluch", "FabriceSimonet", "talfohrt", "MykolaIlin", "EHackerNews", "EHackerNews", "apauna", "kasimerkan", "WhiteKnight32KS", "Evild3ad79", "penpyt", "whitehorse420", "0xVK", "Sug4r7", "UtuhWibowo", "lamoustache", "_goh", "valdesjo77", "gleborek", "Hi_T_ch", "B2bEnfinity", "megra_", "dankar10", "soccermar", "alvarado69", "Spartition", "Matthi3uTr", "yoogihoo", "Veracode", "it4sec", "kylemaxwell", "abriancea", "lupotx", "PhishLuvR", "AurelieSweden", "tsl0", "inkystitch", "DimitriDruelle", "fambaer65", "Queseguridad", "Infosec_skills", "Fabiothebest89", "CabinetB", "tacticalflex", "r0bertmart1nez", "rootkitcn", "SourceFrenchy", "subhashdasyam", "powertool2", "Y_Z_J", "SecurityWire", "fbyme", "ethicalhack3r", "l10nh3x", "arnaud_fontaine", "Murasakiir", "JubertEdouard", "CharlotteEBetts", "Di0Sasm", "Erebuss", "ibenot", "r1chev", "snake97200", "imrudyo", "MarioHarjac", "psorbes", "fredack76", "SecurityTube", "cyberguerre", "Korben", "jryan2004", "jeremy_richard", "Robert_Franko", "WasatchIT", "BradleyK_Baker", "JoseNFranklin", "JohnF_Martin", "jbfavre", "Top_Discount", "OtaLock", "0x1983", "shadd0r", "FabienSoyez", "EskenziFR", "robertthalheim", "ejobbycom", "_Tr00ps", "helmirais", "ArmandILeedom", "Harry_Etheridge", "neurodeath", "spaceolive", "Serianox_", "BestITNews", "mtanji", "NicolasJaume", "jabberd", "KyrusTech", "passivepenteste", "bouyguestelecom", "nono2357", "jcran", "Milodios", "outsourcemag", "kaleidoscoflood", "xiarch", "GJ_Edwards", "RS_oliver", "maxime_tz", "JA25000", "cymbiozrp", "Marruecos_Maroc", "fishnet_sec", "armitagej", "J_simpsonCom", "StevenJustis", "ISSA_France", "kasperskyfrance", "bigz_math", "Peterc_Jones", "hfloch", "HaDeSss", "ElMhaydi", "Cyberprotect", "jrfrydman", "tomchop_", "TravisCornell", "Xartrick", "minml5e", "zast57", "Tenkin1", "aahm", "randyLkinyon", "NetSecurityTech", "ssiegl_", "f_caproni", "RobertSchimke", "WalliserQueen", "caiet4n", "Barbayellow", "defane", "pafsec", "LongoJP", "JasmyneRoze", "osterbergmedina", "khossen", "TwitSecs", "f4kkir", "action09", "Taron__", "holyhot1", "han0tt", "SecurityCourse1", "_nmrdn", "DI_Forensics", "vap0rx", "lilojulien", "ouroboros75", "schippe", "ak1010", "fabien_duchene", "rbee33", "onialex64", "eero", "ScreamingByte", "prasecure991", "pentestit", "flgy", "laith_satari", "waleedassar", "aanval", "vfulco", "4and6", "deados", "EtienneReith", "negotrucky", "freesherpa", "moohtwo", "initbrain", "rodrigobarreir", "PunaiseLit", "Malwarebytes", "aristote", "jennjgil", "RonGula", "_Debaser_", "andersonmvd", "Eeleco", "_plo_", "56_fj", "EpoSecure", "v0ld4m0rt", "tgouverneur", "DebStuben", "G4N4P4T1", "Yxyon", "_bratik", "Diacquenod", "ABC_Pro", "vhutsebaut", "ximepa_", "virtualabs", "irixbox", "Korsakoff1", "tricaud", "TheDataBreach", "Herdir", "fbardea", "oduquesne", "thecyberseb", "krzywix", "Nomade91", "just_dou_it", "cizmarl", "brix666Canadian", "Paul_da_Silva", "xme", "fAiLrImSiOnN", "l0phty", "rssil", "thomasfld", "cwroblew", "PavelDFIR", "Aryaa__", "Patchidem", "EightPaff", "N_oRmE", "barbchh", "mcherifi", "NWsecure", "crowley_eoin", "0x5eb", "ElChinzo", "k_sec", "MarkMcRSA", "rattle1337", "a804046a", "botnets_fr", "garfieldtux", "Cubox_", "MaKyOtOx", "AccelOps", "adula", "bsdaemon", "toastyguy", "kongo_86", "Fly1ngwolf", "TigzyRK", "bartblaze", "syed_khaled", "jhadjadj", "crazyws", "silentjiro", "y0m", "kapitanluffy", "lcheylus", "aNaoy", "KelvinLomboy", "Mandiant", "ProjectxInfosec", "danielvx", "Tris_Acatrinei", "kasperskyuk", "noktec", "SalesNovice", "Tishrom", "FaudraitSavoir", "sravea", "bricolobob", "_saadk", "calebbarlow", "balabit", "spamzi", "Tif0x", "quantm1366", "nyusu_fr", "DFIRob", "SigBister", "MehdiElectron", "saracaul", "emi_castro", "markloisea", "sanguinarius_Bt", "briankrebs", "ubersec", "nmatte90", "k3rn3linux", "jibranilyas", "alienvault", "harunaydnlogl", "lhausermann", "WorldWatchWeb", "jamesejr7", "kafeine", "razaina", "Koios53b", "AlliaCERT", "tbmdow", "SamTeffa", "veeeeep", "_sinn3r", "dalerapp", "Ylujion", "adesnos", "Lapeluche", "eveherna", "qgrosperrin", "udgover", "MonaZegai", "kutioo", "UrSecFailed", "gcaesar", "Steve___Wood", "ForensicDocExam", "wopot", "sibiace_project", "cyberwar", "sandrogauci", "amarjitinfo", "fromlidje", "iseezeroday", "gallypette", "The_Silenced", "JGoumet", "SecMash", "never_crack", "sioban44", "0xerror", "josoudsen", "SensiGuard", "jollyroger1337", "nigroeneveld", "geocoulouvrat", "sysnetpro", "kriptus_com", "SmartInfoSec", "HackingDojo", "Bertr4nd", "Javiover", "TaPiOn", "reboot_film", "pryerIR", "savagejen", "Doethwal", "i_m_ca", "Hexacorn", "JeromeSoyer", "wallixcom", "vanovb", "POuranos", "l_ballarin", "lestutosdenico", "nicklasto", "Ballajack", "mks10110", "wireheadlance", "C_Obs", "E_0_F", "k3170Makan", "vltor338", "T1B0", "iunary", "dvdhein", "braor", "sunblate", "SeguridadMartin", "CQCloud", "bri4nmitchell", "DanGarrett97", "vietwow", "isvoc", "zsecunix", "gertrewd", "alexandriavjrom", "nathimog", "Chongelong", "s0tet", "Psykotixx", "Karion_", "sinbadsale", "nowwz", "yodresh", "BlackyNay", "0xBADB", "yeec_online", "paco_", "pretorienx", "TrC_Coder", "creativeoNet", "Fou1nard", "7h3rAm", "ChanoyuComptoir", "essachin", "Stonesoft_FR", "caltar", "Panda_Security", "tkolsto", "firejoke", "R1secure", "c_APT_ure", "DavidGueluy", "unohope", "aspina", "CodeCurmudgeon", "H_Miser", "eromang", "arbornetworks", "gl707", "sundarnut", "iNem0o", "agevaudan", "YungaPalatino", "D3l3t3m3", "shafigullin", "camenal", "AskDavidChalk", "cthashimoto", "enatheme", "zandor13", "SeTx_X", "loosewire", "itech_summit", "iMHLv2", "aaSSfxxx", "Actualeet", "rmkml", "TeamSHATTER", "Asmaidovna", "JobProd_DOTNET", "4n6s_mc", "Geeko_forensic", "ericfreyss", "aboutsecurity", "Sourcefire", "treyka", "o0_lolwut_0o", "meikk", "dphrag", "patrickmcdowell", "JC_DrZoS", "chiehwenyang", "DudleySec", "buffer_x90", "halilozturkci", "badibouzi", "vgfeit", "SafeNetFR", "Ivan_Portilla", "megatr0nz", "slvrkl", "binsleuth", "james__baud", "HoffmannMich", "lreerl", "kyprizel", "kabel", "Jipe_", "PhysicalDrive0", "g4l4drim", "fschifilliti", "htbridge", "ebordac", "r00tbsd", "zesquale", "hardik05", "dragosr", "wimremes", "legna29A", "_calcman_", "yanisto", "Yayer", "C134nSw33p", "thgkr", "Hydraze", "I_Fagan", "TechBrunchFR", "andreglenzer", "rafi0t", "PagedeGeek", "stackOver80", "Creativosred", "hss4337", "Hat_Hacker", "ITVulnerability", "Redscan_Ltd", "BerSecLand", "p4r4n0id_il", "infiltrandome", "k_sOSe", "DCITA", "apektas", "twatter__", "ximad", "Thaolia", "stacybre", "Shiftreduce", "domisite", "CaMs2207", "halsten", "StrategicSec", "mrdaimo", "Sharp_Design", "gon_aa", "LostInRetrospec", "mrkoot", "SugeKnight4", "danhaagman", "deobfuscated", "AlanPhillips7", "diocyde", "spatcheso", "Xylit0l", "DustySTS", "g30rg3_x", "cbriguet", "_CLX", "DrM_fr", "ponez", "Kizerv", "yenos", "tactika", "Nelson_Thornes", "chri6_", "UnderNews_fr", "selectrealsec", "virusstopper", "chr1x", "follc", "rackta", "keysec", "TwisterAV", "w4rl0ck_d0wn", "agololobov", "2xyo", "ghostie_", "isguyra", "AFromVancouver", "malphx", "stackghost", "JPBICHARD", "NESCOtweet", "csananes", "fredraynal", "f4m0usb34u7y", "theAlfred", "x0rz", "zentaknet", "virtualite", "ITRCSD", "Yahir_Ponce", "eag1e5", "haxorthematrix", "switchingtoguns", "alchemist16", "DidierStevens", "ChristiaanBeek", "ibou9", "azerty728", "Yann2192", "insecurebyte", "MAn0kS", "Jolly", "googijh", "305Vic", "NKCSS", "0security", "0x58", "PR4GM4", "TyphoidMarty", "HTCIA", "jasc22", "knowckers", "mollysmithjj", "thE_iNviNciblE0", "kenneth_aa", "neox_fx", "thesmallbrother", "rebelk0de", "RomainMonatte", "WawaSeb", "unk0unk0", "trolldbois", "StopMalvertisin", "kakroo", "sebastiendamaye", "kjswick", "curqq", "KDPryor", "_x13", "7rl", "danphilpott", "mortensl", "extraexploit", "Ideas4WEB", "ZtoKER", "inuk_x", "sphackr", "0xjudd", "issuemakerslab", "FredLB", "vanjasvajcer", "MarioVilas", "sm0k_", "cowreth", "ncaproni", "cillianhogan", "dnoiz1", "0xroot", "ZenkSecurity", "threatpost", "ntsec2015", "nicolasbrulez", "PascalBrulez", "steevebarbea", "revskills", "unpacker", "sempersecurus", "jz__", "holesec", "JokFP", "Reversing4", "ekse0x", "the_s41nt", "DumpAnalysis", "ozamt", "Darkstack", "y0ug", "MatToufout", "matrosov", "crai", "aszy", "CERTXMCO", "agent_23_", "shydemeanor", "Aarklendoia", "angelodellaera", "OhItsIan", "NonAuxHausses", "ancrisso", "smaciani", "fdebailleul", "zohea", "nicolaslegland", "madgraph_ch", "Archlance", "Hainatoa", "_cuttygirl", "NicolasThomas", "reseau_unamipro", "widgetbooster", "lareponsed", "seb_godard", "ahmedfatmi", "kavekadmfr", "gitedemontagne", "rizzrcom", "Stefko001", "webpositif", "LucBernouin", "MangasTv", "FGRibrea", "marinemarchande", "twittconsultant", "Evangenieur", "greg32885", "hynzowebblog", "Twitchaiev", "SweatBabySweat_", "ovaxio", "PierreTran", "Mariegaraud", "cafesfrance", "populationdata", "Summy46", "sirchamallow1", "jpelie", "Technidog", "ju_lie", "blackwarrior", "cberhault", "julierobert", "sirchamallow", "xhark", "ga3lle", "Zebrure", "vitujc", "littlethom23", "DJKweezes",'CUSecTech', 'InfoSecHotSpot', 'IndieRadioPlay', 'TopMaths', 'ergn_yldrm', 'MegalopolisToys', 'ISC2_Las_Vegas', 'jeffreycady', 'XenDesktop', 'BugBountyZone', 'sciendus', 'Dambermont', 'ghwizuuy', 'hackmiami', 'smirnovvahtang', 'uncl3dumby', 'theStump3r', 'SecureAuth', 'StagesInfograph', '9gnews365', 'secmo0on', 'alexheid', 'XenApp', 'vleescha1', 'CMDSP', 'abouham92597469', 'NetNeutralityTp', 'puja_mano', 'AliSniffer', 'DrupalTopNews', 'ChromeExtenNews', 'sebastien_i', 'Techworm_in', 'argevise', 'windows10apps4r', 'primeroinfotek', 'HAKTUTS', 'ciderpunx', 'kfalconspb', 'whitehatsec', 'furiousinfosec', 'Trencube_GD', 'CtrlSec', 'hacking_report', 'n0psl', 'CryptoKeeUK', '0xDUDE', 'crowd42', '_HarmO_', 'CNNum', 'OxHaK', 'Paddy2Paris', 'RevueduDigital', 'androidapps4rea', 'cryptoland', 'CombustibleAsso', 'geeknik', 'HansAmeel', 'cryptoishard', 'YoouKube', 'jouermoinscher', 'moixsec', 'cyberwar', 'danielbarger67', 'SecurityNewsbot', 'cityofcrows', 'SysAdm_Podcast', 'shafpatel', 'k4linux', 'Refuse_To_Fight', 'x_adn', 'Duffray14', 'AbdelahAbidi', 'pranyny', 'razlivintz', 'unmanarc', 'wallarm', 'foxooAnglet', 'foxoo64', 'brainhackerzz', 'duo_labs', 'zenterasystems', 'jilles_com', 'partyveta760', 'ComixToonFr', 'doaa90429042', 'bestvpnz', 'aebay', 'suigyodo', 'parismonitoring', 'menattitude', 'BretPh0t0n', 'ChariseWidmer', 'racheljamespi', 'ZeNewsLink', 'Omerta_Infosec', '_plesna', 'LawsonChaseJobs', 'fredericpoullet', 'RogersFR', 'jesuiscandice7', 'jeanneG50', 'CryptoXSL', 'maccimum', 'foxtrotfourwbm', 'fido_66', 'AGveille', 'InfoManip', 'HiroProtag', 'jhosley', 'Netmonker', 'tetaneutralnet', 'DefiLocacite', 'MTCyberStaffing', 'thecap59', 'Max1meN1colella', 'CharlesCohle', 'BrianInBoulder', 'ArsneDAndrsy', 'BullFR', 'Five_Star_Tech', 'pourconvaincre', 'Be_HMan', 'click2livefr', 'ElydeTravieso', 'n0rssec', '_fixme', 'infographisteF', 'zephilou', 'puneeth_sword', 'CheapestLock', 'Eprocom', 'LocksmithNearMe', 'YoshiDesBois', 'databreachlaws', 'LDarcam', '_CLX', 'dreadlokeur', '_sinn3r', 'operat0r', 'Moutonnoireu', 'MatToufoutu', 'mubix', 'abcdelasecurite', 'meikk', 'MadDelphi', 'ec_mtl', 'unixist', 'EricSeversonSec', 'slaivyn', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'cabusar', 'julien_c', 'moswaa', 'lycia_galland', 'YrB1rd', 'DogecoinFR', 'corkami', 'Barbayellow', 'Spiceworks', 'dt_secuinfo', 'Yaagneshwaran', 'btreguier', 'TheStupidmonKey', 'follc', '2xyo', 'crazyjunkie1', 'LeCapsLock', 'gizmhail', 'piscessignature', 'JamiesonBecker', '_SaxX_', 'isgroupsrl', 'NuitInfo2K13', 'yenos', 'SecurityTube', 'Gameroverdoses', 'Brihx_', 'silvakreuz', 'DamaneDz', '_bratik', 'vprly', 'didierdeth', 'sudophantom', 'xxradar', 'Techno_Trick', 'malphx', 'wixiweb', 'ChrisGeekWorld', 'AmauryBlaha', 'LRCyber', 'FranckAtDell', 'netrusion', 'ubuntuparty', 'grokFD', 'CISOtech', 'NotifyrInc', 'marcotietz', 'accident', 'darthvadersaber', 'VForNICT', 'ID_Booster', 'yw720', 'AgenceWebEffect', 'JeanLoopUltime', 'guideoss', 'Security_FAQs', 'Oursfriteorchid', 'Gr3gland', 'caaptusss', 'ygini', 'videolikeart', 'Veracode', 'CyberExaminer', 'hackademics_', 'razopbaltaga', 'eric_kavanagh', 'Ikoula', 'LeBlogDuHacker', 'rexperski', 'MathieuAnard', 'ced117', 'Panoptinet', 'BuzzRogers', 'ITSecurityWatch', 'PatchMob', 'officialmcafee', 'hnshah', 'AnonLegionTV', 'sh1rleysm1th', 'soocurious', 'PremiereFR', 'mob4hire', 'ericosx', 'yesecurity', 'DLSPCDoctor', 'tyrus_', 'gritsicon', 'trollMasque', 'AmauryPi', 'OpenForceMaroc', 'CybersimpleSec', 'PorterHick', 'AllTechieNews', 'revvome', 'livbrunet', 'aeris22', 'InfoSecMash', 'gigicristiani', 'stephanekoch', 'leduc_louis', 'ilhamnoorhabibi', 'servermanagedit', 'GTAFRANCE', '1humanvoice', 'stmanfr', 'Current_Tech', 'PEGE_french', 'Kuzbari', 'iisp_hk', 'Facebook_Agent', 'ZeroSkewl', 'chuckdauer', 'Itsuugo', 'Florianothnin', 'neeuQdeR', 'HYCONIQ', 'disk_91', 'ZOOM_BOX_r', 'Rimiologist', 'Matrixinfologic', 'GeneralSeven', 'preventiasvcs', 'atmon3r', 'filowme', 'FcsFcsbasif', 'catalyst', 'Spawnhack', 'globalwifiIntl', 'CajunTechie', 'ConstructionFOI', 'k8em0', 'Flavioebiel', 'FlacoDev', 'Fibo', 'wisemedia_', 'floweb', 'adistafrance', 'AnonBig', 'tacticalflex', 'Katezlipoka', 'MathieuZeugma', 'SophiAntipolis', 'matalaz', 'edehusffis', 'patricksarrea', 'SnapAndShine', 'cryptomars', 'OpPinkPower', 'DidierStevens', 'patatatrax', 'AJMoloney', 'cheetahsoul', 'vxheavenorg', 'defconparties', 'gvalc1', 'clemence_robin', 'XeroFR', 'noncetonic', 'bonjour_madame', 'LeWebSelonEdrek', 'robajackson', 'greenee_gr', 'zahiramyas', 'nation_cyber', 'Rio_Beauty_', 'Sadnachar', 'SecRich', 'unbalancedparen', 'Fyyre', 'VirusExperts', 'Applophile', 'Aziz_Satar', 'SecretDefense', 'Hi_T_ch', 'wireheadlance', 'define__tosh__', 'hamsterjoueur', 'PUREMEDIAHDTV', 'secdocs', 'code010101', 'LagunISA', '_theNextdoor_', 'lefredodulub', 'i4ppleTouch', 'imatin_net', 'KiadySam', 'toiletteintime', 'espeule', '1er_degres', 'BSoie', 'Pintochuks', 'selphiewall479', 'ApScience', 'suivi_avec_lisa', 'TiffenJackson', 'SecretGossips', 'sarahMcCartney2', 'wheatley_core', 'PatSebastien']

Friends = ['AmyOh89','CyberToolsBooks','Manager_of_it','TheAdamGalloway','_seraph1','StanBoyet','rf','jckarter','forenslut','MyWhiteNinja','eevee','GossiTheDog','CiPHPerCoder','MickaelDorigny','whoismrrobot','b1ack0wl','shiftkey','DC503','gcaughey','rootsecdev','cyb3rops','falconsview','ggdaniel','RNR_0','Retidurc','teslawf','lanodan','Techworm_in','DrupalTopNews','AliSniffer','ghwizuuy','Dambermont','BugBountyZone','XenDesktop','simonashley','STIDIA_Security','514nDoG','emmercm','OSFact','fbajak','sambowne','chronic','hacks4pancakes','ra6bit','laparisa','InfoSec_Student','AScarf0','crashtxt','binitamshah','JZdziarski','qwertyoruiopz','Hackers_toolbox','xploit_This','Jamie__Da__Boss','J03_PY','pondeboard1', 'ceb0t', 'theStump3r', 'uncl3dumby', 'gr3yr0n1n', 'poa_nyc', 'Demos74dx', 'sebastien_i', 'HAKTUTS', 'R00tkitSMM', 'pondeboard', 'AcidRampage', 'IncursioSubter', 'BSeeing', 'evleaks', 'InfoSec_BT', 'HIDGlobal', 'kjhiggins', 'vkamluk', 'codelancer', 'ciderpunx', 'HugoPoi', 'kfalconspb', 'lconstantin', 'coolhardwareLA', 'fsirjean', 'h0x0d', 'RCCyberofficiel', 'Tech_NurseUS', 'whitehatsec', 'oej', 'Trencube_GD', 'cissp_googling', '_pronto_', 'CtrlSec', 'ModusMundi', 'SwiftOnSecurity', 'RichRogersIoT', 'jonathansampson', 'Luiz0x29A', 'StephenHawking8', 'dpmilroy', 'usa_satcom', 'hack3rsca', 'PELISSIERTHALES', 'g00dies4', 'rpsanch', 'furiousinfosec', 'Om_dai33', 'wulfsec', 'securiteIT', 'pavornoc', 'hacking_report', 'primeroinfotek', 'L4Y5_G43Y', 'PaulM', 'seclyst', 'cmpxchg16', 'iainthomson', 'e_modular', '_jtj1333', 'n0psl', 'blaked_84', 'tb2091', 'dfirfpi', 'manonbinet001', 'webmathilde', '0xDUDE', 'nn81', 'CryptoKeeUK', 'n1nj4sec', 'ydklijnsma', 'scanlime', '0x6D6172696F', 'nono2357', 'derekarnold', 'hasherezade', '_HarmO_', 'OxHaK', 'CWICKET', 'linuxaudit', 'Space__Between', 'lordofthelake', 'Hired_FR', 'Laughing_Mantis', 'InfoSecHotSpot', 'geeknik', 'CharlesCohle', 'BretPh0t0n', 'jilles_com', 'duo_labs', 'unmanarc', 'x_adn', 'k4linux', 'shafpatel', 'SysAdm_Podcast', 'Everette', 'DadiCharles', 'danielbarger67', 'quequero', 'SecurityNewsbot', 'cityofcrows', 'Dinosn', 'ibmxforce', 'thepacketrat', 'cryptoishard', 'DEYCrypt', 'attritionorg', 'mzbat', 'da_667', 'krypt3ia', 'Z0vsky', 'BSSI_Conseil', 'SecMash', 'corexpert', 'maldevel', 'pof', 'FFD8FFDB', 'Snowden', 'lexsi', 'bestvpnz', 'EnfanceGachee', 'samykamkar', 'pevma', 'kafeine', 'k0ntax1s', 'gN3mes1s', 'GawkerPhaseZero', 'FreedomHackerr', 'sec_reactions', '0xAX', 'nolimitsecu', 'bascule', 'm3g9tr0n', 'nbs_system', 'sn0wm4k3r', 'jivedev', 'd_olex', 'indiecom', 'BlueCoat', 'Tif0x', 'UnGarage', 'HomeSen', 'CTF365', 'Securityartwork', 'accessnow', 'ZeljkaZorz', 'mortensl', 'ThomasNigro', 'Sidragon1', 'garage4hackers', 'hanno', 'p4r4n0id_il', 'AsymTimeTweeter', 'Omerta_Infosec', 'nopsec', 'cyberguerre', 'Protocole_ZATAZ', 'Grain_a_moudre', 'BIUK_Tech', 'TMZvx', '_plesna', 'PhysicalDrive0', 'rodneyjoffe', 'ithurricanept', 'sec0ps', 'comex', 'deepimpactio', 'ClechLoic', 'AGveille', 'amzben', 'FIC_fr', 'EricSeversonSec', 'MalwarePorn', 'Odieuxconnard', 'unixist', 'LhoucineAKALLAM', '_langly', 'S2DAR', 'pwcrack', 'PhilHagen', 'Falkvinge', 'IPv4Countdown', 'lycia_galland', 'wirehack7', 'linux_motd', 'lamagicien', 'ubuntumongol', '_cypherpunks_', 'TekDefense', 'LeakSourceInfo', 'moswaa', 'OsandaMalith', 'Lope_miauw', 'dt_secuinfo', 'morganhotonnier', 'Relf_PP', 'abcderza', 'Barbayellow', 'corkami', 'KitPloit', 'ec_mtl', 'bugs_collector', 'BleepinComputer', 'Tinolle1955', 'valdesjo77', 'xombra', 'julien_c', 'Spiceworks', 'snipeyhead', 'YrB1rd', 'Trojan7Sec', 'Yaagneshwaran', 'ZATAZWEBTV', 'f8fiv', 'Netmonker', 'epelboin', '0xmchow', 'angealbertini', 'Incapsula_com', 'SurfWatchLabs', 'Exploit4Arab', 'hackerstorm', '2xyo', 'JamiesonBecker', 'NuitInfo2K13', '_SaxX_', 'piscessignature', 'crazyjunkie1', 'SecurityTube', 'comptoirsecu', '_saadk', 'penpyt', 'yenos', 'Intrinsec', 'udgover', 'jujusete', 'poulpita', 'suffert', 'clementd', '_CLX', '_bratik', 'tomchop_', 'vprly', 'mboelen', 'martijn_grooten', 'aristote', 'gandinoc', 'silvakreuz', 'ifontarensky', 'cedricpernet', 'y0m', 'knowckers', 'lakiw', 'didierdeth', 'paulsparrows', 'sudophantom', 'arbornetworks', 'AzzoutY', 'cabusar', 'Xartrick', 'netrusion', 'AmauryBlaha', 'Techno_Trick', 'wixiweb', 'hackhours', 'netbiosX', 'Daniel15', 'Routerpwn', 'asl', 'jeetjaiswal22', 'shoxxdj', 'FranckAtDell', 'ubuntuparty', 'jpgaulier', 'adulau', 'fredraynal', 'shu_tom', 'Cyberprotect', 'LRCyber', 'cymbiozrp', 'bitcoinprice', 'lafibreinfo', 'dreadlokeur', 'YoouKube', 'NotifyrInc', 'olfashdeb', 'MiltonSecurity', 'quota_atypique', 'TNWmicrosoft', 'LLO64', 'davromaniak', 'ID_Booster', 'VForNICT', 'klorydryk', 'vam0810', 'SecurityWeek', 'secludedITaid', 'montrehack', 'cvebot', 'chetfaliszek', 'NeckbeardHacker', 'hipsterhacker', 'AgenceWebEffect', 'marcotietz', 'erwan_lr', 'guideoss', 'sonar_guy', 'notsosecure', 'FlipFlop8bit', 'MalwareAnalyzer', 'yw720', 'SebBLAISOT', 'Cubox_', 'Ninja_S3curity', 'maximemdotnet', 'lea_linux', 'securitypr', '0xUID', 'MargaretZelle', 'Gr3gland', 'steveklabnik', 'iooner', 'caaptusss', 'tuxfreehost', 'ygini', 'Mind4Digital', 'ADNcomm', 'Veracode', 'hackademics_', 'xhark', 'TopHatSec', '0xSeldszar', 'PLXSERT', 'eric_kavanagh', 'IT_securitynews', 'devttyS0', 'Parisot_Nicolas', 'dclauzel', 'SCMagazine', 'JoceStraub', 'HackerfreeUrss', 'dascritch', 'aabaglo', 'ITConnect_fr', 'razopbaltaga', 'cargamax', 'MyOmBox', 'Wobility', 'evdokimovds', 'dookie2000ca', 'nuke_99', 'isgroupsrl', '_fwix_', 'LeBlogDuHacker', 'Ikoula', 'PortableWebId', 'OfficialGirish', 'httphacker', 'ripemeeting', 'ymitsos', 'Solarus0', 'Zestryon', 'ko_pp', 'etribart', 'TomsGuideFR', 'k3170Makan', 'jeeynet', 'qualys', 'KdmsTeam', 'frsilicon', 'astro_luca', 'rexperski', 'spiwit', 'nuclearleb', 'mcherifi', 'laVeilleTechno', 'framasoft', 'NyuSan42', 'nextinpact', 'PirateOrg', 'MathieuAnard', 'blesta', 'IPv6Lab', 'billatnapier', 'starbuck3000', 'jmplanche', 'pbeyssac', 'Keltounet', 'cwolfhugel', 'ZeCoffre', 'Dave_Maynor', 'durand_g', 'TMorocco', 'CyberExaminer', 'PatchMob', 'Nathanael_Mtd', '1nf0s3cpt', 'ospero_', 'ced117', 'LinuxActus', 'Panoptinet', 'schoolofprivacy', 'TrustedSec', 'maccimum', 'hadhoke', 'Jordane_T', 'novogeek', 'ChimeraSecurity', 'officialmcafee', 'GolumModerne', 'milw0rms', 'AsmussenBrandon', 'arnolem', 'Goofy_fr', 'AnonLegionTV', 'infoworld', 'soocurious', 'atarii', 'SebydeBV', 'JacquesBriet', 'ITSecurityWatch', 'SecurityFact', 'dorkitude', 'CISecurity', 'bishopfox', 'jeremieberduck', 'ericosx', 'dimitribest', 'levie', 'andreaglorioso', 'tyrus_', 'DLSPCDoctor', 'guiguiabloc', 'AlainClapaud', 'yesecurity', 'trollMasque', 'planetprobs', 'vincib', 'LeCapsLock', 'kafeinnet', 'Irrodeus', 'jbfavre', 'guestblog', 'rboulle', 'Fr33Tux', 'SecurityHumor', 'creoseclabs', 'm0rphd', 'argevise', 'gritsicon', 'veorq', 'Abdelmalek__', 'OpenForceMaroc', 'hashbreaker', 'AlexandreThbau1', 'MacPlus', 'yrougy', 'MaldicoreAlerts', 'AmauryPi', 'TrendMicroFR', 'sirchamallow', 'ACKFlags', 'jameslyne', 'LaNMaSteR53', 'AllTechieNews', 'garfieldair', 'PorterHick', 'arstechnica', 'sendio', 'CipherLaw', 'Golem_13', 'livbrunet', 'RealMyop', 'KenBogard', 'KarimDebbache', 'SmoothMcGroove', 'AlDeviant', 'Canardpcredac', 'SebRuchet', 'F_Descraques', 'Unul_Officiel', 'Poischich', 'drlakav', 'genma', 'lastlineinc', 'Cryptomeorg', 'CybersimpleSec', 'DarkReading', 'tqbf', 'gyust', 'KanorUbu', 'walane_', 'jedisct1', 'hadopiland', 'all_exploit_db', 'brutelogic_br', 'lechat87', 'gigicristiani', 'aeris22', 'terminalfix', 'ChristophePINO', 'ihackedwhat', 'InfoSecMash', 'bayartb', 'ErrataRob', 'DefuseSec', 'jcsirot', 'christiaan008', 'gopigoppu', 'lawmanjapan', 'RichardJWood', 'darthvadersaber', 'BryanAlexander', 'leduc_louis', 'distriforce', 'democraticaudit', 'PaulChaloner', 'kentbye', 'HacknowledgeC', 'servermanagedit', 'Coders4africa', 'securitycast', 'macbid', 'tomsguide', 'DrInfoSec', '1humanvoice', 'fsf', 'volodia', 'clusif', 'gbillois', 'theliaecommerce', 'JoshMock', 'MarConnexion', 'stmanfr', 'archiloque', 'ggreenwald', 'libdemwasjailed', 'inthecloud247', 'BlogsofWarIntel', 'pewem_formation', 'zdnetfr', 'Current_Tech', 'ilhamnoorhabibi', 'PEGE_french', 'Lu1sma', 'msftsecurity', 'ashish771', 'brutenews', 'iPhoneTweak_fr', 'my_kiwi', 'SilvaForestis', 'PierreTran', 'Kuzbari', 'r0bertmart1nez', 'yttr1um', 'hrousselot', 'crashsystems', 'benlandis', 'netsecu', 'securityaffairs', 'Stormbyte', 'iisp_hk', 'zonedinteret', 'Facebook_Agent', 'confidentiels', 'CryptoFact', 'chuckdauer', 'vriesjm', '_antoinel_', 'dhanji', '_reflets_', 'Anon_Online', 'MailpileTeam', 'Itsuugo', 'mdecrevoisier', 'freeboxv6', 'garwboy', 'StackCrypto', 'ChanologyFr', '_gwae', 'ashk4n', 'nzkoz', 'Florianothnin', 'neeuQdeR', 'UsulduFutur', 'BullGuard', 'samehfayed', 'olesovhcom', 'dragondaymovie', 'Itforma', 'HYCONIQ', 'axcheron', 'blakkheim', 'pressecitron', 'ChrisGeekWorld', 'episod', 'thalie30', 'disk_91', 'idfpartipirate', 'PPAlsace', 'FlorenceYevo', 'gdbassett', 'VulnSites', 'Secunia', 'iteanu', 'sciendus', 'esrtweet', '6l_x', 'MduqN', 'Skhaen', 'daveaitel', 'ZeroSkewl', 'Rimiologist', 'ekse0x', 'ZOOM_BOX_r', 'aanval', 'fhsales', 'Ruslan_helsinky', 'OpLastResort', 'fcouchet', 'GTAXLnetIRC', 'TheAdb38', 'DeloitteUS', 'GeneralSeven', 'AustenAllred', 'AlliaCERT', 'Double_L83', 'scoopit', 'Dylan_irzi11', 'fr0gSecurity', 'atmon3r', '0x736C316E6B', 'Hask_Sec', 'Zer0Security', 'xssedcom', 'php_net', 'phpizer', 'JpEncausse', 'M4ke_Developp', 'nkgl', 'preventiasvcs', 'SwiftwayNet', 'c4software', 'who0', 'gandi_net', 'H_Miser', 'nikcub', 'gcouprie', 'MindDeep', 'MdM_France', 'SpritesMods', 'NakedSecurity', 'GDataFrance', 'conciseonline', 'filowme', 'regislutter', 'CelebsBreaking', 'globalwifiIntl', 't2_fi', 'catalyst', 'x6herbius', 'cryptocatapp', 'arahal_online', 'mtigas', 'ALLsecuritySoft', 'lisachenko', 'renaudaubin', 'wamdamdam', '01net', 'secuobsrevuefr', 'DataSecuB', 'drambaldini', 'secu_insight', 'cyber_securite', 'smeablog', 'DecryptedMatrix', 'eCoreTechnoS', 'topcodersonline', 'Sec_Cyber', 'thegaryhawkins', 'CajunTechie', 'Othrys', 'jeromesegura', 'RazorEQX', 'Xylit0l', 'c_APT_ure', 'it4sec', 'ConstructionFOI', 'Official_SEA16', 'OpGabon', 'SecuraBit', 'esheesle', 'brutelogic', 'taziden', 'sam_et_max', 'iMilnb', 'Clubic', 'greenee_gr', 'fo0_', 'nathanLfuller', 'carwinb', 'puellavulnerata', 'samphippen', 'ntisec', 'dummys1337', 'flanvel', 'SUPINFO', 'Epitech', 'Erebuss', 'infobytesec', 'garybernhardt', 'mab_', 'wisemedia_', 'LagunISA', 'wiretapped', 'verge', 'crowd42', 'virusbtn', 'FlacoDev', 'SunFoundation', 'TheNextWeb', 'guillaumeQD', 'IBMSecurity', 'code010101', 'gvalc1', 'adistafrance', 'LeWebSelonEdrek', 'tacticalflex', 'imatin_net', 'espeule', 'Applophile', 'nation_cyber', 'zahiramyas', 'alexheid', 'SecMailLists', 'mob4hire', 'AnonBig', 'FloCorvisier', 'MathieuZeugma', 'Katezlipoka', 'w_levin', 'climagic', 'PartiPirate', 'InfosecNewsBot', 'nedos', 'jerezim', 'katylevinson', 'ThVillepreux', 'PBerhouet', 'dbbimages', 'irqed', 'BLeQuerrec', 'patricksarrea', 'pierre_alonso', 'Flameche', 'AndreaMann', 'SciencePorn', 'mvario1', 'AbbyMartin', 'TheGoodWordMe', 'chroniclesu', 'DoubleJake', 'Kilgoar', 'TylerBass', 'FievetJuliette', 'Reuters', 'mrjmad', 'Sebdraven', 'SophiAntipolis', 'LaFranceapeur', 'papygeek', 'gordonzaula', 'neufbox4', 'plugfr', 'BenoitMio', '_Kitetoa_', 'Numendil', 'laquadrature', 'kheops2713', 'benjaltf4_', 'Fibo', 'codesscripts', 'zorelbarbier', 'Be_HMan', 'FranceAnonym', 'SpartacusK99', 'Free_Center', 'TrucAstuce', 'schignard', 'ciremya', 'MatVHacKnowledg', 'FreenewsActu', 'XSSed_fr', 'planetubuntu', 'S_surveillance', 'cyphercat_eu', 'Hack_Gyver', 'ncaproni', 'MISCRedac', 'Cyber_Veille', 'journalduhack', 'bidouillecamp', 'Apprenti_Sage', 'Oxygen_IT', 'FIC_Obs', 'orovellotti', 'cyberdefenseFR', 'l1formaticien', 'Reseauxtelecoms', 'neuromancien', 'actuvirus', 'cryptomars', 'amaelle_g', 'Hybird', 'Monitoring_fr', 'Zythom', 'InfosReseaux', 'speude', 'lavachelibre', 'dezorda', 'Bugbusters_fr', '3615internets', 'planetedomo', 'Mayeu', 'HeliosRaspberry', 'CiscoFrance', 'anonfrench', 'IvanLeFou', 'NosOignons', 'OSSIRFrance', 'patatatrax', 'EFF', 's7ephen', 'kaspersky', '2600', 'cheetahsoul', 'OpPinkPower', 'AJMoloney', 'ecrans', 'anonhive', 'julien_geekinc', 'Anonymous_SA', 'USAnonymous', 'e_kaspersky', 'FSecure', 'ClipperChip', 'ax0n', 'hevnsnt', 'Aratta', 'yolocrypto', 'waleedassar', 'postmodern_mod3', 'kochetkov_v', 'pwntester', 'bartblaze', 'TheDanRobinson', 'unpacker', 'r_netsec', 'AnonymousPress', 'priyanshu_itech', 'kinugawamasato', 'mozwebsec', 'zonehorg', 'beefproject', 'YourAnonNews', 'boblord', 'vikram_nz', 'PublicAnonNews', 'kkotowicz', 'hackersftw', '0xerror', 'fancy__04', 'l33tdawg', 'node5', '0xjudd', '_mr_me_', 'sickness416', 'googleio', 'infosecmafia', 'p0sixninja', 'isa56k', 'TheWhiteHatTeam', 'inj3ct0r', 'snowfl0w', 'SocEngineerInc', 'jdcrunchman', 'DiptiD10', 'ehackingdotnet', 'jack_daniel', 'BrandonPrry', 'TurkeyAnonymous', 'MarkWuergler', 'pranesh', 'eddieschwartz', 'mozilla', 'deCespedes', 'M0nk3H', 'tpbdotorg', 'IPredatorVPN', 'smarimc', 'Thomas_Drake1', 'opindia_revenge', 'Malwarebytes', 'EHackerNews', 'HNBulletin', 'dietersar', 'CCrowMontance', 'r3shl4k1sh', 'DanielEllsberg', 'PMOIndia', 'SecurityPhresh', 'vxheavenorg', 'kgosztola', 'TheHackersNews', 'jeromesaiz', 'Trem_r', 'netsabes', 'Flaoua', 'DannyDeVito', 'p0sixn1nja', 'twitfics', 'wzzx', 'DustySTS', 'Lincoln_Corelan', 'SecureTips', 'InfoSecRumors', 'matthew_d_green', 'agl__', 'elwoz', 'apiary', '0xabad1dea', 'dangoodin001', 'kpoulsen', 'ethicalhack3r', 'SecBarbie', 'dguido', 'marcusjcarey', 'jadedsecurity', 'petitpetitam', 'hackeracademy', 'moreauchevrolet', 'Jean_Leymarie', 'tricaud', 'Nipponconnexion', 'OtakuGameWear', 'schneierblog', 'g4l4drim', '0x73686168696e', 'securityvibesfr', 'window', 'sm0k_', 'pentesteur', 'AlainAspect', 'chandraxray', 'AstronomyNow', 'Astro_Society', 'SpitzerScope', 'NASAspitzer', 'NASAWebb', 'NASAFermi', 'SpaceflightNow', 'NASAStennis', 'sciam', 'WISE_Mission', 'NASA_Images', 'NatGeo', 'NASAblueshift', 'universetoday', 'NASAJPL_Edu', 'NASA_Orion', 'TrinhXuanThuan', 'Infographie_Sup', 'MartinAndler', 'pierenry', 'Bruno_LAT', 'RichardDawkins', 'guardianscience', 'TheSkepticMag', 'TomFeilden', 'gemgemloulou', 'AdamRutherford', 'Baddiel', 'DrAliceRoberts', 'ProfWoodward', 'SarcasticRover', 'robajackson', 'MarsCuriosity', 'BBCBreaking', 'shanemuk', 'Schroedinger99', 'AtheneDonald', 'imrankhan', 'danieldennett', 'paulwrblanchard', 'MartinPeterFARR', 'DPFink', 'sapinker', 'chrisquigg', 'minutephysics', 'AdamFrank4', 'SpaceX', 'astrolisa', 'Erik_Seidel', 'simonecelia', 'PhilLaak', 'TEDchris', 'colsonwhitehead', 'plutokiller', 'dvergano', 'carlzimmer', 'j_timmer', 'edyong209', 'Laelaps', 'bmossop', 'maiasz', 'ericmjohnson', 'WillmJames', 'BadAstronomer', 'billprady', 'reneehlozek', 'PolycrystalhD', 'BoraZ', 'sethmnookin', 'albionlawrence', 'RisaWechsler', 'seanmcarroll', 'imaginaryfndn', 'PhysicsNews', 'DiggScience', 'bigthink', 'PopSci', 'AIP_Publishing', 'NSF', 'NewsfromScience', 'BBCScienceNews', 'PhysicsWorld', 'ScienceNews', 'physorg_com', 'TED_TALKS', 'TreeHugger', 'physorg_space', 'physorg_tech', 'NASAGoddard', 'CERN_FR', 'neiltyson', 'ProfBrianCox', 'SethShostak', 'b0yle', 'NASAJPL', 'worldofscitech', 'michiokaku', 'OliverSacks', 'AMNH', 'JannaLevin', 'bgreene', 'AssoDocUp', 'MyScienceWork', 'ParisDiderot', 'molmodelblog', 'neilfws', 'pjacock', 'dalloliogm', 'yokofakun', 'mrosenbaum711', 'joshwhedon', 'BrentSpiner', 'moonfrye', 'greggrunberg', 'Schwarzenegger', 'RealRonHoward', 'arnettwill', 'AmandaSeyfried', 'JasonReitman', 'DohertyShannen', 'JohnStamos', 'frankiemuniz', 'TheRealNimoy', 'EyeOfJackieChan', 'dhewlett', 'ZacharyLevi', 'MillaJovovich', 'JohnCleese', 'BambolaBambina', 'CERN', 'CNES', 'Inserm', 'NASA', 'USGS', 'NatureNews', 'Planck', 'IN2P3_CNRS', 'Inria', 'INC_CNRS', 'tgeadonis', 'inp_cnrs', 'AlainFuchs', 'CNRSImages', 'FabriceImperial', 'CNRS', 'laurentguyot', 'consult_detect', 'NewsBreaker', 'ISS_Research', 'nicolaschapuis', 'PolarisTweets', 'uncondamne', 'veytristan', 'gplesse', 'MattBellamy', 'LeParisien_Tech', 'Pontifex_fr', 'DenisCourtine', 'PascalDronne', 'NSegaunes', 'LeParisien_Buzz', 'NoemieBuffault', 'LesInconnus', 'FBIBoston', 'Pascallegitimus', 'lucabalo', 'isabellemathieu', 'FlorentLadeyn', 'NaoelleTopChef', 'quentintopchef', 'julienduFFe', 'natrevenu', 'yannforeix', 'defrag', 'rybolov', 'securid', 'stacythayer', 'tcrweb', 'Techdulla', 'TimTheFoolMan', 'treguly', 'YanceySlide', 'golfhackerdave', 'liquidmatrix', 'jonmcclintock', 'infosecpodcast', 'HypedupCat', 'Hak5', 'georgevhulme', 'gcluley', 'gattaca', 'g0ne', 'EACCES', 'digininja', 'devilok', 'd4ncingd4n', 'CSOonline', 'anthonymckay', 'abaranov', 'aaronbush', '_LOCKS', 'security_pimp', 'teksquisite', 'blpnt', 'alpharia', 'jgarcia62', '_MC_', 'InfoSec208', 'SPoint', 'i0n1c', 'torproject', 'room362', 'nicowaisman', 'VirusExperts', 'DavidHarleyBlog', 'follc', 'episeclab', 'manhack', 'pollux7', 'y0ug', 'Hallewell', 'SteveGoldsby', 'polarifon', 'malwarecityFR', 'Webroot', 'Infosanity', 'BitDefenderAPAC', 'VirusExpert', 'securitypro2009', 'blackd0t', 'securityfocus', 'DanaTamir', 'securitywatch', 'securitynetwork', 'PrivacySecurity', 'securitystuff', 'myCSO', 'RSAsecurity', 'SecurityExtra', 'WebSecurityNews', 'web_security', 'SCmagazineUK', 'TechProABG', 'malwareforensix', 'stephanekoch', 'daleapearson', 'CyberSploit', 'veryblackhat', 'opexxx', 'Hakin9', 'EvilFingers', 'isaudit', 'SpiderLabs', 'securegear', 'gdssecurity', 'ioerror', 'yaunbug', 'dstmx', 'zentaknet', 'wireheadlance', 'TenableSecurity', 'secdocs', 'proactivedefend', 'racheljamespi', 'xxradar', 'aebay', 'vincentzimmer', 'xanda', 'MarioVilas', 'sting3r2013', 'SecRich', 'deanpierce', 'HaDeSss', 'Jolly', 'searchio', 'thomas_wilhelm', 'gollmann', 'HackerTheDude', 'ADMobilForensic', 'SecurityStream', 'gadievron', 'tomaszmiklas', 'irongeek_adc', '_____C', 'operat0r', 'carne', 'fmavituna', 'PandaSecurityFR', 'freaklabs', 'alphaskade', 'hgruber97', 'noncetonic', 'AVGFree', 'k0st', 'kargig', 'lgentil', 'andreasdotorg', 'redragonvn', 'theharmonyguy', 'NoSuchCon', 'b10w', '0security', 'Z3r0Point', 'bortzmeyer', 'ahoog42', 'gianluca_string', 'eLearnSecurity', 'k4l4m4r1s', 'issuemakerslab', 'matalaz', 'ForcepointLabs', 'iExploitXinapse', 'itespressofr', 'ehmc5', 'practicalexplt', 'Pentesting', 'avkolmakov', 'manicode', 'HITBSecConf', 'sensepost', 'TeamSHATTER', 'n00bznet', 'thegrugq', 'judy_novak', 'TaPiOn', 'revskills', 'randomdross', 'malphx', 'OpenMalware', 'syngress', '2gg', 'GNUCITIZEN', 'chrissullo', 'michael_howard', 'c7five', 'pdp', 'securosis', 'Shadowserver', 'BlackHatHQ', 'securityincite', 'bsdaemon', 'Secn00b', 'dyngnosis', 'mwtracker', 'BorjaMerino', 'packetlife', 'toolcrypt', 'hackmiami', 'OWASP_France', 'jkouns', 'Mario_Vilas', 'zate', '_supernothing', 'aszy', 'lestutosdenico', 'espreto', '_sinn3r', 'aloria', 'Fyyre', 'SymantecFR', 'aircrackng', 'hackerschoice', 'MuscleNerd', 'smalm', 'OxbloodRuffin', 'subliminalhack', 'bannedit0', 'armitagehacker', 'RealGeneKim', 'mxatone', 'Snort', 'rebelk0de', 'hackingexposed', 'virustotalnews', 'InfiltrateCon', 'aramosf', 'msfdev', 'ChadChoron', 'n0secure', 'ITRCSD', 'CyberDefender', 'ArxSys', 'lulzb0at', 'crypt0ad', 'Stonesoft_FR', 'LordRNA', 'WindowsSCOPE', 'yo9fah', 'michelgerard', 'NAXSI_WAF', 'v14dz', 'x0rz', 'tbmdow', 'kasperskyfrance', 'Agarri_FR', 'ISSA_France', 'Jhaddix', 'Heurs', 'PlanetCreator', 'infernosec', 'rexploit', 'ConfCon', 'securityshell', 'bonjour_madame', 'minusvirus', 'emiliengirault', 'dvrasp', 'virtualabs', 'rfidiot', 'ttttth', 'msuiche', 'Ivanlef0u', 'Korben', 'hackersorg', 'shell_storm', 'WTFuzz', 'MoonSols', 'newsoft', 'vnsec', 'in_reverse', 'hackerfantastic', 'mtrancer', 'datacenter', 'stelauconseil', 'CNIL', 'exploitdb', 'BillBrenner70', 'lagrottedubarbu', 'HackingDave', 'VUPEN', 'siddartha', 'bluetouff', 'sstic', 'ToolsWatch', 'emmasauzedde', 'lseror', 'bearkasey', 'xme', 'helpnetsecurity', 'hackinthebox', 'Transiphone', 'hackaday', 'TheSuggmeister', 'Herve_Schauer', 'humanhacker', 'it_audit', 'Jipe_', 'FredLB', '0vercl0k', 'secbydefault', 'kerouanton', 'dragosr', 'endrazine', 'HBGary', 'pentestit', 'madpowah', 'serphacker', 'security4all', 'SecuObs', 'vloquet', 'joegrand', 'matrosov', 'DIALNODE', 'brucon', 'corelanc0d3r', 'RSnake', '0xcharlie', 'taviso', '41414141', 't0ka7a', 'thedarktangent', 'mubix', 'jonoberheide', 'spacerog', 'ChrisJohnRiley', 'securityninja', 'threatpost', 'nasko', 'mwrlabs', 'justdionysus', 'iHackwing', 'DJLahbug', 'cyber_security', 'hardhackorg', 'e2del', 'a41con', 'msftsecresponse', 'sans_isc', 'egyp7', 'antic0de', 'mikko', '_MDL_', 'mdowd', 'carnal0wnage', 'jeremiahg', 'xorlgr', 'cesarcer', 'BlackHatEvents', 'MatToufoutu', 'csec', 'selectrealsec', 'CERTXMCO', 'SecuritySamurai', 'razlivintz', 'etcpasswd', 'The_Sec_Pub', 'meikk', 'securityweekly', 'alexsotirov', 'DidierStevens', 'beist', 'stalkr_', 'dakami', 'halvarflake', 'dinodaizovi', 'silviocesare', 'stephenfewer', 'barnaby_jack', 'andremoulu', 'thierryzoller', 'PwnieAwards', 'reversemode', 'kalilinux', 'gynvael', 'pusscat', 'abcdelasecurite', 'johnjean', 'ninjanetworks', 'sotto_', 'SecretDefense', 'FFW', 'commonexploits', 'x86ed', 'zsecunix', 'hack_lu', 'Majin_Boo', 'BadShad0w', 'FlUxIuS', 'valuphone', 'free_man_', 'teamcymru', 'ihackstuff', 'secureideas', 'sansforensics', 'benoitbeaulieu', 'LaFermeDuWeb', 'TwitPic', 'noaheverett', 'lostinsecurity', 'democracynow', 'dougburks', 'zephilou', 'kevinmitnick', 'defcon', 'SecurityBSides', 'haxorthematrix', 'rmogull', 'unbalancedparen', 'perfectvendetta', 'siccsudo', 'Nan0Sh3ll', 'newroot', 'ClsHackBlog', '27c3', 'c3streaming', 'SOURCEConf', 'eugeneteo', 'moxie', 'dlitchfield', 'thezdi', 'scarybeasts', 'ryanaraine', 'kernelpool', 'esizkur', 'richinseattle', 'WeldPond', 'k8em0', 'jduck', 'ultramegaman', 'tsohlacol', 'HeatherLeson', 'myrcurial', 'nudehaberdasher', 'drraid', 'Agarik', 'Aziz_Satar', 'hackinparis', 'sdwilkerson', 'Satyendrat', 'LawyerLiz', 'UnderNews_fr', 'deobfuscated', 'HacKarl', 'StopMalvertisin', 'djrbliss', 'TinKode', 'HappyRuche', 'rssil', 'sysdream', 'acissi', 'migrainehacker', 'xsploitedsec', 'sucurisecurity', 'bonjourvoisine', 'Sorcier_FXK', 'mikekemp', 'jaysonstreet', 'roman_soft', 'xavbox', 'HackBBS', 'securitytwits', 'Hi_T_ch', 'DarK_Kiev', 'lbstephane', 'hugofortier', 'bl4sty', 'kaiyou466', 'Thireus', 'Paul_da_Silva', 'fbaligant', '_metalslug_', 'ochsff', 'fjserna', 'JonathanSalwan', 'ericfreyss', 'julianor', 'j00ru', '0xGrimmlin', 'define__tosh__', 'hesconference', 'Calculonproject', 'ZenkSecurity', 'Moutonnoireu', 'newsycombinator', 'securityh4x', 'corbierio', 'Security_Sifu', 'str0ke', 'owasp', 'milw0rm', 'gsogsecur', 'USCERT_gov', 'packet_storm', 'CoreSecurity', 'CiscoSecurity', 'ECCOUNCIL', 'securityweb', 'debian_security', 'ubuntu_security', 'SocialMediaSec', 'offsectraining', 'JournalDuPirate', 'ThisIsHNN', 'nmap', 'metasploit', 'orangebusiness', 'tixlegeek', 'rapid7', 'defconparties', 'ProjectHoneynet', 'NoWatch', '1ns0mn1h4ck', 'zataz', 'r00tbsd', 'hackerzvoice', 'JournalDuGeek', 'Senat_Direct', 'franceculture', 'MetroFrJustice', 'MrAntoineDaniel', 'tanguy', '_clot_', 'Reuno', 'chiptune', 'nicolasfolliot', 'johnmartz', 'lifehacker', 'Vfalkrr', 'AurelieThuot', 'PinkPaink', 'jnkboy', 'ManardUV', 'AsherVo', 'Stephan_Kot', 'thatgamecompany', 'Dedodante', 'RomainSegaud', 'TheMarkTwain', 'Maitre_Eolas', 'jmechner', 'SeinfeldToday', '5eucheu', 'FRANCHEMENT_', 'SuricateVideo', 'alainjuppe', 'antoine64', 'ydca_nico', 'aleksou', 'docslumpy', 'jeremy345', 'TRYWAN', 'UrielnoSekai', 'Mister_AlAmine', 'KrSWOoD', 'hamsterjoueur', 'JyanMaruku', 'insertcoinFR', 'MisterAdyboo', 'MrBouclesDor', 'Gorkab', '____Wolf____', 'Ben_MORIN', 'lestortuesninja', 'neocalimero', 'Sadnachar', 'KazHiraiCEO', 'Bethesda_fr', 'ChrisToullec', 'Juliette1108', 'RisingStarGames', 'LtPaterson', 'VGLeaks', 'SonySantaMonica', 'l87Nico', 'Yatuu', 'cbalestra', 'yosp', 'twfeed', 'ludaudrey', 'RpointB', 'danielbozec', 'LiveScience', 'Rue89', 'ScienceChannel', 'ScienceDaily', 'ubergizmofr', 'Gizmodo', 'Virgini2Clausad', 'fabriceeboue', 'ThibBracci', 'labeauf', 'waterkids', 'MisterMcFlee', 'FranckLassagne', 'GraiggyLand', 'Galagan_', 'BenCesari', '_RaHaN_', 'Tris_Acatrinei', 'Valent1Bouttiau', 'Julien_Bouillet', 'UncleTex', 'Suchablog', 'laboitecom', 'coverflow_prod', 'TeamTerrasse', 'IGmagazine', 'Wael3rd', 'Rogedelaaa', 'starcowparis', 'liloudalas', 'emanu124', 'xfrankblue', 'K0RSIK0', 'UlycesEditions', 'Djoulo', 'cabanong', 'laureleuwers', 'clemence_robin', 'suriondt', '_Supertroll', 'Neveu_Tiphaine', '_theNextdoor_', 'tomnever', 'DavidChoel', 'Elmedoc', 'Delzarissa', 'Nolife_Online', 'NicolAspatoule', 'Frederic_Molas', 'Marcuszeboulet', 'PlayStation', 'RockstarGames', 'Naughty_Dog', 'notch', 'pirmax', 'miklD75', 'ClorindeB', 'NathalieAndr', 'ODB_Officiel', 'LeGoldenShow', 'HIDEO_KOJIMA_EN', 'damiensaez', 'DIEUDONNEMBALA', 'FQXi', 'PerleDuBac', 'SatoshiKon_bot', 'shin14270', 'tsamere', 'Bouletcorp', 'CasselCecile', 'RaynaudJulie', 'LionnelAstier', 'swinefever', 'normanlovett1', 'SteveKeys66', 'DannyJohnJules', 'LeoDiCaprio', 'wikileaks', 'TORDFC', 'RedDwarfHQ', 'DalaiLama', 'Al_Hannigan', 'AnthonySHead', 'SteveMartinToGo', 'bobsaget', 'gwenstefani', 'JohnMCochran', 'ActuallyNPH', 'CobieSmulders', 'alydenisof', 'jasonsegel', 'kavanaghanthony', 'RafMezrahi', 'BellemareOut', 'BellemarePieR', 'rataud', 'piresrobert7', 'beigbedersays', 'IamJackyBlack', 'oizo3000', 'ericetramzy', 'yannlaffont', 'michel_denisot', 'VincentDesagnat', 'PaulMcCartney', 'Pascal__Vincent', 'JimCarrey', 'simonastierHC', 'manulevyoff', 'GillesLellouche', 'axellelaffont', 'xaviercouture', 'emougeotte', 'bernardpivot1', 'sgtpembry', 'Xavier75', 'NicolasBedos1', 'Chabat_News', 'stephaneguillon', 'farrugiadom', 'francoisrollin', 'kyank', 'levrailambert', 'lolobababa', 'jimalkhalili', 'alexnassar', 'suivi_avec_lisa', 'Suzuka_Nolife', 'DavidHasselhoff', 'CCfunkandsoul', 'CaptainAJRimmer', 'DougRDNaylor', 'bobbyllew', 'katherineravard', 'ReizaRamon', 'kaorinchan', 'NolifeOfficiel', 'floweb', 'Thugeek', 'LoloBaffie', 'charlottesavary', 'SebRaynal', 'GirlButGeek', 'bjork', 'YOUNMICHAEL', 'hartza_info', 'ApScience', 'ApertureSciCEO', 'wheatley_core', 'ApertureSciPR', 'lilyallen', 'koreus', 'MichaelYoun']

banlist = ['guess who','normal life','trading','adorable','quarts de finales','#dofus','dofus','oh my gof','BBC',' goals','george Soros',' rumors ',' rumor ','rumored','game of throne','trophy',' Messi ','welcome to my','RT !','urgent','#ad','promo!','promo:','promo ','#promo','@neutrogena','@romain_tmb77','crack open','etsy','wedding','emotion','now everyone','researchers','pinpoint','romain virgo','@playoverwatch',' ads ','crack me up','crack me up!','crack me up!!','selfie','selfies','#taekook','#blogger','#seotools','battu le record','bronze game','need an alternative','sponsor','dress for','dress ','the job you want','@performgroup','has acquired','now playing','miss kenya',' feat ','feat:','feat!','feat.','come to see','#nerve','dare blew your','charlie hebdo','#hollande','une ordure','you dare','#inspiration','dare you to','#CWGGETSIT','your mind!','your mind:','your mind.','pages article','page article','#leaves','#teabag','#printing','garden','#watercolour','#nature','lifepoems','unfair','even cross ','#contemporaryphotography','#contemporaryart','#DigitalArt','#MixedMedia','#storm','#photography','#Fineart','#miniature','#carving','#glass','#sculpture','#wood','sculture','oh boy','bit scary','@sansnetwars','#netwars','students:','students!','scoreboard','thecustos','fuck.','@sanspentest','digital communication','golden age','@securitycharlie',' hotel ','hotels',' top ','follow friday:','followfriday!','follow friday!','followfriday','FollowFriday:','@robaeprice','nauru files','@xor','clear-cut','clear cut','that article','this article','@da_766','tweetstorm','a DM ',' morano ','traffic mess','biopsy','biopsy:','laundry','folding','#FightRansomware','retail store','funny how','#itsfunnyhow','@aerochivette','@mclrapper','abused children','children','death threats','@Kenyapower_care',' bills ','#Gogreen','#fracking','#BLM','#equality','#feminism','#Socialist','#NC','give it a try','trick.','contextures','quick way','#leadership',' kick ','bicycle kick','what a performance',' goal ','@ziarecords','tickets','@kayla_izaa','to com fome','IDF_Emploi',' CDD ','CDD ','CDI ',' CDI ','Rt if you','RT until','RT for','RT to','la rentr','scolaire','thanks @','colissimo','#colissimo','en dm ','canard encha','today!','how to','blog post:','content is king','#kindstore','make life easier','my geek','#1J1P','article de @',' geek ','is out.',' thank you for','learn to crack','learn to hack','like a pro','my butt','clean my crack','had sex','have sex','@madisynpoops','butthole','it solution','IT solutions','minute maid','smart socket',' election ','existential war','war between',' to consider ',' introduces ',' child ',' blonde ','@engadget','@biosshadow','surprised','foggy','headlight','announcing','sitrep:',' Sells ','#insidertrading','i voted for','novel','& more','#mhd',' course ','low cost','avenue','motor city','olympiques',' affrontera ','obscene','JazminconJ',' martes ','LCarvalhoSe','education','medecine',' meeting ',' starbuck ','woot woot','#PS4share','soraf.',' soraf ',' roman:','@virginieMartin_',' romans ',' roman ','#myths','facts:','fact:','@benoisdorais',"coupure d'eau",'dld.bz','hubs.ly','is great!','paper is great','paper is out','shmz.me/gof','surpise','@fashionmask','missing out','@waterstonesTRU','gof award','winner:','winner!','Julian assange lied','follow @','OM_Officiel','@objectif_Match','om.net','Omtv','nouvelle saison','in the usa','in USA','@smolaaron','haking','followed',' queen ','#sorry','beliebers','dlvr.it','recommendation','@roganrichards','@theflexwebsite','fuck by','fucked by','case open','sheriff','daycare','bible.com','dieu','must see','must watch','must read','bloggers','#burkini','burkini','el_manchar','#ediscovery','Scratoch13',' gobert ',' batum ',' match ','un match','#geek','my latest','for cyber','download now','#gaming','for student','for student:','back to school','back to school?','thnku','thankyou','thankyou!','reduced attack','surprised?','#threathunting','ebola','how are you','instagram','tumblr','@wearetroopers','troopers.de','is out:','putain','RT &','t-shirt','pour gagner','gagner','RT & FOLLOW','terreur','sdxcentral','awareness',' adore ','@ouestfrance','lolgique','#honte','employee','diacquenod','damnrealpost','childish','quoique','@Glen_Hansard','learn why ','usatodaytech','the movie','movie.','from movie','band show','glen hansard','cio.com','where does ','very interesting',' zoo ','IGNFRA','premium','ln.is',' via @','via @','Us politician','linkdin.com','girl','fck you','fck u','interesting article','interesting blog','interesting report','echoplex',"no man's sky",'understanding the ','sebbrantigan.net','hypnotic','hypnotic.','[video]','seb lester','seb lester.','calligraphy','mmorpg','multi player','multiplayer','surgery','avoid tunneling','phreaking out','businessinsider.com','@Najizzlee_','bienvenu','@JesusOfficiel','sourire','willie henry','NFLD','backfield','nigeria','game of throne',"y'll","y'all",'veronica','@shadygagafacts','add me on','charity',' starring ',' anally ','#payforyourporn','manga','how to secure','how to protect','how to prevent','going viral','#finance','you need to know about ','music:','xinmad','our report','thx to ','racist','racisme','need to focus','tete de ','mort',' it out!','quaterfinals','inter milan','juventus','kookmin_ph','i need u','top content','#impression',' jazz ','relationship','#family','masked singer','bbcpress','peach girl','heads up','heads up!','hardwear','@hardwear_io','listen to','buff.ly','making so much money?','explains it all.','prier','priaient','subscription',' suites for ','free:','free.','free?','city council','can you dm ','want to help.','bande de ','les feug','les juifs','les musulmans','camping','olympic','my camera',' Thank to ','beyonc','coverage,','review:','member of parliament','fb.me','@ArtByAlida','@randileeharper','catches fire','jobs?',' jobs ','flamecon','#flamecon','@Regrann','#Regrann','from anonymous_truthseeker ','my lord','good lord','valuable','volunteers','#overwatch','team strategy','nuclear payload','protect your','high school','trib.al','trespassing','his stats','the eagles','click to apply',' our latest ','see our latest','find out','happy','13wham.com','main st.','south','west','north','East','intersection','hit by car','proud to','bright light','accident','east loop','west loop','north loop','south loop','ozarkcrone','devil root','head root','cinema','listening','writer','writers','@whoa_dere_Root','fcw.com','good article','design','square root','headlines','pay phone','babe','article generator','#seoservice','one click','new seo','how fluent is','curriculum',' join ',' nude ','nudity','submission','work hard',' navy ','my favourite','stay anonymous','help save',' your chance to ','lessons',' my tl ','spannish people','bizinsider','spell check','new','doctors','panama papers','@lupinion','get the news','language meaning','#WAA2017','gospel','anonymous extraodinary','#Manbij','#raqqa','anonymous heroes','should follow','top minutes','guide to ',' from anonymous','hell out','guns','gun','must have','book award','get ur','get your','medical','understand why','is a part of',' by anonymous','questionnaire','questionnaire.','last chance to ','to become','fellow!','follow friday','follow:','#ff','follow!','tuppu.net','costume','gnome hat','web series','velcro',' racing ','to help!',' RT to help!','strategic','sport ','sport cap','sports cap','Casual sport','.sport',' sport ','sport','headware','#DawgPound','DawgPound','browns_fanly','warrant',' cap ','ebay.to','#polo','#wool','Ralf lauren','shooting','pretty','love you','love u','have you ','way to go','judge others','judging other','judge other','judging others','#humor','humor','jokes','joke','.please',' please ','Please','escort','angel','by clicking>','slingshot','amazon.com','book','back against','tool discussion','brian taylor','books by ',' pop music ',' Steps to ',' Steps for ','courage','our new','See our new','pic of the','via @YouTube','NMAP project','mdr','RT if','Our favorite ','-Anonymous','dance',' win ','tribute','the book','could lead to ','athletic','haters','hater','troll','trolling',' by @','read about our',' Thanks ','do it for you','stay safe','good manners','bourne','McFarland_Shawn','check these ','#RTPodcast','income','chewy','butter','peanut','i am too dim','vacation',' bible ','parawine.com','#vino','proud to be ',' via ',' step ',' visit our ','@RICH_1337','redbull','#RBCP','skateboard','comment choisir','#skateboard','#sport','@KEEMSTAR','Pussy','shipping','your fav','#VAtraffic','vatraffic','main line','lane','road','root beer','@pardus','BREAKING: ','root canal','#podernFamily','join me','jason bourne',' rain ','forest','share it','CC: @','#Entreprise','the enterprise ',' with our ','benefit','benefits','sold out','for sales','sales','sale','discount',' Entrepise ','@WhiteSourceSoft',' with our most ',' business ','limited time','register now','RT for','via','the week','this week','lawfare','periodic table','happiness',' Strategies to ',' principles to ',' Approaches for ','Empowers','real friends','interested to see','#startup','have won','real madrid','books by:','books by ','pop music','Steps to ','steps for ','great read','great article','harassing','essential','come by','See our new','wallpaper','your company','attack of the week','of the month','of the day','our favorite','to suit every need','#hosting','vineyard','#shellcompanies','astro','country','awards show','#specialed','wrestling','champion','anonymous defender','breakout!','writer contest','fiction contest',' micro fiction ','micro fiction','indoor','fan','fans','#publichealth','epidemic','-anonymous.','Led zeppelin','30secondrock','my dick','anonymous girl',' get your ','hospital','available for download','dont miss','Hockey','season','man who attacked','poverty',' moth ',' classroom ','WTOPtraffic','moth trap','moths','#moth','butterfly','#butterfky','@youtube','youtube','WHITE PAPER:','gameplay','check it out','check out','god','survey','congrat','million views','ronaldo','Visual noise','#art',' art ','fan art','drawing','attack me',' poll ','mcflurry','ebonychicks','ebonychicks.us','#Black','foreign aff','5 reasons','2 reasons','girlfriend','3 Reasons','quantico','#quantico',' Health ','be sure to','@_TFlow','god bless','blessing','#Blessing',' wsh ','wesh','vacances','no fake','rt si ','nellawiak','fud admission','about publishing','minesota','we win','we lost','rebeu','send your cvs','hiring','hot girl','hot girls','panties','pants',' books ','#books','-anonymous','falling in reverse','the best ways','I liked a @Youtube video',' rio ','#rio',"l'exploit",'free>','free:','free!','free!"','daily','what is ','we do not forget','we do not forgive','donate 2','#winemaker','winemaker','stand up 4','meadows','innovation','click here>','click here:','click here','out now','stop by the','weekend','championship','marriage','granite','#groundzero','9/11','heart attack:','#SAFCSquad','Be part of the','Donate for','Donate to','Donate via','mini heart attack','heart attack','heroin','look hot','gluten','fuck off','thank u ','how on earth','Scoops,','soundcloud',' stoned ',' Snoop ','thanks for','embracing','liveleak','killed','UKBizCircle','fuck ',' vibes ','smoking','come see','my book','thnks to','thanks to','portfolio','vagina',' soul ','church','#pafc','pls share','watch how','album','so excited to','so excited about','#tip','canonical mission',' gym ','how dare you','diamond','is out!','gary jhonson','skimming the','skimming through','weather',' winds ','heavy rain','did you know','did you know ','did you know?','secret war','harambe','team rocket','tatoo',' pool ','grammar',' spurs ','linkedin.com','Teaches us','download this','#jobsearch','#jobs','pasadenadaisy.com','accepting submissions','the yellow dog project','CVE program','#CVE Program','concours','suck my dick','#kingpin','coming soon','vine.co','want to see private shots of the girls you know from facebook','John Curran','ethnographic','submit here:','micro-fiction','une playlist @YouTube','urologists','howtoquitworking','quit working','#entrepreneur','flash fiction','sold out','inb4','americans','watch out for','university','@Kingpin_Picks','what does the future of ','t forget to ','#ebook','ebook','footer text','cheese','#cheese','taco','#taco','thezoereport','to extend the life',':"please make a contribution','wrisbands','lifestyle','cheat sheet','green arrow','transforming field service:','holydays','holyday','visit our new','#scoop','#scoops','paper.li','i added a video to','Keep You Privacy','GTA','web hosting firm','reasearcher hides','#Health','probiotic','some salted','Telegram explains','rot in hell','smoothie','#fishing','#fish','fish','fishing','vandals','lmaoo','skimming the pool','bbc.in','skimmer','black skimmer','Olympics','learn about','Richard brain','christians','big week','superman','lovecraft','bowie','canonical evidence','enroll in our','interested in ','can boost','bourdieu','can help you be more','embracing','common','#teen','teen','t miss our','t miss your','why your','#scotland','watch:','from being hacked','sec network','cartel','middle man','food violation','#business','Lmao','giveaway','gambling','american flag','miss our','alabama','lawyers','blood shortage','breaking:','the song','middle school','sabmiller','tv network','most common','lures','#management','fdp',' mdr ',' fdp ','simple tricks','new blog','ground floor','#entreprise','football','bradley maning','chelsea chainsow','did you hear?','chicago',' tips ',' tip ','10 ways','3 ways','5 ways','4 ways','clothe','shopping','creature','6 steps','3 steps','4 steps','5 steps','malcolm in the middle','special offer','special photo','rtsi t','white girl','black ppl','white ppl','black people','White people','antisemit','Great blog','les noirs','les arabes','les noir','illuminati','you later','earnings',' earning','weekly','whore','foxnews','loyalists','swallow','trending','top three','top ten','top five','party',' story ',' story','my favorite',' vine','vine ','lmao','alison armitage','#cops2016','brooklyn',' msm ','Jeremy corbyn',' leader ','radical',' rape ','live-action','trailer','summer','film','most value','getting the most','get the most','Louis eavesdropping','vine','sans qu','get it now','is out now','learn more','smell','smells','kiss','the key to ','potes','haine','pote',' wear ','sweatpants','mph','baseball','niggas','beach','the key is to','wealth','economy','businesses','shareeconomy','for a chance','enter now','song','baby','murder','savage','Bomb','improve','marketers','Marketing','career','your business','trends','trend','please rt','pls retweet','pls rt','please rt','RqiM','#ccot','#tcot','that women','this women','that guy','this guy','fool','world ends','want to know the latest','find out now','#getmorelead','10 key','7 key','5 key','3 key','lead generation','rugby','featuring','organization','emploi','up to you','wisdom framework','deal','ginger','MLM','===>','management','#loyality','#MLM','browser/os','#music','housemusic','techhouse','icemoon','guidance','meet your','Meet our','suicide','loam','fuck you','bitch','internet friends','internet slang','the latest','nigger','nigga','broad gauge','felties','glow in the dark','scrapbooking','helixstudios','solidarity',' activist','sweatshop','help grow','Digital buyer','trump','baise','top stories','skid game','arrieta','leading off:','baby hat','newborn','Rt for','dining table','retweet','vibrators','rainbow round','skid row','malliardreport','breaking news','scoop:','spider art','subscribe:','subscribe to our','GOT7','Join us','explosive device','fuzzing feeling','future of our people','sex','pute','penis','sports','toilet valve','toilet water','sfxns','smoke','ptdr','VosMecsQui','cheveux','learn more:','tanning','long trajet','rainbow-filled','Hillary','Hartunes','mystery','Aspirin','growing','please share','rainbow dash','Truth coffee','top 5','rainbow glass','jet lag','jet-lag','clinton campaign','buzzfeed','microbial','growth','are you prepared','nautical','biopsies','reverse vending','Tokyo ghoul','Galang','kingarmani','Trump','rugby','I liked a @Youtube video from','White man','WHITEPAPER','white girl','Whitepaper','growing','to help you','spider thread',' Marketing ','check this out','check out this','mimicking ghosts','fundamental tactics',' FREE ','Richard Armitage','@EdgeofSports','Tips','tips','Increase','growth','free ','Growth','Join Free ','vulnerability of women','cornwall','Forensic Mystery','Learn how','Healthcare','Security Epidemic','ASMSG','microbiome','flood of refugees','Donald Trump','spider couples','Follow us','Sida','carotte','moche','slow motion','fake tweets','meuf','Market Research']

banppl = ['fidh_africa','tarteur','getpy','pcidsswiki','budget_bytes','open_markets','turntjuju','txughbxcketzx3_','dofusfr','cybraryit','sean_martin','fclorient','thesoccerlifee','elegantlife','njhbrooke','e_news_digest','forblogs0','gridcybersec','mitsloan','stephanielevy75','cgmagonline','opendemocracy','homeofunclesam','argevise','hugotoutseul','coresecurity','semibogan','unit42_intel','anaj_ihedn','jullien_ballaire','dussolalexis','ahmed','kazefrance','sniperovitch','jeunedissident','etatmajorfr','lemondefr','gblardone','Rkaroutchi','dupontaignan','adrenaline1001','cocotte421','Rtenfrancais','DussolAlexis','florencecedesruol','Anthonygonzalez56','lelab_e1','leJdd','allais','actu17','police24_7','Daniel_jerome44','croixrouge','chittaphonf','gameofthronefr','Squawka','pcper','somedayilllearn','laboureoin','vulture','omgserv','marcoessomba','kennethholley','stacieinatlanta','JCFELLI','AttackDetection','khaledkarouri','mikequindazzi','KENS5','cloudresdfw','cardartsmart8','emotion','rvaughnmd','ITcrowdsource','bladedandh','jfkarcher','morvybztv','kehlanta','themikerobles','kevin_c_bell','SJ_NUFC','lambriniz','autoblogmaker','lequipe','koteizousa','mylifeingaming','authentic8','thecyberwire','mathowie','tim_maliyil','campaignasia','prashantrao','radiosupa','come to see ','playnerve','jpteppe','mehdimaghibi','soyourlikethat','jaxon_wolfe','CWGAfrica','philae_holland','oneheartstudio','fayhartwell','lifepoems','pab_101','gerrybobrien','grumpygamer','DanielaKayb','TimMedin','thecustos','gdatasoftwareag','kaysarahsera','antibotnet','Dr_K_Albrecht','kelseyhightower','yackheather','Edleake','vmwarecares','techjunkiejh','discordapp','lotocitizens','SSH_EXPERT','FightRansomware','panprincessjazz','mobilesecuRR','nick_jassy','GrnProgressive','POCsuggestions','DzenYz','YourAAT','wef','messi10stats','_mnuse','ziarecords','hadesent','minutebuzz','_laumoreira','IDF_Emploi','TweetLIkeAGuy','demah_rabe','slate','slatefr','bbc','lisalaposte','_internet_it_','geek_think','KnowledgeHubB2B','devitospiderman','rambusinc','Infosec_Review','MumTaupe','1J1Poilu','Babble_Away','cyber_securite','EllevateNtwk','StevieSoFetch_','TheBfBible','Floris','GadgetHax','Articles_Maker','droqen','madisynpoops','CooeeProduct','molly_knight','Imperva','virtualgraffiti','ChrchCurmudgeon','headlight','GenChuckYeager','fillon2017lux','globakissueweb','InsiderTradingWire','MyBrosephJoe','tokyomonamour','JacobDjWilson','FRABasketball','HollyGraceful','JazminconJ','LCarvalhoSe','anders_aslund','aoighost','taeng_bbing','EisMC2','jjx','Profuse_Pxrris','ThomasRagon','YouHadOneJob','JeanmarcMAINI','ELLEfrance','jose_ades','RealFKNNews','EIQNetworks','shemazingIE','gof_girlsonfilm','fashionmask','WarfareMagazine','harryxhermione','ARYNEWS24','OM_Officiel','TedFranzman','angelsalvador','NiqueNasty','when people','when ppl','hate when ppl','Zuhaa05','innova_scape','QueerMeNow','FreeRangerKids','AristideMinlo','visittobago','GregYamben','ibr4him2011','AbosiOgba','el_manchar','normative','EdatMaxfield','StaceyBanks','JavascriptBot_','Bekouz','d4v3null','find_evil','DLTSolutions','Apey','cananterzioglu','PremiereFr','mimijedi','sdxtech','ouestfrance','CrocMignon','TritTriton','Diacquenod','DamnRealPosts','_BuffyMars','usatodaytech','CobbleAndFrame','A_Moatti','Ace_Tennis_Tips','BigBBrown','entertainmentIE','___Prof_V___','IGNFRA','geek_mx','kateloving','v3rt4','DamidotValerie','CaseyMoreta','cjane87','cancelled','JourneyCheckFcc','Seb_Brantigan','RoseDeBerne','videospremiumen','mikemetcalf','handsurgeryedu','finlyai','Count__Tracula','Najizzlee_','SylvainPDurif','alaindesjardin','NFLDrafter','yagirltemi','JesusOfficiel','elloydgaf','jb8sy','@shadygagafacts','MyVeronicaAvluv','nubileteenporn','Le360fr','SLSingh','JayceHall','ximad','NCT_TH','racisme','SecureThinking','wimremes','Sunzag','teztikelz','inquirerdotnet','InterMilanNow','kookmin_ph','jenstirrup','aki_official1','loriedden','PepperParkJIMIN','KellyChan86','Crunchyroll','harsh_mahajan11','ravgab','ChristianHeimes','Morrissons','huniverses','Tesco','sardinimou','ryannminajj','twerkftari','hotlinejoon','br_uk','total_nebula','CrankThatFrank','stylesjack','OfficialWithHL','@ArtByAlida','sameoldtrust','randileeharper','SamuraiKnitter','SwissHttp','SimonZerafa','GoProgRRam','villabone','AUKenDog','PlaggeVal','ClaraSchmelck','ServerVirt_TT','JPN_PokemonGo','richardbro','frecaze','mreeseeagles','13WHAM','HerrBrains','houstontranstar','cocoalabs','QuinesaJ','Amy_ROOT','Cortexi_Fan','sixthlife1','bibsteralert','chapmns','Nuditivity','derekcarrqb','TEDTalks','paulgebel','GoProgRRam','nickaster','MUFCMNTC','DaRealSafado','lidlfrance','selectanescort','MountainGoth','browns_fanly','esquireattire','ABSCBNNews','ohsosavymom','WOLFPSICOPATA','sarawiseman33','tdhopper','LindaBuquet','GUIGolf','jennjacquelynm','TheBardockObama','InvictosSomos','Bugcrowd','pannchoa','McFarland_Shawn','EADI','elevationng','Parawinecom','Rich_1337','RBContentPool','KEEMSTAR','MrBornHelix','W130SN','XxPLWxX','IrisABC15','TomFlowers','MLG','junocake','ElminsterRTA','IsaiahBizabani','coolvicky70','JulioCyberSec','cwaggonerfox4','Perficient_IBM','WhiteSourceSoft','imokx','AngeliccVirgo','RomanAtwood','ThelmaR0drigues','BitnerdGx','HighheelsDes','jenjacquelyn','Biz_Gurux','UKBCHour','IronHorseVyds','CCMAofficial','PrivatMe','50degreesam','WritersContests','LilGlolita','anonymous girl','DiosasLesbianas','Bucks','UWBadgers','HotNewHipHop','2peasandadog','WTOPtraffic','Mersive','ChelseyCBS','HPE_ALM','AdamSmith1','EatYourOwnEars','getbentsaggy','JosDice','decorationsart','1to1Legal','Andrey_ink','monsieurturnup','relation_goals','AurelieSmd','Syfaaax','Corxntin','TheKairi78','bxstivn','nellawiak','stonelabanowitz','_TFlow','blvckndn','ochocinco','LESFEMININES','BSteekFC','SunderlandAFC','PrinzNiyi','geekygabriela15','Juliissaaaa_','PilgrimPetey','beholdthymother','_TheMunSession_','chris_peruggia','NexCentCit','Jvxon','spbetting1','truerpoems','High_','amadijuana','Kingpin_Picks','deadcool','musicaltrees','thezoereport','olicityloyalty','Pete_Spence','europeanhistry','Parkdean','DailyStockPlays','DJW_Macbeth','Queen_HoneyPot','braylannnE','CastroTrapMoney','YoungTiba','AusWyche','mmasekgoam','Polygon','SiriusNews_com','Diez_30et1Diez','Gunzblazing_MV','WWE','1dasviness','sciendus','mrk1_','kennyjnners','ShitJokes','BsbLifeStyle_','Talib944','MattBellassai','charlieputh','FreddyAmazin','FurBearers','RedFumz','Carbonite','rugbycomau','DaybreakHelp','FindPsychics','FrancisMastroMj','StartupProduct','MyCloudstar','tonni_olsen','aliciacrisp1','AdeosunA1','fxckmodel','crochet_rr','FaustianDemon','MalliardReport','AllyBenoliel','biiiiitchy_69','richchigga','sexualgifs_','neymarjr','sofarrsogud','thesecret','Swaaann_','DJ_Korsakoff','Poetryinsunsets','alexielsi','MonMecNePeutPas','cvrentin','RailMinIndia']

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

	global apicall
	global updatecall
	global twitter

	goflush = 0

        Fig = Figlet(font='rev')
        print Fig.renderText('flushtmp()')

	time.sleep(0.3)
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
			time.sleep(2)

		if goflush == 1:


			print
			print "=="
			Fig = Figlet(font='basic')
			print Fig.renderText('Flushing Temps Files')
			print "=="
			print
			
			file.close()
                	try:
                        	twitter.send_direct_message(user_id="292453904", text="New Session ! " + str(currentdate))
                        	apicall = apicall +1
                        	updatecall = updatecall +1
                        	print ""
                        	Fig = Figlet(font='basic')
                        	print Fig.renderText('Status sent !"')

                	except Exception as e:
                	        print e
                	        print "fuck"
                	        time.sleep(5)
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
	time.sleep(0.3)
	try:
		global newkeywords
		global checkM
                oldlen = len(wordlist)
                file = open(noresult,"r")
                lines2 = file.read().splitlines()
                lenmatch2 = len(set(lines2) & set(wordlist))

		print
		print "=="
                Fig = Figlet(font='epic')
                print Fig.renderText('Rm No Result')
		print
		time.sleep(0.5)
                while lenmatch2 >0:
                        print "Found %i occurences :" % lenmatch2
                        set(lines2) & set(wordlist)
                        print
                        print
                        time.sleep(1)
                        print "Removing No result from list ..."
                        wordlist = list(set(wordlist) - set(lines2))
                        print
                        time.sleep(1)
                        print
                        print "New lenght of searchlist : " + str(len(wordlist)) + " (Was " + str(oldlen) + " )"
                        print "=="
                        print
                        time.sleep(1)
                        lenmatch2 = len(set(lines2) & set(wordlist))
                file.close()

                Fig = Figlet(font='epic')
                print Fig.renderText('Rm Old n Used')
                print
		time.sleep(0.5)
                newkeywords = wordlist
                print
                print "=="
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Removed successfully')
                print "=="
                time.sleep(1)

                oldlen = len(wordlist)
                file = open(TmpMeal,"r")
                lines = file.read().splitlines()
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
                print "=="
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Removed successfully')
                print "=="
                checkM = 1
                time.sleep(1)
                newkeywords = wordlist
	except Exception as e:
		print e

		print "=="
                Fig = Figlet(font='basic')
                print Fig.renderText('No previous searchs found for today')
		print "=="
		time.sleep(1)


def lastmeal(lastsearch):

                Fig = Figlet(font='rev')
                print Fig.renderText('LastSearch()')
		time.sleep(0.3)
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
		time.sleep(0.3)


def SaveTotalCall(call,update):
                print
                print
                print
                print
                print
		Fig = Figlet(font='rev')
                print Fig.renderText('SaveTotalCall()')
		print
		time.sleep(0.3)
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
		time.sleep(0.3)
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

                time.sleep(0.3)
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
	global waithalf
	global rtsave

	waithalf = 1

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

		try:
		        twitter.send_direct_message(user_id="292453904", text="Tweets: " + str(nbrRtwt) + " Total Call :" + str(totalcall) + " Total update : " + str(totalupdatecall) )
		        apicall = apicall +1
		        updatecall = updatecall +1
		        print ""
                        Fig = Figlet(font='basic')
                        print Fig.renderText('Status sent !"')

		except Exception as e:
			print e
		        print "fuck"
			time.sleep(5)
		rtsave = nbrRtwt
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
		                        Fig = Figlet(font='puffy')
					print
					print

		                        print Fig.renderText('Done !')
					print
					print
					figy = "Tweets left to send %i / %i " % (tmpcount,nbrRtwt)
					print Fig.renderText(figy)
					print "**"
					print
					print "*=*=*=*=*=*=*=*=*=*"
					time.sleep(1)
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

									time.sleep(0.3)
def tweetlist(point,id):


        Fig = Figlet(font='rev')
        print Fig.renderText('Tweetlist()')
        ammo = str(point) + "-" + str(id)
        retweetlist.append(ammo)
#	time.sleep(0.3)
	print "=="
        Fig = Figlet(font='epic')
        print Fig.renderText('Loaded into Queue !')
	print "=="
	print
	time.sleep(0.3)




def limits():
        Fig = Figlet(font='rev')
        print Fig.renderText('Limits()')

#	time.sleep(0.3)
	global apicall
	global updatecall
	global totalupdatecall
	global totalcall
	global twitter
	global searchlimit
	global restabit
	global waithour
	global waithalf

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
                print Fig.renderText('Waiting 60 minutes')

                for i in xrange(3600,0,-1):
                        time.sleep(1)
                        sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
                        sys.stdout.flush()

                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waking up ..')
                time.sleep(0.3)
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

		if waithalf != 1:
                	print Fig.renderText('Waiting 15 minutes')
		
		
			for i in xrange(900,0,-1):
    				time.sleep(1)
				sys.stdout.write("Time Left : " + str(i) + " Seconds" + "\r")
				sys.stdout.flush()
		else:
                        print Fig.renderText('Waiting 30 minutes')

                
                        for i in xrange(1800,0,-1):
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
        time.sleep(1)




def Ban(tweet,sender,id):

	global Banned
	ushallpass = 0

        Fig = Figlet(font='rev')
        print Fig.renderText('Ban()')
	print
        print "*=*=*=*=*=*=*=*=*=*"
	Fig = Figlet(font='cybermedium')
#        print Fig.renderText('Verify if this Tweet contains at least one of the Keywords :')
	print

	for mustbe in Keywordsave:
	  	if ushallpass == 0:
	    		if Banned == 0:
                		pos = 0
                		lng = len(mustbe)
				if lng >= 8:
                			half = lng / 2
				else:
					half = lng - 1
                		next = half + pos
                		sample = mustbe[pos:half]
                		maxpos = pos + len(sample)

		                while maxpos < lng:

		   		    try:
		                        if str(sample.lower()) in str(tweet.lower()) and sample != " ":
		                                print
		                                Fig = Figlet(font='cybermedium')
		                                print Fig.renderText('Found Keywords :')
						print
        		                        print "Sample : ",sample
                                		print
						Fig = Figlet(font='basic')
                                		print Fig.renderText('You shall Pass')
                                		print "*=*=*=*=*=*=*=*=*=*"
		   				ushallpass = 1
                                		maxpos = lng
                        		else:
                                		pos = pos + 1
                                		next = half + pos
                                		sample = mustbe[pos:next]
                                		maxpos = pos + len(sample)
				    except:
                                                pos = pos + 1
                                                next = half + pos
                                                sample = mustbe[pos:next]
                                                maxpos = pos + len(sample)
	if ushallpass != 1:
                                print
                                print Fig.renderText('Did not found any Keyword in tweet.')
				Banned = 1
				time.sleep(1)
	print "*=*=*=*=*=*=*=*=*=*"
	Fig = Figlet(font='cybermedium')
#	print Fig.renderText('Checking if this Tweet contains any forbidden terms:')
	print

	for forbid in banlist:
	    if Banned == 0:
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
			time.sleep(0.3)

        for forbid in banppl:
	    if Banned == 0:
                if forbid.lower() in sender.lower():

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
                        time.sleep(0.3)

        for forbid in bandouble:
	    if Banned == 0:
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
		if tweet.count("@") >= 3:


	                Fig = Figlet(font='basic')
	                print Fig.renderText('Follow Friday')
			Fig = Figlet(font='cybermedium')
	                print Fig.renderText('Going To Trash')
	                print "*=*=*=*=*=*=*=*=*=*"
	                print
			Banned = 1
			time.sleep(0.5)

	        if tweet.count("#") >= 3:


	                Fig = Figlet(font='basic')
	                print Fig.renderText('HashTags Fever')
	                Fig = Figlet(font='cybermedium')
	                print Fig.renderText('Going To Trash')
	                print "*=*=*=*=*=*=*=*=*=*"
	                print
			Banned = 1
	                time.sleep(0.5)


	if Banned == 0:

                Fig = Figlet(font='speed')
                print Fig.renderText('Good To Go !!')
	        print "*=*=*=*=*=*=*=*=*=*"
		print
		time.sleep(0.3)


def Saveid(id):

                Fig = Figlet(font='rev')
                print Fig.renderText('Saveid()')
		print
#		time.sleep(0.3)

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
		time.sleep(0.3)


def Idlist(id):

		global alreadysend

                Fig = Figlet(font='rev')
                print Fig.renderText('Idlist()')
#		time.sleep(0.3)

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
			time.sleep(0.3)




def Scoring(tweet,search):

	global apicall
	global totalcall
	global updatecall
	global totalupdatecall
	global Banned
	global bandouble
	global alreadysend
	global moyscore

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
	time.sleep(0.3)

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

			if tweet['retweet_count'] > 2 and tweet['retweet_count'] <= 10:
				Score  = Score + 1
                        if tweet['retweet_count'] > 10 and tweet['retweet_count'] <= 20:
                                Score  = Score + 2
                        if tweet['retweet_count'] > 20 and tweet['retweet_count'] <= 30:
                                Score  = Score + 3
                        if tweet['retweet_count'] > 30 and tweet['retweet_count'] <= 40:
                                Score  = Score + 4
                        if tweet['retweet_count'] > 40 and tweet['retweet_count'] <= 50:
                                Score  = Score + 5
                        if tweet['retweet_count'] > 50 and tweet['retweet_count'] <= 50:
                                Score  = Score + 6
                        if tweet['retweet_count'] > 60 and tweet['retweet_count'] <= 70:
                                Score  = Score + 7
                        if tweet['retweet_count'] > 70 and tweet['retweet_count'] <= 80:
                                Score  = Score + 8
                        if tweet['retweet_count'] > 80 and tweet['retweet_count'] <= 90:
                                Score  = Score + 9
                        if tweet['retweet_count'] > 90 and tweet['retweet_count'] <= 100:
                                Score  = Score + 10
                        if tweet['retweet_count'] > 100 and tweet['retweet_count'] <= 110:
                                Score  = Score + 11
                        if tweet['retweet_count'] > 110 and tweet['retweet_count'] <= 120:
                                Score  = Score + 12
                        if tweet['retweet_count'] > 120 and tweet['retweet_count'] <= 130:
                                Score  = Score + 13
                        if tweet['retweet_count'] > 130 and tweet['retweet_count'] <= 140:
                                Score  = Score + 14
                        if tweet['retweet_count'] > 140 and tweet['retweet_count'] <= 150:
                                Score  = Score + 15
                        if tweet['retweet_count'] > 150 and tweet['retweet_count'] <= 160:
                                Score  = Score + 16
                        if tweet['retweet_count'] > 160 and tweet['retweet_count'] <= 170:
                                Score  = Score + 17
                        if tweet['retweet_count'] > 170 and tweet['retweet_count'] <= 180:
                                Score  = Score + 18
                        if tweet['retweet_count'] > 180 and tweet['retweet_count'] <= 190:
                                Score  = Score + 19
                        if tweet['retweet_count'] > 190 and tweet['retweet_count'] <= 200:
                                Score  = Score + 20
                        if tweet['retweet_count'] > 200 and tweet['retweet_count'] <= 210:
                                Score  = Score + 21
                        if tweet['retweet_count'] > 210 and tweet['retweet_count'] <= 220:
                                Score  = Score + 22
                        if tweet['retweet_count'] > 220 and tweet['retweet_count'] <= 665:
                                Score  = Score + 23
                        if tweet['retweet_count'] >= 666:
                                Banned = 1
				Score = Score - 23

                        





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
			if fav > 1 and fav <= 10:
                        	Score = Score + 1
			if fav > 10 and fav <= 20:
				Score = Score + 2
			if fav > 20 and fav <= 30:
				Score = Score + 3
                        if fav > 30 and fav <= 40:
                                Score = Score + 4
                        if fav > 40 and fav <= 50:
                                Score = Score + 5
                        if fav > 50 and fav <= 60:
                                Score = Score + 6
                        if fav > 60 and fav <= 70:
                                Score = Score + 7
                        if fav > 70 and fav <= 80:
                                Score = Score + 8
                        if fav > 80 and fav <= 90:
                                Score = Score + 9
                        if fav > 90 and fav <= 100:
                                Score = Score + 10 
                        if fav > 100 and fav <= 110:
                                Score = Score + 11
                        if fav > 110 and fav <= 120:
                                Score = Score + 12
                        if fav > 120 and fav <= 130:
                                Score = Score + 13
                        if fav > 130 and fav <= 140:
                                Score = Score + 14
                        if fav > 140 and fav <= 150:
                                Score = Score + 15
                        if fav > 150 and fav <= 160:
                                Score = Score + 16
                        if fav > 160 and fav <= 170:
                                Score = Score + 17
                        if fav > 170 and fav <= 180:
                                Score = Score + 18
                        if fav > 180 and fav <= 190:
                                Score = Score + 19 
                        if fav > 190 and fav <= 200:
                                Score = Score + 20
                        if fav > 200 and fav <= 210:
                                Score = Score + 21
                        if fav > 210 and fav <= 220:
                                Score = Score + 22
                        if fav > 220 and fav <= 665:
                                Score = Score + 23
			if fav >= 666:
				Score = Score - 23
				Banned = 1
				






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

				Score = Score + 5


	TwtTime = tweet['created_at']
        TwtTime = TwtTime.replace(" +0000 "," ")
        Timed = datetime.datetime.strptime(TwtTime,'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
	TimeFinal = datetime.datetime.strptime(Timed,'%Y-%m-%d %H:%M:%S')
	hourtweet = now - TimeFinal
	print
	print "This tweet was send at : ",TwtTime
	print
	time.sleep(0.3)
	print
        try:

	    if currentdate.day != 01:
                if TimeFinal.month != currentdate.month:
                                        Fig = Figlet(font='basic')
                                        print
                                        print Fig.renderText('WAY TOO OLD !')
                                        print
                                        Banned = 1
                                        time.sleep(3)
		else:
			print
        except Exception as e:
                print e
                time.sleep(3)

	print

	try:
		if TimeFinal.year != currentdate.year:
                                        Fig = Figlet(font='basic')
                                        print
                                        print Fig.renderText('FUCKING TOO OLD !')
                                        print
                                        Banned = 1
                                        time.sleep(1)
		else:
			print 
	except Exception as e:
		print e
		time.sleep(3)
	try:
		if hourtweet.days > 1:
                                        Fig = Figlet(font='basic')
					print
                                        print Fig.renderText('TOO OLD !')
					print
					Banned = 1
					time.sleep(0.5)
	except:
		placehold = "monkey want pullover , monkey get banana"
	if 'retweeted_status' in tweet :
	   if 'created_at' in tweet['retweeted_status'] and len(tweet['retweeted_status']['created_at']) > 0:
		RtTime = tweet['retweeted_status']['created_at']
	        RtTime = RtTime.replace(" +0000 "," ")
	        RtTimed = datetime.datetime.strptime(RtTime,'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
		RtTimeFinal = datetime.datetime.strptime(RtTimed,'%Y-%m-%d %H:%M:%S')
		Rthourtweet = now - RtTimeFinal
	        try:
	
	            if currentdate.day != 01:
	                if RtTimeFinal.month != currentdate.month:
	                                        Fig = Figlet(font='basic')
	                                        print
	                                        print Fig.renderText('RT WAY TOO OLD !')
	                                        print
	                                        Banned = 1
	                                        time.sleep(3)
	                else:
	                        print
	        except Exception as e:
	                print e
	                time.sleep(3)
	
	        print
	
	        try:
	                if RtTimeFinal.year != currentdate.year:
	                                        Fig = Figlet(font='basic')
	                                        print
	                                        print Fig.renderText('RT FUCKING TOO OLD !')
	                                        print
	                                        Banned = 1
	                                        time.sleep(1)
	                else:
	                        print 
	        except Exception as e:
	                print e
	                time.sleep(3)
	

	if Banned != 1:
		if hourtweet.seconds < 3600:
			Score = Score + 2 + 3
			print "Less than an hour ago ."
			print "Score = + 5"
			print
			print "Score = ",Score
			print

		if hourtweet.seconds > 3600 and hourtweet.seconds <= 7200:
			Score = Score + 2 + 2
			print "An hour ago ."
			print "Score = + 4"

        	if hourtweet.seconds > 7200 and hourtweet.seconds <= 10800:
        	        Score = Score + 3
        	        print "Two hours ago ."
			print "Score = + 3"

        	if hourtweet.seconds > 10800 and hourtweet.seconds <= 14400:
        	        Score = Score + 2
        	        print "Three hours ago ."
			print "Score = + 2"

        	if hourtweet.seconds > 14400 and hourtweet.seconds <= 18000:
        	        Score = Score + 1
        	        print "Four hours ago ."
			print "Score = + 1"

        	if hourtweet.seconds > 18000 and hourtweet.seconds <= 21600:
                	Score = Score + 0
                	print "Five hours ago ."
			print "Score = + 0"

      	 	if hourtweet.seconds > 21600 and hourtweet.seconds <= 25200:
                	Score = Score + 0
                	print "Six hours ago ."
			print "Score = + 0"

        	if hourtweet.seconds > 25200 and hourtweet.seconds <= 28800:
			Score = Score + 0
                	print "Seven hours ago ."
			print "Score = + 0"

        	if hourtweet.seconds > 28800 and hourtweet.seconds <= 32400:
                	Score = Score + 0
                	print "Eight hours ago ."
                	print "Score = + 0"

        	if hourtweet.seconds > 32400 and hourtweet.seconds <= 36000:
        	        Score = Score + 0
        	        print "Nine hours ago ."
        	        print "Score = + 0"
        	if hourtweet.seconds > 36000 and hourtweet.seconds <= 39600:
        	        print "Ten hours ago ."
        	        print "Score = + 0"

        	if hourtweet.seconds > 39600 and hourtweet.seconds <= 43200:
        	        Score = Score - 1
        	        print "Eleven hours ago ."
        	        print "Score =  -1"
        	        print
        	        print "Score = ",Score
        	        print


		if hourtweet.seconds > 43200 and hourtweet.seconds <= 46800:
			print "Twelve hours ago ."
			Score = Score - 2
        	        print "Score = - 2"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 46800 and hourtweet.seconds <= 50400:
        	        Score = Score - 3
        	        print "Thirteen hours ago ."
        	        print "Score = - 3"
        	        print
        	        print "Score = ",Score
        	        print
	

        	if hourtweet.seconds > 50400 and hourtweet.seconds <= 54000:
        	        Score = Score - 4
        	        print "Fourteen hours ago ."
        	        print "Score = - 4"


        	if hourtweet.seconds > 54000 and hourtweet.seconds <= 57600:
        	        Score = Score - 5
        	        print "Fiveteen hours ago ."
        	        print "Score = - 5"
        	        print
        	        print "Score = ",Score
        	        print



        	if hourtweet.seconds > 57600 and hourtweet.seconds <= 61200:
        	        Score = Score - 6
        	        print "Sixteen hours ago ."
        	        print "Score = - 6"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 61200 and hourtweet.seconds <= 64800:
        	        Score = Score - 7
        	        print "Seventeen hours ago ."
        	        print "Score = - 7"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 68400 and hourtweet.seconds <= 72000:
        	        Score = Score - 8
        	        print "Eighteen hours ago ."
        	        print "Score = - 8"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 72000 and hourtweet.seconds <= 75600:
        	        Score = Score - 9
        	        print "Nineteen hours ago ."
        	        print "Score = - 9"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 75600 and hourtweet.seconds <= 79200:
                	Score = Score - 10
                	print "Twenty hours ago ."
                	print "Score = - 10"
                	print
                	print "Score = ",Score
                	print

        	if hourtweet.seconds > 79200 and hourtweet.seconds <= 82800:
                	Score = Score - 11
                	print "Twenty one hours ago ."
                	print "Score = - 11"
                	print
                	print "Score = ",Score
                	print

	        if hourtweet.seconds > 82800 and hourtweet.seconds <= 86400:
	                print "Twenty two hours ago ."
			Score = Score - 12
	                print "Score = - 12"
	                print
	                print "Score = ",Score
	                print

	        if hourtweet.seconds > 86400 and hourtweet.seconds <= 90000:
	                Score = Score - 13
	                print "Twenty three hours ago ."
	                print "Score = - 13"
	                print
	                print "Score = ",Score
	                print

	        if hourtweet.seconds > 90000 and hourtweet.seconds <= 160000:
	                print "Twenty 24 hours ago ."
	                print "Score = - 14"
	                print
			Score = Score - 14
	                print "Score = ",Score
	                print
	                time.sleep(3)
                if hourtweet.total_seconds() >= 160000 or Rthourtweet.total_seconds()  >= 240000:
                        print "Too old more than Two Days."
                        print "Score = - 100000"
                        print
                        Score = Score - 100000
                        print "Score = ",Score
                        print
                        time.sleep(4)
			Banned = 1

	time.sleep(0.3)



	moyscore.append(Score)

	if tweet['lang'] == "en" or tweet['lang'] == "fr" or tweet['lang'] == "en-gb":

		Idlist(tweet['id'])

		if alreadysend == 0:

			Ban(tweet['text'],tweet['user']['screen_name'],tweet['id'])

			if Banned != 1:
				if Score >= 16 :
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
                                        Fig = Figlet(font='puffy')
					figy = "Score = %i" % Score
                                        print Fig.renderText(figy)
                                        print "================================================================================"
					print "Score = ",Score
                                        print "================================================================================"
					print tweet['text']
					print "================================================================================"
					print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
					print "This tweet does not match the requirement to be retweeted. (Score)"
					print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
					print "================================================================================"
					print ""
		
					time.sleep(0.5)
			else:
	                                print ""
                                        Fig = Figlet(font='epic')
                                        print Fig.renderText("But ..")
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
					time.sleep(0.5)
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
                                        time.sleep(0.5)



	else:
				print
                                Fig = Figlet(font='epic')
                                print Fig.renderText("but ..")
                                print "================================================================================"
				Fig = Figlet(font='cybermedium')
				print Fig.renderText("Language")
                                print "==============================================================================="
                                print tweet['text']

				print "================================================================================"
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
                                print "This tweet does not match the requirement needed to be retweeted."
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
				print "================================================================================"
                                print ""
				time.sleep(0.3)

        time.sleep(0.3)


	print
	print






def searchTst(word):
	global apicall
	global updatecall
	global twitter
	global restabit
        Fig = Figlet(font='rev')
        print Fig.renderText('SearchTst()')
	time.sleep(0.3)
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
				time.sleep(0.3)
		
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
				print ""
				time.sleep(0.3)
				print "=="
				print ""
				time.sleep(0.3)
				print ""
	
			except:
						apicall = apicall + 1
	                                        print
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	                                        print "Error Sorry trying next one"
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	                                        print
						time.sleep(0.3)
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
			try:
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
			except Exception as e:
				print e


		else:
	                print
			searchlimit = 1
			limits()



#Some Code

Fig = Figlet(font='poison')
print Fig.renderText("-----")
print
Fig = Figlet(font='alligator')
print Fig.renderText("-RED-")
print Fig.renderText("QUEEN")
print
Fig = Figlet(font='poison')
print Fig.renderText("-----")
print

time.sleep(5)

print "=/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText('Calling Flush function')
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
flushtmp()
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText('Calling Search function')
print "=/\/\/\/\/\/\/\/\/\/\/\/\="

Minwords = len(Keywords)/300
Maxwords = len(Keywords)/150
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
try:
                        twitter.send_direct_message(user_id="292453904", text="Redqueen.py started at "+ str(currentdate) + " Searching " + str(rndwords) + " items .")
                        apicall = apicall +1
                        updatecall = updatecall +1
                        print ""
                        Fig = Figlet(font='basic')
                        print Fig.renderText('Status sent !"')

except Exception as e:
                        print e
                        print "fuck"
                        time.sleep(5)

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
tmpcnt= 0
for key in Keywords[:rndwords]:
	tmpcnt = tmpcnt + 1
	figy = "Searching %i/%i" % (tmpcnt,rndwords) 
	Fig = Figlet(font='puffy')
	print Fig.renderText(figy)
	time.sleep(1)
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
time.sleep(0.3)
print
print
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText("Retweet function stopped")
print "=/\/\/\/\/\/\/\/\/\/\/\/\="
print
time.sleep(0.3)
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
time.sleep(0.3)
lastmeal(Keywords[:rndwords])
print
avgscore = sum(moyscore) / float(len(moyscore))
try:
	dbrief= "*Redqueen Debrief* -Searchs: "+ str(rndwords) +"-Twts:" + str(len(moyscore)) + "-Avg Score:" + str(avgscore) + "-Rtwts:" + str(rtsave)+ "-Tcall:" + str(totalcall) + "-Ucall:" + str(totalupdatecall)
	twitter.send_direct_message(user_id="292453904", text=str(dbrief))
	apicall = apicall +1
	updatecall = updatecall +1
	print ""
	Fig = Figlet(font='basic')
	print Fig.renderText('Status sent !"')

except Exception as e:
                        print e
                        print "fuck"
                        time.sleep(5)

print "=/\/\/\/\/\/\/\/\/\="
Fig = Figlet(font='basic')
print Fig.renderText("Calling Saving call function")
print "=/\/\/\/\/\/\/\/\/\="
print
time.sleep(0.3)
SaveTotalCall(apicall,updatecall)

print "##############################################################################################################"
print "##############################################################################################################"
Fig = Figlet(font='basic')
print Fig.renderText("The End")
print "##############################################################################################################"
print "##############################################################################################################"
print 
print
print
print
#################################################TheEnd#############################################################
time.sleep(0.3)
