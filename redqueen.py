#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import division
from builtins import range
from asciimatics.effects import Scroll, Mirage, Wipe, Cycle, Matrix,BannerText, Stars, Print
from asciimatics.renderers import FigletText, Rainbow ,ColourImageFile
from asciimatics.particles import RingFirework, SerpentFirework, StarFirework, PalmFirework,ShootScreen
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from random import randint, choice, shuffle
from twython import Twython
from TwitterApiKeys import app_key, app_secret, oauth_token, oauth_token_secret
from pyfiglet import Figlet
import re
import time
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import os
import string
import datetime
import emoji
import signal

#Some Vars

fuck = 0

Rthourtweet = ""

exit = 0

tmpbypass = 0

doneid = 0

waithour = 0

waithalf = 0

moyscore = []

emolist = []

rtsave = ""

currentdate = datetime.datetime.now()

path = "./Data/"

TmpDay = str(path) + "Total Api.Call" 

TmpDay2 = str(path) + "Update Status.Call"

TmpMeal = str(path) + "Search Terms.Used"

Tmpkey = str(path) + "Rq.Keywords"

Tmpword = str(path) + "Rq.Bannedword"

Tmpfolo = str(path) + "Rq.Following"

Tmpfriend = str(path) + "Rq.Friends"

Tmpbppl= str(path) + "Rq.Bannedpeople"

Tmpbw= str(path) + "Rq.Bannedword"

Session = str(path) + "Current.Session"

noresult = str(path) + "No.Result"

idsaved = str(path) + "Tweets.Sent"

doublesaved = str(path) + "Text.Sent"

restabit = 0

twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)

#Keywords = ["th3j35t3r","@th3j35t3r"]

Keywords = []

Keywordsave = []

Following = []

Friends = []

banlist = []

banppl = []

bandouble = []

apicall = 0

updatecall = 0

totalcall = 0

totalupdatecall = 0

tobsnd = []

allok = 0

Totalsent = 0

checkM = 0

mcdone = 0
	
searchapi = 0

searchlimit = 0

searchdone = 0

retweetlist = []

newkeywords = []

QueueList = []

startedat = ''

time2wait = 0

totalscore = 0

totalalrdysnd = 0

totallanguage = 0

total2old = 0

totalnokeyword = 0

totalbannedwords = 0

totalff = 0

totalhf = 0

totalbannedppl = 0

twtbyuser = []


#startedat = datetime.datetime.now()

newtlist = []
printable = set(string.printable)


#Some Defs

def loadvars():

		global Keywords
		global Keywordsave
		global Following
		global Friends
		global banlist
		global banppl


                Fig = Figlet(font='rev')
                print Fig.renderText('LoadVars()')
		print
		print
		print
		print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Loading Keywords')
		print
		print


                try:
                        file = open(Tmpkey,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Tmpkey)"
                        print "Creating file"
                        print "=="
                        file = open(Tmpkey,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(Tmpkey, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

                with open(Tmpkey, "w") as f:
                    f.writelines('\n'.join(clean_lines))

		file = open(Tmpkey,"r+")
                lines = file.read().splitlines()

		for saved in lines:
			Keywords.append(saved)
			
                print "*=*=*=*=*=*=*=*=*=*"
#                print "New lenght of Keywords :",len(Keywords)
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Keywords Loaded')
                print "*=*=*=*=*=*=*=*=*=*"
                print
		time.sleep(2)

		Keywordsave = Keywords
		shuffle(Keywords)

		print
		print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Loading Following')
		print
		print


                try:
                        file = open(Tmpfolo,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Tmpfolo)"
                        print "Creating file"
                        print "=="
                        file = open(Tmpfolo,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(Tmpfolo, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

                with open(Tmpfolo, "w") as f:
                    f.writelines('\n'.join(clean_lines))

		file = open(Tmpfolo,"r+")
                lines = file.read().splitlines()

		for saved in lines:
			Following.append(saved)
			
                print "*=*=*=*=*=*=*=*=*=*"
#                print "New lenght of Following :",len(Following)
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Following Loaded')
                print "*=*=*=*=*=*=*=*=*=*"
                print
		time.sleep(2)

		print
		print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Loading Friends')
		print
		print


                try:
                        file = open(Tmpfriend,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Tmpfriend)"
                        print "Creating file"
                        print "=="
                        file = open(Tmpfriend,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(Tmpfriend, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

                with open(Tmpfriend, "w") as f:
                    f.writelines('\n'.join(clean_lines))

		file = open(Tmpfriend,"r+")
                lines = file.read().splitlines()

		for saved in lines:
			Friends.append(saved)
			
                print "*=*=*=*=*=*=*=*=*=*"
#                print "New lenght of Friends :",len(Friend)
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Friends Loaded')
                print "*=*=*=*=*=*=*=*=*=*"
                print
		time.sleep(2)


		print
		print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Loading Banned Words')
		print
		print


                try:
                        file = open(Tmpbw,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Tmpbw)"
                        print "Creating file"
                        print "=="
                        file = open(Tmpbw,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(Tmpbw, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

                with open(Tmpbw, "w") as f:
                    f.writelines('\n'.join(clean_lines))

		file = open(Tmpbw,"r+")
                lines = file.read().splitlines()

		for saved in lines:
			banlist.append(saved)
			
                print "*=*=*=*=*=*=*=*=*=*"
#                print "New lenght of Banned Words :",len(banlist)
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Banned Words Loaded')
                print "*=*=*=*=*=*=*=*=*=*"
                print
		time.sleep(2)


		print
		print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Loading Banned Users')
		print
		print


                try:
                        file = open(Tmpbppl,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Tmpbppl)"
                        print "Creating file"
                        print "=="
                        file = open(Tmpbppl,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(Tmpbppl, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

                with open(Tmpbppl, "w") as f:
                    f.writelines('\n'.join(clean_lines))

		file = open(Tmpbppl,"r+")
                lines = file.read().splitlines()

		for saved in lines:
			banppl.append(saved)
			
                print "*=*=*=*=*=*=*=*=*=*"
#                print "New lenght of Banned Users :",len(banppl)
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Banned Users Loaded')
                print "*=*=*=*=*=*=*=*=*=*"
                print
		time.sleep(2)

def title(screen):

    scenes = []
    effects = [
        Print(screen,
              Rainbow(screen, FigletText("* RED QUEEN *", font="alligator")),
              y=screen.height // 4 - 5),
        Print(screen,
              FigletText("-Twitter Search Bot-"),
              screen.height // 2 - 3),
        Print(screen,
              FigletText("-Crawling For InfoSec News-"),
              screen.height * 3 // 4 - 3),
    ]
    scenes.append(Scene(effects, 60))

    effects = [
        ShootScreen(screen, screen.width // 2, screen.height // 2, 100),
    ]
    scenes.append(Scene(effects, 40, clear=False))
    #scenes.append("error")

    try:
    	screen.play(scenes, repeat=False, stop_on_resize=False)
    except:
	pass





def timer(mode):
   global timeleft
   global timed
   global startedat
   if mode == 2:
	now = ''
	timesup = ''
	timeleft = ''
	timed = ''

        now = datetime.datetime.now()
        timesup = now - startedat
        timeleft = "Time Left %i / %i"% (timesup.seconds,time2wait)
        timed = timesup.seconds

        return timeleft


   if mode == 1:

        now = ''
        timesup = ''
        timeleft = ''
        timed = ''



        now = datetime.datetime.now()
        timesup = now - startedat
        timed = timesup.seconds
	return timed

def prepoptweet(screen):
	    scenes = []
            effects = [
                Cycle(
                    screen,
                    FigletText("-Tweets About To Be Send-", font='big'),
                    screen.height // 2 - 8),
                Cycle(
                    screen,
                    FigletText("-By RedQueen-", font='big'),
                    screen.height // 2 + 3),
                Stars(screen, (screen.width + screen.height) // 2)
            ]
            scenes.append(Scene(effects, 100))
#	    bla = "bla"
#	    scenes.append(bla)
	    try:
		screen.play(scenes,repeat=False)
		Screen.wrapper(poptweet)
	    except:
		Screen.wrapper(poptweet)
def poptweet(screen):
    global newtlist
    cnt = 0
    newtlist = []
    for item in tobsnd:
        newtlist.append(filter(lambda x: x in printable, item))
    if len(newtlist) >= 2:
    	while cnt < len(newtlist):
		for item in newtlist:
	 	        screen.print_at(str(item),
        	                randint(0, screen.width), randint(0, screen.height),
                	        colour=randint(0, screen.colours - 1),
                        	bg=randint(0, screen.colours - 1))
			cnt = cnt + 1
			time.sleep(0.3)
	        	screen.refresh()
    Screen.wrapper(firework)
def win(screen):
    scenes = []
    effects = [
        Print(screen, ColourImageFile(screen, "./Data/win.jpg",
                                           screen.height-2), 0,
                        stop_frame=100),
        Print(screen,
                        Rainbow(screen, FigletText("Got One !", font="basic")),
                        y=screen.height // 9 - 2),

                ]
    scenes.append(Scene(effects))
    try:
        screen.play(scenes,repeat=False, stop_on_resize=True)
    except Exception as e:
                print e
def wow(screen):
    randodge = ['Cool ','Gorgeous ','Soft ','Enjoy ','Totally ','Awesome ','Fun ','Easy ','Free ','Wow ','Much ','Many ','Too ','So ','Such ','Very ','Amaze ']
    randcoin = ['Big Drama !','Wow !','Such Deception !','Very Sad !','Many Sucks !','So Mean !','Much Cry !','Full Failure !']
    dodgecoin = str(choice(randodge)) + str(choice(randcoin))

    scenes = []
    effects = [
        Print(screen, ColourImageFile(screen, "./Data/wow.png",
                                           screen.height-2), 0,
			stop_frame=100),
	Print(screen,
                        Rainbow(screen, FigletText(str(dodgecoin), font="basic")),
                        y=screen.height // 9 - 2),

		]
    scenes.append(Scene(effects))
#    bla = "bla"
#    scenes.append(bla)

    try:
    	screen.play(scenes,repeat=False, stop_on_resize=True)
    except Exception as e:
    		print e
#		time.sleep(3)
def firework(screen):
    scenes = []
    effects = []
    for _ in range(20):
        fireworks = [
            (PalmFirework, 25, 30),
            (PalmFirework, 25, 30),
            (StarFirework, 25, 35),
            (StarFirework, 25, 35),
            (StarFirework, 25, 35),
            (RingFirework, 20, 30),
            (SerpentFirework, 30, 35),
        ]
        firework, start, stop = choice(fireworks)
        effects.insert(
            1,
            firework(screen,
                     randint(0, screen.width),
                     randint(screen.height // 8, screen.height * 3 // 4),
                     randint(start, stop),
                     start_frame=randint(0, 250)))

    effects.append(Print(screen,
                         Rainbow(screen, FigletText("TOTAL RETWEETS")),
                         screen.height // 2 - 6,
                         speed=1,
                         start_frame=100))
    effects.append(Print(screen,
                         Rainbow(screen, FigletText(str(Totalsent))),
                         screen.height // 2 + 1,
                         speed=1,
                         start_frame=100))
    scenes.append(Scene(effects, 300))
    scenes.append("error")

    try:
    	screen.play(scenes, repeat=False, stop_on_resize=False)
	Screen.wrapper(credits)
    except:
	print
	print
	Screen.wrapper(credits)


def credits(screen):


	apicalltxt = "Current ApiCalls: ",str(apicall)

	updatecalltxt = "Current Update Calls: ",str(updatecall)

	totalcalltxt =  "Total Calls: ",str(totalcall)

	totalupdatecalltxt = "Total Update Calls: ",str(totalupdatecall)

	banppltxt = "Banned Users in list: ",str(len(banppl))

	bandoubletxt = "Total Banned (Double): ",str(totalalrdysnd)

	banlisttxt = "Banned Words in list: ",str(len(banlist))

	Friendstxt = "Nbr of friends: ",str(len(Friends))

	Followingtxt = "Users Followed: ",str(len(Following))

	Keywordstxt = "Keywords in list: ",str(len(Keywords))

	moyscoretxt = "Current Tweets collected: ",str(len(moyscore))

	totalscoretxt = "Total Banned (Score): ",str(totalscore)

	totallanguagetxt = "Total Banned (Language): ",str(totallanguage)

	total2oldtxt = "Total Banned (Too old): ",str(total2old)

	totalnokeywordtxt = "Total Banned (No Keywords): ",str(totalnokeyword)

	totalbannedwordstxt = "Total Banned (Words): ",str(totalbannedwords)

	totalfftxt = "Total Banned (FF): ",str(totalff)

	totalhftxt = "Total Banned (###):",str(totalhf)

	totalbannedppltxt = "Total Banned Users: ",str(totalbannedppl)

	if time2wait == 300:
		wting = "WAITING\n05 Minutes..."

	if time2wait == 900:
		wting = "WAITING\n15 Minutes..."

	if time2wait == 1800:
		wting = "WAITING\n30 Minutes..."

	if time2wait == 3600:
		wting = "WAITING\n60 Minutes..."


	if timer(1) < time2wait:
	    scenes = []
	    effects = [
	        Matrix(screen, stop_frame=200),
	        Mirage(
	            screen,
	            FigletText(str(wting)),
	            screen.height // 2 - 3,
	            Screen.COLOUR_GREEN,
	            start_frame=100,
	            stop_frame=200),
	        Wipe(screen, start_frame=150),
	        Cycle(
	            screen,
	            FigletText(str(timer(2))),
	            screen.height // 2 - 3,
	            start_frame=200)
	    ]
	    scenes.append(Scene(effects, 300, clear=True))
	
	    effects = [
	        BannerText(
	            screen,
	            Rainbow(screen, FigletText(
	                "-RedQueen Session Stats-", font='slant')),
	            screen.height // 2 - 3,
	            Screen.COLOUR_GREEN)
	    ]
	    scenes.append(Scene(effects))
	    effects = [
	        Mirage(
	            screen,
	            FigletText(str(apicalltxt)),
	            screen.height,
	            Screen.COLOUR_GREEN),
	        Mirage(
	            screen,
	            FigletText(str(totalcalltxt)),
	            screen.height + 8,
	            Screen.COLOUR_GREEN),
	        Mirage(
	            screen,
	            FigletText(str(updatecalltxt)),
	            screen.height + 16,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(totalupdatecalltxt)),
	            screen.height + 24,
	            Screen.COLOUR_GREEN),
	
	
	        Mirage(
	            screen,
	            FigletText(str(moyscoretxt)),
	            screen.height + 32,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(banppltxt)),
	            screen.height + 40,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(totalbannedppltxt)),
	            screen.height + 48,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(totalscoretxt)),
	            screen.height + 56,
	            Screen.COLOUR_GREEN),
	
	
	        Mirage(
	            screen,
	            FigletText(str(totallanguagetxt)),
	            screen.height + 64,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(totalbannedwordstxt)),
	            screen.height + 72,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(total2oldtxt)),
	            screen.height + 80,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(totalfftxt)),
	            screen.height + 88,
	            Screen.COLOUR_GREEN),
	
	
	        Mirage(
	            screen,
	            FigletText(str(totalhftxt)),
	            screen.height + 96,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(banlisttxt)),
	            screen.height + 104,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(bandoubletxt)),
	            screen.height + 112,
	            Screen.COLOUR_GREEN),
	
	        Mirage(
	            screen,
	            FigletText(str(Keywordstxt)),
	            screen.height + 120,
	            Screen.COLOUR_GREEN),
	
	
	        Mirage(
	            screen,
	            FigletText(str(Friendstxt)),
	            screen.height + 128,
	            Screen.COLOUR_GREEN),
		
	
                Mirage(
                    screen,
                    FigletText(str(Followingtxt)),
                    screen.height + 136,
                    Screen.COLOUR_GREEN),

                Mirage(
                    screen,
                    FigletText(str(totalnokeywordtxt)),
                    screen.height + 144,
                    Screen.COLOUR_GREEN),


                Scroll(screen, 7),
	    ]
	    scenes.append(Scene(effects, (screen.height + 640) * 3))
	

	    timer(1)
#	    bla = "bla bla"
#   	    scenes.append(bla)
	    
	    try:
	    	screen.play(scenes,repeat=False)
		Screen.wrapper(prepoptweet)
	    except:
		Screen.wrapper(prepoptweet)

	else:

		print



def signal_handler(signal, frame):
	global allok
	global exit
	if exit == 0:
		exit = exit + 1
        	print('Ok Let me check if there are anything to retweet first ..')
		if len(retweetlist) > 1:
			print "There are %d items in Retweet list ." % len(retweetlist)
			allok = 2
			Retweet()

		if len(retweetlist) == 0:
			print "Nothing to retweet bye bye ! "
        		sys.exit(0)
	if exit > 0:
                        print "OK OK CALM DOWN ! "
			print "EXITING NOW "
                        sys.exit(0)


def Request():

	global Keywords
	global banlist
	global banppl
	global apicall
	global Banned

        Fig = Figlet(font='rev')
        print Fig.renderText('Request()')
        print
        time.sleep(0.3)

	dmlist = twitter.get_direct_messages(count=200)
	apicall = apicall + 1

	if len(dmlist) > 0:
	
	        for dm in dmlist:
		    Banned = 0
		    Idlist(dm['id'])
		    if Banned == 0:
	            	if "On4r4p" in str(dm['sender']['screen_name']):
	            	    words = []
	            	    users = []
			    addkey = []
			    
			    Saveid(dm['id'])
	            	    print
	            	    print "New msg from allowed user:", dm['id']
	            	    print
	            	    print
	            	    print "On %s ."% dm['created_at']
			    a = "On %s ."% dm['created_at']
	            	    print "You send this commande :"
			    b = "You send this commande :"
	            	    print dm['text']
			    c = dm['text']
	            	    items = dm['text'].split(',')
			    d = ""
			    e = ""
			    f = ""
			    g = ""
			    h = ""

	            	    print
			    
	            	    for sample in items:
	                        if not "http" in sample and not "https" in sample and sample is not " " and len(sample) > 1:
	                                if "@" in sample and not "add:" in sample and not "Add:" in sample and not "add :" in sample and not "Add :" in sample :
						print "You asked to Ban this user :",sample
	                                        users.append(sample.replace("@","").replace(" ",""))


	                    		if "Banuser" in sample or "banuser" in sample:
			                        print
			                        print "You asked to Ban the user from that quote:"
						d = "You asked to Ban the user from that quote:"

						try:
			                                d = "You asked to Ban the user from that quote:"
			                        	print dm['entities']['urls'][-1]['expanded_url']
							e = dm['entities']['urls'][-1]['expanded_url']
							if "http:" in e:
			                        		name = re.split('http://twitter.com/|,|/status/| ',dm['entities']['urls'][-1]['expanded_url'])
							if "https:" in e:
								name = re.split('https://twitter.com/|,|/status/| ',dm['entities']['urls'][-1]['expanded_url'])
			                        	print name[1]
		
							f = name[1]
				                     	users.append(name[1])
						except:
							print "But no quote was found ..."

		                        if "add:" in sample or "Add:" in sample or "add :" in sample or "Add :" in sample:
		                                print
		                                print "You asked to add keywords :"
						
		       
		        	                addkey.append(sample.split(":",1)[1])
								
						h = "You asked to add Keywords :",addkey
						print
						print addkey

	                                if not "banuser"in sample and not "Banuser" in sample and not "add:" in sample and not "Add:" in sample and not "add :" in sample and not "Add :" in sample :
	                                        words.append(sample)


				if "http" in sample and sample is not " " and len(sample) > 1:
					endcmd = sample.split("http")
			                if "@" in endcmd and not "add:"in endcmd and not "Add:" in endcmd and not "add :" in endcmd and not "Add :" in endcmd:
						print "You asked to Ban this user :",endcmd[0]
	                                        users.append(endcmd[0].replace("@","").replace(" ",""))


	                    		if "Banuser" in endcmd or "banuser" in endcmd:
			                        print
			                        print "You asked to Ban the user from that quote:"
						d = "You asked to Ban the user from that quote:"

						try:
			                                d = "You asked to Ban the user from that quote:"
			                        	print dm['entities']['urls'][-1]['expanded_url']
							e = dm['entities']['urls'][-1]['expanded_url']
							if "http:" in e:
			                        		name = re.split('http://twitter.com/|,|/status/| ',dm['entities']['urls'][-1]['expanded_url'])
							if "https:" in e:
								name = re.split('https://twitter.com/|,|/status/| ',dm['entities']['urls'][-1]['expanded_url'])
			                        	print name[1]
		
							f = name[1]
				                     	users.append(name[1])
						except:
							print "But no quote was found ..."

	                                if "add:" in endcmd or "add :" in endcmd or "Add :" in endcmd or "Add:" in endcmd and len(sample) > 0:
        	                                addkey.append(endcmd[0].split(":",1)[1])
						print "You asked to add keywords :"
						h = "You asked to add Keywords :",addkey
						print "You asked to add Keywords :",addkey

	                                if not "banuser"in endcmd and not "Banuser" in endcmd and not "add:" in endcmd and not "Add:" in endcmd and not "add :" in endcmd and not "Add :" in endcmd :
	                                        words.append(endcmd[0])

			
			    g = "%i Banned topic , %i Banned Users Detected and %i Keywords Detected" % (len(words),len(users),len(addkey))
			    print "%i Banned topic , %i Banned Users Detected and %i Keywords Detected" % (len(words),len(users),len(addkey))			


	                    print 	
	                    
                            print 

				

			    try:
                                        file = open("./Data/Request.log","r")
                                        file.close()
                            except:
                                        print "=="
                                        print "File does not exist (Request.log)"
                                        print "Creating file"
                                        print "=="
                                        file = open("./Data/Request.log","w")
                                        file.write("")
                                        file.close()
			    
			    file = open("./Data/Request.log","a")
			    file.write("\n"+"#####"+"\n"+str(a)+"\n"+str(b)+"\n"+str(c)+"\n"+str(d)+"\n"+str(e)+"\n"+str(f)+"\n"+str(g)+"\n"+str(h)+"\n"+"Users: "+str(users)+"\n"+"Topic: "+str(words)+"\n"+"#####"+"\n")
			    file.close

		            try:
		                        file = open(Tmpbppl,"r")
		                        file.close()
		            except:
		                        print "=="
		                        print "File does not exist (Tmpbppl)"
		                        print "Creating file"
		                        print "=="
		                        file = open(Tmpbppl,"w")
		                        file.write("")
		                        file.close()

		            try:
		                        file = open(Tmpword,"r")
		                        file.close()
		            except:
		                        print "=="
		                        print "File does not exist (Tmpword)"
		                        print "Creating file"
		                        print "=="
		                        file = open(Tmpword,"w")
		                        file.write("")
		                        file.close()


                            try:
                                        file = open(Tmpkey,"r")
                                        file.close()
                            except:
                                        print "=="
                                        print "File does not exist (Tmpkey)"
                                        print "Creating file"
                                        print "=="
                                        file = open(Tmpkey,"w")
                                        file.write("")
                                        file.close()



			    file = open(Tmpbppl,"a")

			    for item in users:
                		file.write("\n"+str(item.replace(" ","").replace(",","")))
                	    file.close()
	


			    file = open(Tmpword,"a")
			
			    for item in words:
				file.write("\n"+str(item))
			    file.close()

                            file = open(Tmpkey,"a")

                            for item in addkey:
                                file.write("\n"+str(item))
                            file.close()


			    print
			    print 
        		    Fig = Figlet(font='cybermedium')
        		    print Fig.renderText('Added new items to files')
			    print
	
	                    time.sleep(2)

			    Idlist(dm['id'])

	                else:
	                	print "%s You re not the boss of me now !"% dm['sender']['screen_name']

			
		else:
			    print
                            Fig = Figlet(font='cybermedium')
                            print Fig.renderText('Old Cmd')
			    print

	Banned = 0	

def SaveDouble(text):
		print
		print

                Fig = Figlet(font='rev')
                print Fig.renderText('SaveDouble()')
                print
                #time.sleep(0.3)

		text = text.replace("\n"," ")

                try:
                        file = open(doublesaved,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (Double Saved)"
                        print "Creating file"
                        print "=="
                        file = open(doublesaved,"w")
                        file.write("")
                        file.close()

                file = open(doublesaved,"a")
                file.write("\n"+str(text))
                file.close()

                print
                print
                print "*=*=*=*=*=*=*=*=*=*"
                print "SAVING TWEET TO TMP :",text
                Fig = Figlet(font='larry3d')
                print Fig.renderText('Saved')
                print "*=*=*=*=*=*=*=*=*=*"
                print
                print
                #time.sleep(0.3)

def STOPEVERYTHING(screen):
	    scenes = []
	    effects = [
	        Print(screen, ColourImageFile(screen, "./Data/th3j3st3r.gif",
	                                      screen.height-20), 18,
	              stop_frame=100),
		Print(screen,
                	Rainbow(screen, FigletText("A WILD J3ST3R\n!!!!!!! APPEARS !!!!!!!", font="basic")),
                	y=screen.height // 9 - 2),

#	        Print(screen,
#	              FigletText("A WILD J3ST3R\n!!!!!!! APPEARS !!!!!!!", font='basic'),
#	              screen.height//9-2, colour=1),
	    ]
	    scenes.append(Scene(effects))
#            bla = "bla"
#            scenes.append(bla)
            try:
                screen.play(scenes,repeat=False)
            except:
                pass



def CheckDouble():


		global bandouble

                Fig = Figlet(font='rev')
                print Fig.renderText('CheckDbl()')
		print


                try:
                        file = open(doublesaved,"r")
                        file.close()
                except:
                        print "=="
                        print "File does not exist (doublesaved)"
                        print "Creating file"
                        print "=="
                        file = open(doublesaved,"w")
                        file.write("")
                        file.close()

		clean_lines = []

		with open(doublesaved, "r") as f:
		    lines = f.readlines()
		    clean_lines = [l.strip() for l in lines if l.strip()]

                with open(doublesaved, "w") as f:
                    f.writelines('\n'.join(clean_lines))

		file = open(doublesaved,"r+")
                lines = file.read().splitlines()

		for saved in lines:

					bandouble.append(saved)
                print "*=*=*=*=*=*=*=*=*=*"
#                print "New lenght of BanDouble :",len(bandouble)
                Fig = Figlet(font='larry3d')
                print Fig.renderText('BanDouble Updated')
                print "*=*=*=*=*=*=*=*=*=*"
                print
		time.sleep(2)



def flushtmp():

	global apicall
	global updatecall
	global twitter

	goflush = 0

        Fig = Figlet(font='rev')
        print Fig.renderText('flushtmp()')

	time.sleep(3)
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
	time.sleep(3)
	try:
		global newkeywords
		global checkM
                oldlen = len(wordlist)
                file = open(noresult,"r")
                lines2 = file.read().splitlines()
                lenmatch2 = len(set(lines2) & set(wordlist))

		print
		print "=="
                Fig = Figlet(font='doom')
                print Fig.renderText('Removing Last Searches with No Result')
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

                Fig = Figlet(font='doom')
                print Fig.renderText('Removing Old Searches')
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

		global mcdone

		if mcdone == 0:
                	Fig = Figlet(font='rev')
                	print Fig.renderText('LastSearch()')
			time.sleep(3)
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
			mcdone = mcdone + 1
			time.sleep(0.3)
		else:
			print "=="
                	Fig = Figlet(font='cybermedium')
                	print Fig.renderText('Saved already')
			print "=="
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
        if allok == 1 or allok == 2:
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


		if nbrRtwt <= 0:
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
		else:
	                print "%d Apicall Left (more or less)." %nbrRtwt
	                print
	                time.sleep(2)

		if nbrRtwt > len(QueueList):
			nbrRtwt = len(QueueList)
                	print
			print "More than enough only %d tweets in queue !" % len(QueueList)
                	print
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
				if tmpbypass != 1:
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
										if tmpbypass != 1:
											limits()

									if fuck == 3:
										print
										print
										Fig = Figlet(font='cybermedium')
                                        					print Fig.renderText('The Lanister sends their regards ..')
										sys.exit()
									else:
										restabit = 1
										if tmpbypass != 1:
											limits()
							if "Twitter API returned a 429 (Too Many Requests), Rate limit exceeded" in e:
									restabit = 1
									if tmpbypass != 1:
										limits()
							if "Twitter API returned a 403 (Forbidden), You have already retweeted this tweet." in e:
									print "Already Retweet trying next one"
									apicall = apicall + 1
									Saveid(FinalItem)
							if "(110, 'ETIMEDOUT')" in e:
									print " Mysterious Timeout ..."
									twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
									restabit = 1
									if tmpbypass != 1:
										limits()

		if allok == 2:
                                                                        SaveTotalCall(apicall,updatecall)
                                                                        lastmeal(Keywords[:rndwords])
                                                                        Fig = Figlet(font='cybermedium')
                                                                        print Fig.renderText('Exiting sorry for late')
									sys.exit()
		if tmpbypass == 1:
			print "##############################################################################################################"
			print "##############################################################################################################"
			Fig = Figlet(font='basic')
			print Fig.renderText("The End")
			print "##############################################################################################################"
			print "##############################################################################################################"
			print 

			sys.exit()
def tweetlist(point,id):


        Fig = Figlet(font='rev')
        print Fig.renderText('Tweetlist()')
        ammo = str(point) + "-" + str(id)
        retweetlist.append(ammo)
#	#time.sleep(0.3)
	print "=="
        Fig = Figlet(font='epic')
        print Fig.renderText('Loaded into Queue !')
	print "=="
	print
	#time.sleep(0.3)




def limits():
        Fig = Figlet(font='rev')
        print Fig.renderText('Limits()')

#	#time.sleep(0.3)
	global apicall
	global updatecall
	global totalupdatecall
	global totalcall
	global twitter
	global searchlimit
	global restabit
	global waithour
	global waithalf
	global time2wait
	global startedat
	global allok
	global tmpbypass
        startedat = datetime.datetime.now()

	if waithour == 1:

                print
                print
                print
		Request()
                print
                print
                print

                print "****************************************"
                print "****************************************"
                print
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ARE REACHED !!')
                print ""
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving current Search Terms')

                lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Resetting current apicalls')


                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Login Out')
                print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waiting 60 minutes')
                print
                print
                print
                print
                print
                print

		time2wait = 3600
		Screen.wrapper(credits)

                updatecall = 0
                apicall = 0
                searchlimit = 0
                restabit = 0
		waithour = 0

                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waking up ..')
                #time.sleep(0.3)
                print ""
                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
                print

                print

	if restabit == 1:
		print
                print
                print
		Request()
                print
                print
                print

                print "****************************************"
                print "****************************************"
                print
	        Fig = Figlet(font='epic')
	        print Fig.renderText('Mysterious Error !!!')
                print ""
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving current Search Terms')

		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Resetting current apicalls')


                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Login Out')
		print
                Fig = Figlet(font='')
                print Fig.renderText('Waiting 5 minutes')

		time2wait = 300
		Screen.wrapper(credits)

                updatecall = 0
                apicall = 0
                searchlimit = 0
		restabit = 0

                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waking up ..')
		#time.sleep(1)
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
		Request()
                print "****************************************"
                print "****************************************"
                print
                Fig = Figlet(font='epic')
                print Fig.renderText('SEARCH LIMITS ALMOST REACHED')
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Resetting current apicalls')


                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Login Out')
		print
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Waiting 15 minutes')
                print
                print
                print
                print
                print
                print
		time2wait = 900
		Screen.wrapper(credits)

                updatecall = 0
                apicall = 0
		searchlimit = 0

                Fig = Figlet(font='cybermedium')
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
		Request()
		print "****************************************"
		print "****************************************"
		print
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ALMOST REACHED')
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Resetting current apicalls')


                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Login Out')
		print
                Fig = Figlet(font='cybermedium')

		if waithalf != 1:
                	print Fig.renderText('Waiting 15 minutes')
		
		
			time2wait = 900
			Screen.wrapper(credits)
		else:
                        print Fig.renderText('Waiting 30 minutes')

			time2wait = 1800
			Screen.wrapper(credits)                


		updatecall = 0
                apicall = 0
                Fig = Figlet(font='cybermedium')
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


	if totalcall > 8888:
                print
                print
                print
                print
                print
		Request()
                print "****************************************"
                print "****************************************"

                print

                print
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ALMOST REACHED (total)')
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Resetting current apicalls')
		allok = 1
                print
                print
                print
                print
                print
                print
		tmpbypass = 1
		Retweet()

	if totalupdatecall > 2223:
		Request()
                print
                print
                print
                print
                print
                print "****************************************"
                print "****************************************"
                Fig = Figlet(font='epic')
                print Fig.renderText('CURRENT LIMITS ALMOST REACHED (update)')
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving current Search Terms')
		lastmeal(Keywords[:rndwords])
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Saving Total Calls to file')
                SaveTotalCall(apicall,updatecall)
                Fig = Figlet(font='cybermedium')
                print Fig.renderText('Resetting current apicalls')
                print
                print
                print
                print
                print
                print
 		allok = 1
 		Retweet()

        print
        print "==================="
#       print "Current Apicall = ",apicall
#       print "Total call = ",totalcall
#       print "="
#       print "Current Update call =",updatecall
#        print "Total Update call = ",totalupdatecall
        Fig = Figlet(font='cybermedium')
        print Fig.renderText('Ok')
        print "==================="
        #time.sleep(1)




def Ban(tweet,sender,id,bio):


	global Banned
	global totalnokeyword
	global totalbannedwords
	global totalalrdysnd
	global totalff
	global totalhf
	global totalbannedppl


	ushallpass = 0

        Fig = Figlet(font='rev')
        print Fig.renderText('Ban()')
	print
        print "*=*=*=*=*=*=*=*=*=*"

#	Fig = Figlet(font='cybermedium')
#        print Fig.renderText('Verify if this Tweet contains at least one of the Keywords :')
	if Banned == 0:

                for item in emolist:
                        emotst = tweet.count(item)
                        if emotst > 0:
                                print "Found this emoji : ",item
                        	Banned = 1
                if Banned == 1:
                        Fig = Figlet(font='cybermedium')
                        print Fig.renderText('This tweet contains an Emoticon and must die . ')
                        print
                        print tweet
                        print
                        print
                        print Fig.renderText('Going To Trash')
                        print "*=*=*=*=*=*=*=*=*=*"



	if Banned == 0:
	   for mustbe in Keywordsave:
	  	if ushallpass == 0:
 	    		
                		pos = 0
                		lng = int(len(mustbe))
				if lng >= 12:
                			half = lng / 2
				else:
					half = lng - 1
                		next = int(half) + pos
                		sample = mustbe[pos:int(half)]
                		maxpos = pos + int(len(sample))

		                while maxpos < int(lng):
				    
					
		   		    try:
                                        if len(sample) <= 3:
                                                pos = pos + 1
                                                next = int(half) + pos
                                                sample = mustbe[pos:int(next)]
                                                maxpos = pos + int(len(sample))


		                        if str(sample.lower()) in str(tweet.lower()) and sample.count(" ") < 2:
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
						#print "Sample : ",sample
                                		pos = pos + 1
                                		next = int(half) + pos
                                		sample = mustbe[pos:int(next)]
                                		maxpos = pos + int(len(sample))
				    except:
                                                pos = pos + 1
                                                next = int(half) + pos
                                                sample = mustbe[pos:int(next)]
                                                maxpos = pos + int(len(sample))
	   if ushallpass != 1:
                                print
                                print Fig.renderText('Did not found any Keyword in tweet.')
				totalnokeyword = totalnokeyword + 1
				Banned = 1
				#time.sleep(1)
	   print "*=*=*=*=*=*=*=*=*=*"
#	Fig = Figlet(font='cybersmall')
#	print Fig.renderText('Checking if this Tweet contains any forbidden terms:')

	for forbid in banlist:
	    if Banned == 0:
		if str(forbid.lower()).replace(":"," ").replace(","," ").replace("!"," ").replace("?"," ").replace(";"," ").replace("'"," ").replace('"',' ').replace("-"," ").replace("_"," ") in str(tweet.lower()).replace(":"," ").replace(","," ").replace("!"," ").replace("?"," ").replace(";"," ").replace("'"," ").replace('"',' ').replace("-"," ").replace("_"," "):

			print
	                Fig = Figlet(font='cybermedium')
	                print Fig.renderText('This tweet contains banned words :')
			print
			print tweet
			print
			print "** %s **" % str(forbid)
			print
			print Fig.renderText('Going To Trash ...')
			print "*=*=*=*=*=*=*=*=*=*"
			print
			Banned = 1
			totalbannedwords = totalbannedwords + 1
			#time.sleep(0.3)
        for forbid in banlist:
            if Banned == 0:
                if str(forbid.lower()) in str(bio.lower()):

                        print
                        Fig = Figlet(font='cybermedium')
                        print Fig.renderText('This user profile contains banned words :')
                        print
                        print bio
                        print
                        print "** %s **" % str(forbid)
                        print
                        print Fig.renderText('Going To Trash ...')
                        print "*=*=*=*=*=*=*=*=*=*"
                        print
                        Banned = 1
                        totalbannedwords = totalbannedwords + 1
                        #time.sleep(0.3)

        for forbid in banppl:
	    if Banned == 0:
                if str(forbid.lower()) in str(sender.lower()):

                        print
	                Fig = Figlet(font='cybermedium')
	                print Fig.renderText('This tweet is from a banned user :')
                        print
                        print tweet
                        print
			print "** %s **" % forbid
			print
                        print Fig.renderText('Going To Trash')
                        print "*=*=*=*=*=*=*=*=*=*"
                        print
                        Banned = 1
			totalbannedppl = totalbannedppl + 1
                        #time.sleep(3)

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
			totalalrdysnd = totalalrdysnd + 1
                        #time.sleep(0.3)


	for item in bandouble:

	    if Banned == 0 and len(item) > 10:
		pos = 0
		lng = len(item)
		half = lng / 2
		next = int(half) + pos
		sample = item[pos:int(half)]
	        maxpos = pos + int(len(sample))

		while int(maxpos) < int(lng):
		    try:
			if str(sample) in str(tweet) and str(sample) != " ":
				print
	                        Fig = Figlet(font='cybermedium')
        	                print Fig.renderText('Some parts are Identicals to a Previous Tweet :')
	                        print "Tweet :",tweet
	                        print
				print "Found Matched :",sample
	                        Saveid(id)
	                        print
	                        print Fig.renderText('Going To Trash')
	                        print "*=*=*=*=*=*=*=*=*=*"


				print
				maxpos = int(lng)
				Banned = 1
				totalalrdysnd = totalalrdysnd + 1
			else:
				pos = pos + 1
			        next = int(half) + pos
			        sample = item[pos:int(next)]
			        maxpos = pos + int(len(sample))
		    except:
                                pos = pos + 1
                                next = int(half) + pos
                                sample = item[pos:int(next)]
                                maxpos = pos + int(len(sample))



	if Banned == 0:
		if tweet.count("@") >= 3:


	                Fig = Figlet(font='basic')
	                print Fig.renderText('Follow Friday')
			Fig = Figlet(font='cybermedium')
	                print Fig.renderText('Going To Trash')
	                print "*=*=*=*=*=*=*=*=*=*"
	                print
			Banned = 1
			totalff = totalff +1
			#time.sleep(0.5)

	        if tweet.count("#") >= 3:


	                Fig = Figlet(font='basic')
	                print Fig.renderText('HashTags Fever')
	                Fig = Figlet(font='cybermedium')
	                print Fig.renderText('Going To Trash')
	                print "*=*=*=*=*=*=*=*=*=*"
	                print
			Banned = 1
			totalhf = totalhf + 1
	                #time.sleep(0.5)

		if twtbyuser.count(str(sender)) >= 2:
                        Fig = Figlet(font='basic')
                        print Fig.renderText('Too many Tweets From this user ')
                        Fig = Figlet(font='cybermedium')
                        print Fig.renderText('Going To Trash')
                        print "*=*=*=*=*=*=*=*=*=*"
                        print
                        Banned = 1
                        totalbannedppl = totalbannedppl + 1
                        #time.sleep(0.5)
		else:
			figy = "Nbr of tweets for this user : ",str(twtbyuser.count(sender))
                        Fig = Figlet(font='cybermedium')
                        print Fig.renderText(str(figy))
                        print "*=*=*=*=*=*=*=*=*=*"
			#time.sleep(0.3)


	if Banned == 0:

                Fig = Figlet(font='speed')
                print Fig.renderText('Good To Go !!')
	        print "*=*=*=*=*=*=*=*=*=*"
		print
		#time.sleep(0.3)


def Saveid(id):

                Fig = Figlet(font='rev')
                print Fig.renderText('Saveid()')
		print
#		#time.sleep(0.3)

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
		#time.sleep(0.3)


def Idlist(id):
		global Banned
		global alreadysend
		global Totalsent
		global doneid

                Fig = Figlet(font='rev')
                print Fig.renderText('Idlist()')
#		#time.sleep(0.3)

		alreadysend = 0
		if doneid == 0:
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


			Totalsent = sum(1 for line in open(idsaved))
			doneid = 1



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
					Banned = 1
					alreadysend = 1
					#time.sleep(2)


		if alreadysend == 0:

			print
			print "*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
                	Fig = Figlet(font='basic')
                	print Fig.renderText('Unknown Tweet ID')

			print "*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
			print
			#time.sleep(0.3)





def Scoring(tweet,search):

	global apicall
	global totalcall
	global updatecall
	global totalupdatecall
	global Banned
	global bandouble
	global alreadysend
	global moyscore
	global Rthourtweet
	global totalscore
	global totalalrdysnd
	global totallanguage
	global total2old
	global twtbyuser
	global tobsnd
        global restabit
        global twitter
        global fuck
        global waithour
        global waithalf
        global rtsave

	Bouffon = 0
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
	##time.sleep(0.2)

	print
	print
	print
        print "*************************************************************************************" 
        Fig = Figlet(font='basic')
        print Fig.renderText('Starting Scoring function')
	print ""

        if 'screen_name' in tweet['user'] :
                        tstjester = tweet['user']['screen_name']
			if tstjester == "th3j35t3r":
				Bouffon = 1





	if len(tweet['text']) < 70 :
                                Banned = 1
                                print
                                Fig = Figlet(font='cybermedium')
                                print Fig.renderText('NOT ENOUGH TEXT')
                                print
                                print
                                print Fig.renderText('Going To Trash')
                                print "*=*=*=*=*=*=*=*=*=*"
	if Banned == 0 or Bouffon == 1:
		if 'retweet_count' in tweet:

			print "##"
			print "This tweet has been retweeted %i times " % tweet['retweet_count']
			print "##"
			luck = randint(0,6)
			if tweet['retweet_count'] < 1 and luck != 1:
				Banned = 1
                                print
                                Fig = Figlet(font='cybermedium')
                                print Fig.renderText('NOT ENOUGH RETWEET')
                                print
                                print
                                print Fig.renderText('Going To Trash')
                                print "*=*=*=*=*=*=*=*=*=*"
				##time.sleep(0.2)
			if tweet['retweet_count'] < 2 and luck == 1:
                                print
                                Fig = Figlet(font='cybermedium')
                                print Fig.renderText('Not enough retweet')
                                print
                                print
                                print Fig.renderText('But lets give it a chance ...')
                                print "*=*=*=*=*=*=*=*=*=*"

                                print

			if tweet['retweet_count'] > 2 and tweet['retweet_count'] <= 23:
				Score  = Score + int(tweet['retweet_count'])
                        
                        if tweet['retweet_count'] > 23 and tweet['retweet_count'] <= 30:
                                Score  = Score + 23 + 3
                        if tweet['retweet_count'] > 30 and tweet['retweet_count'] <= 40:
                                Score  = Score + 23 + 4
                        if tweet['retweet_count'] > 40 and tweet['retweet_count'] <= 50:
                                Score  = Score + 23 + 5
                        if tweet['retweet_count'] > 50 and tweet['retweet_count'] <= 50:
                                Score  = Score + 23 + 6
                        if tweet['retweet_count'] > 60 and tweet['retweet_count'] <= 70:
                                Score  = Score + 23 + 7
                        if tweet['retweet_count'] > 70 and tweet['retweet_count'] <= 80:
                                Score  = Score + 23 + 8
                        if tweet['retweet_count'] > 80 and tweet['retweet_count'] <= 90:
                                Score  = Score + 23 + 9
                        if tweet['retweet_count'] > 90 and tweet['retweet_count'] <= 100:
                                Score  = Score + 23 + 10
                        if tweet['retweet_count'] > 100 and tweet['retweet_count'] <= 110:
                                Score  = Score + 23 + 11
                        if tweet['retweet_count'] > 110 and tweet['retweet_count'] <= 120:
                                Score  = Score + 23 + 12
                        if tweet['retweet_count'] > 120 and tweet['retweet_count'] <= 130:
                                Score  = Score + 23 + 13
                        if tweet['retweet_count'] > 130 and tweet['retweet_count'] <= 140:
                                Score  = Score + 23 + 14
                        if tweet['retweet_count'] > 140 and tweet['retweet_count'] <= 150:
                                Score  = Score + 23 + 15
                        if tweet['retweet_count'] > 150 and tweet['retweet_count'] <= 160:
                                Score  = Score + 23 + 16
                        if tweet['retweet_count'] > 160 and tweet['retweet_count'] <= 170:
                                Score  = Score + 23 + 17
                        if tweet['retweet_count'] > 170 and tweet['retweet_count'] <= 180:
                                Score  = Score + 23 + 18
                        if tweet['retweet_count'] > 180 and tweet['retweet_count'] <= 190:
                                Score  = Score + 23 + 19
                        if tweet['retweet_count'] > 190 and tweet['retweet_count'] <= 200:
                                Score  = Score + 23 + 20
                        if tweet['retweet_count'] > 200 and tweet['retweet_count'] <= 210:
                                Score  = Score + 23 + 21
                        if tweet['retweet_count'] > 210 and tweet['retweet_count'] <= 223:
                                Score  = Score + 23 + 23
                        if tweet['retweet_count'] > 323:
                                print 
                                print
                                Fig = Figlet(font='cybermedium')
                                print Fig.renderText('Too many Fav checking if this tweet is from a known user or friend..')
                                print
                                print
                                coop = tweet['user']['screen_name']
                                nogo = 1
                                print
                                print "##"

                                print "##"
                                print

                                if coop in Following:
                                        print "##"
                                        print "This tweet is from a known user : ",tweet['user']['screen_name']
                                        print "##"
                                        Score = Score + 123
                                        nogo = 0
                                if coop in Friends:
                                        print "##"
                                        print "This tweet is from a friend : ",tweet['user']['screen_name']
                                        print "##"
                                        nogo = 0
                                        Score = Score + 123
                                if nogo == 1: 
					print "Nop ..."
					print
                                        print "Too many retweets to be legit."
                                        Score = Score - 232
                                        Banned = 1


				##time.sleep(0.2)

        	else:


                                print





        if 'entities' in tweet:
	   if Banned == 0 or Bouffon == 1:
		print

#             	if 'symbols' in tweet['entities'] and len(tweet['entities']['symbols']) > 0:
#                        print "##"
#                        print "This tweet contains a Symbol and must die for no reason. "
#                        print "##"
#                        Banned = 1
#			time.sleep(1)
#		print

	   if Banned == 0 or Bouffon == 1:

		if 'urls' in tweet['entities'] and len(tweet['entities']['urls']) > 0:
			print "##"
			print "This tweet contains a link : ",tweet['entities']['urls'][-1]['expanded_url']
			print "##"
			Score = Score + 3
                if 'hashtags' in tweet['entities'] and len(tweet['entities']['hashtags']) > 0:
			print "##"
                        print "This tweet contains Hashtag : ",tweet['entities']['hashtags'][-1]['text']
			print "##"
                        Score = Score + 1


                if 'media' in tweet['entities'] and len(tweet['entities']['media']) > 0:
			print "##"
                        print "This tweet contains Media : ",tweet['entities']['media'][-1]['media_url']
			print "##"
                        Score = Score + 3

                if tweet['favorite_count'] > 0:

			print "##"
                        print "This tweet has been fav : ",tweet['favorite_count']
			print "##"
			Score = Score + 1
			fav = tweet['favorite_count']
			if fav > 1 and fav <= 23:
                        	Score = Score + int(fav)
			if fav > 23 and fav <= 30:
				Score = Score + 23 + 3
                        if fav > 30 and fav <= 40:
                                Score = Score + 23 + 4
                        if fav > 40 and fav <= 50:
                                Score = Score + 23 + 5
                        if fav > 50 and fav <= 60:
                                Score = Score + 23 + 6
                        if fav > 60 and fav <= 70:
                                Score = Score + 23 + 7
                        if fav > 70 and fav <= 80:
                                Score = Score + 23 + 8
                        if fav > 80 and fav <= 90:
                                Score = Score + 23 + 9
                        if fav > 90 and fav <= 100:
                                Score = Score + 23 + 10 
                        if fav > 100 and fav <= 110:
                                Score = Score + 23 + 11
                        if fav > 110 and fav <= 120:
                                Score = Score + 23 + 12
                        if fav > 120 and fav <= 130:
                                Score = Score + 23 + 13
                        if fav > 130 and fav <= 140:
                                Score = Score + 23 + 14
                        if fav > 140 and fav <= 150:
                                Score = Score + 23 + 15
                        if fav > 150 and fav <= 160:
                                Score = Score + 23 + 16
                        if fav > 160 and fav <= 170:
                                Score = Score + 23 + 17
                        if fav > 170 and fav <= 180:
                                Score = Score + 23 + 18
                        if fav > 180 and fav <= 190:
                                Score = Score + 23 + 19 
                        if fav > 190 and fav <= 200:
                                Score = Score + 23 + 20
                        if fav > 200 and fav <= 210:
                                Score = Score + 23 + 21
                        if fav > 210 and fav <= 220:
                                Score = Score + 23 + 22
                        if fav > 220 and fav <= 323:
                                Score = Score + 23 + 23
			if fav >= 324:
                      		coop = tweet['user']['screen_name']
				nogo = 1
                        	print
                        	print "##"
                        	print "Too many Fav checking if this tweet is from a known user or friend ",coop
                        	print "##"
                        	print

                        	if coop in Following:
                        	        print "##"
                        	        print "This tweet is from a known user : ",tweet['user']['screen_name']
                        	        print "##"
                        	        Score = Score + 123
					nogo = 0
                        	if coop in Friends:
                        	        print "##"
                        	        print "This tweet is from a friend : ",tweet['user']['screen_name']
                        	        print "##"
					nogo = 0
                        	        Score = Score + 123
				if nogo == 1: 
					print "Too many Favs to be legit."
					Score = Score - 232
					Banned = 1
				






                if 'followers_count' in tweet['user'] and tweet['user']['followers_count'] > 0:
			print "##"
                        print "Source followers count  : ",tweet['user']['followers_count']
			print "##"

                        if tweet['user']['followers_count'] <= 400:
                                print 
                                print
                                Fig = Figlet(font='cybermedium')
                                print Fig.renderText('Not Enough Followers')
                                print tweet['user']['followers_count']
                                print
                                Fig = Figlet(font='cybermedium')
                                print
                                coop = tweet['user']['screen_name']
                                nogo = 1
                                print
                                print "##"
                                print "Checking if this tweet is from a known user or friend ",coop
                                print "##"
                                print

                                if coop in Following:
                                        print "##"
                                        print "This tweet is from a known user : ",tweet['user']['screen_name']
                                        print "##"

                                        nogo = 0
                                if coop in Friends:
                                        print "##"
                                        print "This tweet is from a friend : ",tweet['user']['screen_name']
                                        print "##"
                                        nogo = 0
                                        Score = Score + 123
                                if nogo == 1: 
                                        print "Nop..."
                                        Banned = 1
                                


                                print Fig.renderText('Going To Trash')
                                print "*=*=*=*=*=*=*=*=*=*"
                                Banned = 1
				Score = Score - 10000

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

			if tweet['entities']['user_mentions'][-1]['screen_name'] == "th3j35t3r":
				Bouffon = 1

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
        	                Score = Score + 10

			if coop in Friends:
				print "##"
				print "This tweet is from a friend : ",tweet['user']['screen_name']
				print "##"

				Score = Score + 5

			if coop == "th3j35t3r" or Bouffon == 1:


            
	    			Score = Score + 9000
	    			randodge = ['Cool ','Gorgeous ','Soft ','Enjoy ','Totally ','Awesome ','Fun ','Easy ','Free ','Wow ','Much ','Many ','Too ','So ','Such ','Very ','Amaze ']
	    			dodgecoin = str(choice(randodge)) + str(choice(banlist)) + " "
	    			Screen.wrapper(STOPEVERYTHING)
	    			time.sleep(2)
	    			print "================================================================================"
	    			print
	    			Fig = Figlet(font='basic')
            			print Fig.renderText('SUCH SCORE !!')
	    			print
            			#print "================================================================================"
            			Fig = Figlet(font='puffy')
            			figy = "Score = %i" % Score
            			print Fig.renderText(str(figy))
            			#print "================================================================================"
	    			#time.sleep(2)
            			#print "================================================================================"
            			print
            			Fig = Figlet(font='basic')
            			print Fig.renderText('MUCH TWEET !!')
            			print
            			#print "================================================================================"
            			Fig = Figlet(font='puffy')
            			print Fig.renderText("Text:")
	    			print tweet['text']
            			#print "================================================================================"
	    			time.sleep(2)
            			#print "================================================================================"
            			print
            			Fig = Figlet(font='basic')
            			print Fig.renderText('MANY RETWEET !!')
            			print
            			#print "================================================================================"
            			Fig = Figlet(font='puffy')
            			figy = "Retweets = %i" % tweet['retweet_count']
            			print Fig.renderText(str(figy))
            			#print "================================================================================"
	    			time.sleep(2)
            			#print "================================================================================"
            			print
            			Fig = Figlet(font='basic')
            			print Fig.renderText('SO FAVORITE !!')
            			print
            			#print "================================================================================"
            			Fig = Figlet(font='puffy')
            			figy = "Favourites = %i" % tweet['favorite_count']
            			print Fig.renderText(str(figy))
            			#print "================================================================================"
	    			time.sleep(2)
            			#print "================================================================================"
            			print
            			Fig = Figlet(font='basic')
            			print Fig.renderText('VERY TREND !!')
            			print
            			#print "================================================================================"
            			Fig = Figlet(font='puffy')
            			figy = "Followers = %i" % tweet['user']['followers_count']
            			print Fig.renderText(str(figy))
            			#print "================================================================================"
            			time.sleep(2)
            			#print "================================================================================"
            			print
            			Fig = Figlet(font='basic')
            			print Fig.renderText('AMAZE TWEET!!')
            			print
            			print "================================================================================"
            			Fig = Figlet(font='puffy')
            			figy = "Amaze Now !"
            			print Fig.renderText(str(figy))
				link = "https://twitter.com/"+ str(choice(randodge).replace(" ","")) + "/status/" + str(tweet['id'])

				twit = tweet['text'].replace("@th3j35t3r","th3b0uf0n").replace("th3j35t3r","th3b0uf0n")
				dodgelink = str(dodgecoin) + " " + str(link)
				time.sleep(1)
				limits()

				Banned = 0
			        for forbid in bandouble:
				    if Banned == 0:
			                if forbid in tweet['text']:

			                        print
			                        Fig = Figlet(font='cybermedium')
			                        print Fig.renderText('This tweet is Identical to a Previous tweet :')
			                        print
			                        print tweet['text']
			                        print
						Saveid(tweet['id'])
			                        print
			                        print Fig.renderText('Going To Trash')
			                        print "*=*=*=*=*=*=*=*=*=*"
			                        print
			                        Banned = 1
						totalalrdysnd = totalalrdysnd + 1
			                        time.sleep(1)


				for item in bandouble:

				    if Banned == 0 and len(item) > 10:
					pos = 0
					lng = len(item)
					half = lng / 2
					next = int(half) + pos
					sample = item[pos:int(half)]
				        maxpos = pos + int(len(sample))

					while int(maxpos) < int(lng):
					    try:
						if str(sample) in str(tweet['text']) and str(sample) != " ":
							print
				                        Fig = Figlet(font='cybermedium')
			        	                print Fig.renderText('Some parts are Identicals to a Previous Tweet :')
				                        print "Tweet :",tweet['text']
				                        print
							print "Found Matched :",sample
				                        Saveid(id)
				                        print
				                        print Fig.renderText('Going To Trash')
				                        print "*=*=*=*=*=*=*=*=*=*"
							time.sleep(1)

							print
							maxpos = int(lng)
							Banned = 1
							totalalrdysnd = totalalrdysnd + 1
						else:
							pos = pos + 1
						        next = int(half) + pos
						        sample = item[pos:int(next)]
						        maxpos = pos + int(len(sample))
					    except:
			                                pos = pos + 1
			                                next = int(half) + pos
			                                sample = item[pos:int(next)]
			                                maxpos = pos + int(len(sample))
				Idlist(tweet['id'])

				if Banned == 0:
				   SaveDouble(str(twit))
				   try:
					print twit
					print 
					if len(dodgelink) > 140:
						dodgelink = dodgelink[:140]
					if len(twit) > 140:
						twit = twit[:137] + "..."
					twitter.update_status(status=str(twit))
					time.sleep(1)
					
					print
					twitter.update_status(status=str(dodgelink))
        			    	Fig = Figlet(font='cybermedium')
        			    	figy = "DONE"
					print Fig.renderText(str(figy))
        			        apicall = apicall + 2
        			        updatecall = updatecall + 2
					Saveid(tweet['id'])
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
									Screen.wrapper(wow)
									if fuck == 1 or fuck == 2:
										waithour = 1
										if tmpbypass != 1:
											limits()

									if fuck == 3:
										print
										print
										Fig = Figlet(font='cybermedium')
                                        					print Fig.renderText('The Lanister sends their regards ..')
										sys.exit()
									else:
										restabit = 1
										if tmpbypass != 1:
											limits()
							if "Twitter API returned a 429 (Too Many Requests), Rate limit exceeded" in e:
									restabit = 1
									Screen.wrapper(wow)
									if tmpbypass != 1:
										limits()
							if "Twitter API returned a 403 (Forbidden), Status is a duplicate." in e:
                                                                        apicall = apicall + 2
                                                                        Saveid(tweet['id'])
									Screen.wrapper(wow)
							if "Twitter API returned a 403 (Forbidden), You have already retweeted this tweet." in e:
									print "Already Retweet trying next one"
									apicall = apicall + 2
									Saveid(tweet['id'])
									Screen.wrapper(wow)
							if "(110, 'ETIMEDOUT')" in e:
									print " Mysterious Timeout ..."
									twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
									restabit = 1
									Screen.wrapper(wow)
									if tmpbypass != 1:
										limits()
            			   print "================================================================================"
          			   time.sleep(3)

	  			   Banned = 1
				else:

						Screen.wrapper(wow)
						print "================================================================================"
						Fig = Figlet(font='cybermedium')
                                        	print Fig.renderText(' WOW Already Sent !!')
						print "================================================================================"
						time.sleep(1)
	TwtTime = tweet['created_at']
        TwtTime = TwtTime.replace(" +0000 "," ")
        Timed = datetime.datetime.strptime(TwtTime,'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
	TimeFinal = datetime.datetime.strptime(Timed,'%Y-%m-%d %H:%M:%S')
	hourtweet = now - TimeFinal
	print
	print "This tweet was send at : ",TwtTime
	print
	##time.sleep(0.2)
	print
	luck = randint(0,10)
        try:
	  if Banned != 1:
	    if currentdate.day != 01:
                if TimeFinal.month != currentdate.month:
                                        Fig = Figlet(font='basic')
                                        print
                                        print Fig.renderText('WAY TOO OLD !')
                                        print
					if luck != 1:
                                        	Banned = 1
						total2old = total2old + 1
                                        if luck == 1:
                                        	print Fig.renderText('But who cares !')
                                        	print

		else:
			print
        except Exception as e:
                print e
                ##time.sleep(0.2)

	print

	try:
	     if Banned != 1:
		if TimeFinal.year != currentdate.year:
                                        Fig = Figlet(font='basic')
                                        print
                                        print Fig.renderText('FUCKING TOO OLD !')
                                        print
                                        if luck != 1:
                                                Banned = 1
                                                total2old = total2old + 1
                                        if luck == 1:
                                        	print Fig.renderText('But who cares !')
                                        	print

		else:
			print 
	except Exception as e:
		print e
		##time.sleep(0.2)
	try:
             if Banned != 1:
		if hourtweet.days == 1:
			print "Score - 13"
			print "More than a day Not so fresh ..."
			Score = Score - 13
		if hourtweet.days > 2:
                                        Fig = Figlet(font='basic')
					print
                                        print Fig.renderText('TOO OLD !')
					print
                                        if luck != 1:
                                                Banned = 1
                                                total2old = total2old + 1
                                        if luck == 1:
                                        	print Fig.renderText('But who cares !')
                                        	print

	except:
		pass

        if Banned != 1:
	  if 'retweeted_status' in tweet :
	   if 'created_at' in tweet['retweeted_status'] and len(tweet['retweeted_status']['created_at']) > 0:
		RtTime = tweet['retweeted_status']['created_at']
	        RtTime = RtTime.replace(" +0000 "," ")
	        RtTimed = datetime.datetime.strptime(RtTime,'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
		RtTimeFinal = datetime.datetime.strptime(RtTimed,'%Y-%m-%d %H:%M:%S')
		Rthourtweet = now - RtTimeFinal
		print "Retweet created at :" ,RtTimeFinal
	        try:
	
	            if currentdate.day != 01:
	                if RtTimeFinal.month != currentdate.month:
	                                        Fig = Figlet(font='basic')
	                                        print
	                                        print Fig.renderText('RT WAY TOO OLD !')
	                                        print
                                        	if luck != 1:
                                                	Banned = 1
                                                	total2old = total2old + 1
                                        	if luck == 1:
                                        		print Fig.renderText('But who cares !')
                                        		print

	                else:
	                        print
	        except Exception as e:
	                print e
	                ##time.sleep(0.2)
	
	        print
	
	        try:
	                if RtTimeFinal.year != currentdate.year:
	                                        Fig = Figlet(font='basic')
	                                        print
	                                        print Fig.renderText('RT FUCKING TOO OLD !')
	                                        print
	                                        Banned = 1
						total2old = total2old + 1
	                                        ##time.sleep(0.2)
	                else:
	                        print 
	        except Exception as e:
	                print e
	                ##time.sleep(0.2)
	
	if Banned != 1:
		if hourtweet.seconds < 3600:
			Score = Score + 23
			print "Less than an hour ago ."
			print "Score = + 23"
			print
			print "Score = ",Score
			print

		if hourtweet.seconds > 3600 and hourtweet.seconds <= 7200:
			Score = Score + 2 + 2
			print "An hour ago ."
			print "Score = + 22"

        	if hourtweet.seconds > 7200 and hourtweet.seconds <= 10800:
        	        Score = Score + 21
        	        print "Two hours ago ."
			print "Score = + 21"

        	if hourtweet.seconds > 10800 and hourtweet.seconds <= 14400:
        	        Score = Score + 20
        	        print "Three hours ago ."
			print "Score = + 20"

        	if hourtweet.seconds > 14400 and hourtweet.seconds <= 18000:
        	        Score = Score + 19
        	        print "Four hours ago ."
			print "Score = + 19"

        	if hourtweet.seconds > 18000 and hourtweet.seconds <= 21600:
                	Score = Score + 18
                	print "Five hours ago ."
			print "Score = + 18"

      	 	if hourtweet.seconds > 21600 and hourtweet.seconds <= 25200:
                	Score = Score + 17
                	print "Six hours ago ."
			print "Score = + 17"

        	if hourtweet.seconds > 25200 and hourtweet.seconds <= 28800:
			Score = Score + 16
                	print "Seven hours ago ."
			print "Score = + 16"

        	if hourtweet.seconds > 28800 and hourtweet.seconds <= 32400:
                	Score = Score + 15
                	print "Eight hours ago ."
                	print "Score = + 15"

        	if hourtweet.seconds > 32400 and hourtweet.seconds <= 36000:
        	        Score = Score + 14
        	        print "Nine hours ago ."
        	        print "Score = + 14"
        	if hourtweet.seconds > 36000 and hourtweet.seconds <= 39600:
        	        print "Ten hours ago ."
        	        print "Score = + 13"
                        Score = Score + 13
        	if hourtweet.seconds > 39600 and hourtweet.seconds <= 43200:
        	        Score = Score + 12
        	        print "Eleven hours ago ."
        	        print "Score =  + 12"
        	        print
        	        print "Score = ",Score
        	        print


		if hourtweet.seconds > 43200 and hourtweet.seconds <= 46800:
			print "Twelve hours ago ."
			Score = Score + 11
        	        print "Score = + 11"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 46800 and hourtweet.seconds <= 50400:
        	        Score = Score + 10
        	        print "Thirteen hours ago ."
        	        print "Score = + 10"
        	        print
        	        print "Score = ",Score
        	        print
	

        	if hourtweet.seconds > 50400 and hourtweet.seconds <= 54000:
        	        Score = Score + 9
        	        print "Fourteen hours ago ."
        	        print "Score = + 9"


        	if hourtweet.seconds > 54000 and hourtweet.seconds <= 57600:
        	        Score = Score + 8
        	        print "Fiveteen hours ago ."
        	        print "Score = + 8"
        	        print
        	        print "Score = ",Score
        	        print



        	if hourtweet.seconds > 57600 and hourtweet.seconds <= 61200:
        	        Score = Score + 7
        	        print "Sixteen hours ago ."
        	        print "Score = + 7"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 61200 and hourtweet.seconds <= 64800:
        	        Score = Score + 6
        	        print "Seventeen hours ago ."
        	        print "Score = + 6"
        	        print
        	        print "Score = ",Score
        	        print

                if hourtweet.seconds > 64800 and hourtweet.seconds <= 68400:
                        Score = Score + 5
                        print "Eighteen hours ago ."
                        print "Score = + 5"
                        print
                        print "Score = ",Score
                        print



        	if hourtweet.seconds > 68400 and hourtweet.seconds <= 72000:
        	        Score = Score + 4
        	        print "Nineteen hours ago ."
        	        print "Score = + 4"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 72000 and hourtweet.seconds <= 75600:
        	        Score = Score + 3
        	        print "twenty hours ago ."
        	        print "Score = + 3"
        	        print
        	        print "Score = ",Score
        	        print


        	if hourtweet.seconds > 75600 and hourtweet.seconds <= 79200:
                	Score = Score + 2
                	print "Twenty one hours ago ."
                	print "Score = + 2"
                	print
                	print "Score = ",Score
                	print

        	if hourtweet.seconds > 79200 and hourtweet.seconds <= 82800:
                	Score = Score + 1
                	print "Twenty two hours ago ."
                	print "Score = + 1"
                	print
                	print "Score = ",Score
                	print

	        if hourtweet.seconds > 82800 and hourtweet.seconds < 86400:
	                print "Twenty three hours ago ."
			Score = Score + 0
	                print "Score = + 0"
	                print
	                print "Score = ",Score
	                print

	#time.sleep(0.3)



	moyscore.append(Score)

	if tweet['lang'] == "en" or tweet['lang'] == "fr" or tweet['lang'] == "en-gb":

		Idlist(tweet['id'])

		if alreadysend == 0:

			Ban(tweet['text'],tweet['user']['screen_name'],tweet['id'],tweet['user']['description'])

			if Banned != 1:
				if Score >= 16:
					Screen.wrapper(win)
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
					twtbyuser.append(tweet['user']['screen_name'])
					tobsnd.append(tweet['text'])
					bandouble.append(tweet['text'].replace("\n"," "))
					tweetlist(Score,tweet['id'])
					SaveDouble(tweet['text'])

				else:
					print ""
                                        Fig = Figlet(font='epic')
                                        print Fig.renderText("But ..")
                                        print "================================================================================"
                                        Fig = Figlet(font='puffy')
					figy = "Score = %i" % Score
                                        print Fig.renderText(str(figy))
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
					totalscore = totalscore + 1
					##time.sleep(0.2)
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
					##time.sleep(0.2)
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
					totalalrdysnd = totalalrdysnd + 1
                                        ##time.sleep(0.2)



	else:
				print
                                Fig = Figlet(font='epic')
                                print Fig.renderText("but ..")
                                print "================================================================================"
				Fig = Figlet(font='cybermedium')
				print Fig.renderText("Language")
                                print "==============================================================================="
				print "Language : ",tweet['lang']
                                print tweet['text']
				print "================================================================================"
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
                                print "This tweet does not match the requirement needed to be retweeted."
				print ":( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :( :("
				print "================================================================================"
                                print ""
				##time.sleep(0.2)
				totallanguage = totallanguage +1
        #time.sleep(0.3)


	print
	print






def searchTst(word):
	global apicall
	global updatecall
	global twitter
	global restabit
	global searchdone
	global searchlimit
	global searchapi

        Fig = Figlet(font='rev')
        print Fig.renderText('SearchTst()')
	#time.sleep(0.3)
	ratechk = 0

	if searchdone == 0:

		try :
        	        twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
        		rate = twitter.get_application_rate_limit_status()
		        search = rate['resources']['search']['/search/tweets']['remaining']
			searchapi = int(search)
			
			apicall = apicall + 2
			ratechk = 1
	
	        except Exception as e:
	
			print "mysterious error"
			print
			print e
	                twitter = Twython(app_key, app_secret, oauth_token, oauth_token_secret)
			apicall = apicall + 1
			restabit = 1
			limits()
	        if ratechk != 1:
	                searchapi = 23
	                ratechk = 1

	if searchapi > 2:
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
				searchapi = searchapi - 1
				#time.sleep(0.3)
		
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
				#time.sleep(0.3)
				print "=="
				print ""
				#time.sleep(0.3)
				print ""
	
			except:
						apicall = apicall + 1
	                                        print
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	                                        print "Error Sorry trying next one"
						print "!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	                                        print
						#time.sleep(0.3)
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
					#time.sleep(1)
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
			searchdone = 0
			limits()



#Some Code
try:
	Screen.wrapper(title)
except Exception as e:
	print e
	pass
signal.signal(signal.SIGINT, signal_handler)

print
print
Request()
time.sleep(2)
loadvars()
time.sleep(2)
CheckDouble()
time.sleep(2)
print
Fig = Figlet(font='basic')
print Fig.renderText('Loading Emoticon')
print
time.sleep(2)

for use_aliases, group in (
                            (False, emoji.unicode_codes.EMOJI_UNICODE),
                            (True, emoji.unicode_codes.EMOJI_ALIAS_UNICODE)):
                        for name, ucode in group.items():
                            assert name.startswith(':') and name.endswith(':') and len(name) >= 3
                            emj = emoji.emojize(name, use_aliases=use_aliases)
			    print emj,
                            emolist.append(emj)
Fig = Figlet(font='cybermedium')
print
print Fig.renderText('Done')
time.sleep(2)
Fig = Figlet(font='basic')
print Fig.renderText('Calling Flush function')
print
flushtmp()
print
Fig = Figlet(font='basic')
print Fig.renderText('Calling Search function')
print
time.sleep(2)

Minwords = len(Keywords)/20
Maxwords = len(Keywords)/10
Minwords = int(Minwords)
Maxwords = int(Maxwords)
rndwords = randint(Minwords,Maxwords)
if rndwords < 100:
	rndwords = len(Keywords)
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
print
Fig = Figlet(font='cybermedium')
print Fig.renderText("Check Last Menu started")
print
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
	figy = "Searching : %s %i/%i" % (key,tmpcnt,rndwords) 
	Fig = Figlet(font='puffy')
	print Fig.renderText(figy)
	time.sleep(1)
	searchTst(key)
	

print
print
print
print
Fig = Figlet(font='basic')
print Fig.renderText("All Done !")
print
print
time.sleep(1)
print
Fig = Figlet(font='basic')
print Fig.renderText("Calling Retweet function")
print
print
print
print
print
print
print
print
print
time.sleep(1)
allok = 1
Retweet()
print 
print
print
print
print
print
print
#time.sleep(0.3)
print
print
print
Fig = Figlet(font='basic')
print Fig.renderText("Retweet function stopped")
print
print
#time.sleep(0.3)
print 
print
print
print
print
print
print
print
print
Fig = Figlet(font='basic')
print Fig.renderText("Calling Save Search Terms Function")
print
print 
print
print
print
#time.sleep(0.3)
lastmeal(Keywords[:rndwords])
print
if (len(moyscore)) != 0:
	avgscore = sum(moyscore) / float(len(moyscore))
else:
	avgscore = 0
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

print
Fig = Figlet(font='basic')
print Fig.renderText("Calling Saving call function")
print
print
#time.sleep(0.3)
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
#time.sleep(0.3)

