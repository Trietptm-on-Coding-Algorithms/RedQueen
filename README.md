My personal search bot crawling twitter for infoSec news.

It tries to sort all tweets from worst to best tweet by giving them a score 
depending on their contents , nbr of followers , retweets , favorites , language , media 
, timestamp , emoticon , if already sent or not , if content or user bio contains banned words or is from a banned user ,
Check if there is enough text, check if Tweet is Follow Friday or if too much hashs,
check and act if tweet is from a verifed account or from a friend or follower , check if current tweet contains some part
of tweet already sent to prevent retweeting the same info twice , do not retweet the same user more than 3 times ,
do not retweet if retweet count is not at least 1 (Roll a dice and if 1 give a chance to this tweet ) ...
do not retweet if retweet count id more than 323 , 
do not retweet if older than 2 days (need fresh info),Saves item already searched ,
do not retweet if the user is not followed by at least 400 ppl,
saves items searched which returned no result and removes them from the search list,
provide some statistique about the current session during api resting time,
it does respect the limit of twitter api by saving the total nbr of calls and then
react depending on how many call are left to be send (reset calls every 24 hours), etc ...


Then Sends me a dm when done retweeting all the good stuff in its timeline .


pip install asciimatics
pip install emoji
pip install twython
python 2.7
