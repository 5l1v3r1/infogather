__author__ = 'panos'
from socks import setdefaultproxy, PROXY_TYPE_SOCKS4, socksocket
import socket
from os.path import basename
from urllib import urlencode
from urllib2 import Request, urlopen
from json import loads
from sys import exit, argv
from termcolor import colored
if __name__ != "__main__":
	print colored('[-] Fatal use this as a standalone script.','red')
	exit()
if 	len(argv) < 2:
	print colored('''
....       :MM ..  M...  MM:............
........ M .......M.M....... M ........
......7M.........M...M.........M=......
  ...M... ....  M ....M......... M.....
  .=?.     . . M.  ... M..........Z7....
  N.... .  . .N.   .... D...........$...
 ,,..   .....D, ........,7..........?=.
 M...     ..:. ...........?..........M..
M.... .   ..N.............Z...........M
M ...     .$M....OMMMZ....MD..........M.
. .....   M.M. M ..... M..M.M ........+
  ...   .M..M,8.........7.M..M.........7
 .......M...MM........ . MM . M..  .   7
.......M....MN...........MM....M......+.
M.....M.....MM...........MM... .M ... M.
M ...M......M.M....... .Z M ..  .M    M
 M..M ......M. M ......M..M . ... M. M..
 ,.M .......M....~MMM:    M     . .M:I.
..O:..................    . .   .  .? ..
...++................. .  . .   . O$  .
.... M................ ..   ..  .M..  ..
......~M........... ..   .     M,  .  .
.........M............ .. . .M,..  .  ..
.......... .MM.......... MM... .. ... ..
     ....  .  .  .IZI...  . .  .   ..  .\n''', 'red')
	print '''
Shared domains enumerator script:

Usage: python '''+basename(argv[0])+''' domain tor_flag (set 1 for tor use)
'''
	exit()
if int(argv[2]) == 1:
	setdefaultproxy(PROXY_TYPE_SOCKS4, '127.0.0.1', 9050, True)
	socket.socket = socksocket
domain = str(argv[1])
try:
	ip = socket.gethostbyname(domain)
except socket.gaierror:
	print colored('[-] Fatal the main domain ip address cannot be resolved exiting...','red')
	exit()
print colored('[+] Given domain ip obtained: '+str(ip),'green')
url = 'http://domains.yougetsignal.com/domains.php'
data = urlencode({'remoteAddress': domain,
                  'key&': '',
                  '_=': ''})
headers = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0'}
request = Request(url, data, headers)
content = urlopen(request)
if content.getcode() == 200:
	correlated = loads(content.read())
	if 'Success' in correlated['status']:
		for x in correlated['domainArray']:
			try:
				domainip = socket.gethostbyname(x[0])
			except socket.gaierror:
				fail = True
				pass
			if 'fail' in locals() and 'www.' not in x[0]:
				try:
					domainip = socket.gethostbyname('www.'+x[0])
					prefix = True
					del fail
				except socket.gaierror:
					print colored('[-] Error domain '+x[0]+' cannot be resolved.', 'red')
					del fail
					continue
			elif 'fail' in locals() and 'www.' in x[0]:
				print colored('[-] Error domain '+x[0]+' cannot be resolved.', 'red')
				del fail
				continue
			if domainip in ip:
				if 'prefix' in locals():
					print colored('[+] Domain www.' + x[0] + ' found.', 'green')
					del domainip
					del prefix
				else:
					print colored('[+] Domain ' + x[0] + ' found.', 'green')
					del domainip
	elif 'Daily reverse' in correlated['message']:
		print colored('[-] Daily limit reached try change your ip address or use tor instead...','red')
		exit()
