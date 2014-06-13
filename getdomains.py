__author__ = 'panos'
from sys import exit, argv
from termcolor import colored
from socket import gethostbyname, gaierror, socket, error
from os.path import basename
from urllib import urlencode
from httplib2 import ProxyInfo, Http, HttpLib2Error
from httplib2.socks import PROXY_TYPE_SOCKS4
from json import loads
from time import sleep
from re import compile, IGNORECASE
notes = 1

def out(message,level):
	if notes == 0 and level == 2:
		return
	if level == 1:
		prefix = '[-] Fatal: '
		collor = 'red'
	elif level == 2:
		prefix = '[*] Note: '
		collor = 'yellow'
	elif level == 3:
		prefix = '[+] OK: '
		collor = 'green'
	else:
		raise ValueError
	if len(message) == 0:
		raise ValueError
	print colored(prefix+message,collor)
	if level == 1:
		exit()
if __name__ != "__main__":
	out('use this as a standalone script.',1)

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

Usage: python '''+basename(argv[0])+''' domain tor_flag (set 1 for tor use )
'''
	exit()
def change_ip():
	if argv[2] is '1':
		try:
			sock = socket()
			sock.connect(('127.0.0.1',9051))
			sock.send("AUTHENTICATE\r\n")
			if 'OK' in sock.recv(10):
				sock.send("SIGNAL NEWNYM\r\n")
				if 'OK' in sock.recv(10):
					sock.close()
					return True
		except error:
			return False
	else:
		return False
def get_data(domain):
	global tor
	if tor is True:
		opener = Http(proxy_info = ProxyInfo(PROXY_TYPE_SOCKS4, '127.0.0.1', 9050, True))
	else:
		opener = Http()
	data = urlencode({'key':'', 'remoteAddress':domain})
	code, content = opener.request('http://domains.yougetsignal.com/domains.php', 'POST', data, {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
                                                                                             'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
	del opener
	return code, content
def resolve_host(host):
	if argv[2] is '1':
		try:
			sock = socket()
			sock.connect(('127.0.0.1',9051))
			sock.send("AUTHENTICATE\r\n")
			if 'OK' in sock.recv(10):
				sock.send("SETEVENTS ADDRMAP\r\n")
				if 'OK' in sock.recv(10):
					sock.send("RESOLVE %s\r\n" % host)
					while True:
						back = sock.recv(1024)
						if 'ADDRMAP '+host in back:
							if host+' <error>' in back:
								raise gaierror
							reobj = compile(r"ADDRMAP ([^\s]+) ([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})", IGNORECASE)
							result = reobj.findall(back)
							if str(result[0][0]) == str(host):
								sock.close()
								return result[0][1]
		except gaierror:
			raise
		except error:
			return False
	else:
		try:
			return gethostbyname(host)
		except gaierror:
			return None
try:
	argv[2]
except IndexError:
	argv.append(None)

if  argv[2] is '1':
	tor = True
	try:
		code, returndata = Http(proxy_info = ProxyInfo(PROXY_TYPE_SOCKS4, '127.0.0.1', 9050, True)).request('https://check.torproject.org/api/ip')
		if code.status == 200:
			tor_data = loads(returndata)
			if tor_data['IsTor'] is False:
				out('we are not using tor exiting...',1)
			else:
				out('tor check successful...',3)
		else:
			raise HttpLib2Error
	except HttpLib2Error:
		out('error in tor check routine exiting...',1)
else:
	tor = False

domain = str(argv[1])
try:
	ip = resolve_host(domain)
except gaierror:
	out('main domain ip address cannot be resolved exiting...',1)

out('given domain ip obtained: '+str(ip),3)
cond = True
while cond:
	code, content = get_data(domain)
	if code.status != 200:
		out('wrong status code returned probably cloudflare is blocking our requests...',2)
		if change_ip() is True:
			out('we changed ip retrying...',2)
			sleep(2)
		else:
			out('ip change failed exiting...',1)

	if code.status == 200:
		correlated = loads(content)
		if 'fail' in correlated['status'].lower():
			if 'daily reverse' in correlated['message'].lower():
				if change_ip() is False:
					out('daily limit reached try change your ip address or use tor instead...',1)
				else:
					out('daily limit reached we changed ip retrying...',2)
					sleep(2)
			else:
				out('unknown fail message: '+correlated['message'],1)

		if 'success' in correlated['status'].lower():
			cond = False
			for x in correlated['domainArray']:
				try:
					domainip = resolve_host(x[0])
				except gaierror:
					fail = True
					pass
				if 'fail' in locals() and 'www.' not in x[0]:
					try:
						domainip = resolve_host('www.'+x[0])
						prefix = True
						del fail
					except gaierror:
						out('domain '+x[0]+' cannot be resolved.', 2)
						del fail
						continue
				elif 'fail' in locals() and 'www.' in x[0]:
					out('domain '+x[0]+' cannot be resolved.', 2)
					del fail
					continue
				if domainip in ip:
					if 'prefix' in locals():
						out('domain www.' + x[0] + ' found.', 3)
						del domainip
						del prefix
					else:
						out('domain ' + x[0] + ' found.', 3)
						del domainip
				else:
					out('domain '+x[0]+' not bound to target ip.',2)