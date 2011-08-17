#!/usr/bin/env python
from contextlib import closing
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_DOWN, ROUND_UP
from functools import partial
import getpass
import inspect
import json
import locale
import re
import readline
import traceback
import urllib
import urllib2
import urlparse

# Imports for parsing config file
import ConfigParser
from ConfigParser import SafeConfigParser
import string

# Imports for storing secret key
import binascii
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Imports for signing API requests
import base64
import hmac
import hashlib
import time

# Set config file
cfgFile = "goxsh.cfg"

class CfgParse(object):
	def readCfg(self):
		cfg = ConfigParser.SafeConfigParser()
		cfg.read(cfgFile)
		return cfg
	def setCfg(self, section, name, value):
		section = section.decode('string_escape')
		name = name.decode('string_escape')		
		value = str(value).decode('string_escape')
		cfg = ConfigParser.SafeConfigParser()
		cfg.read(cfgFile)
		cfg.set(section, name, value)
		with open (cfgFile, 'wb') as configfile:
			cfg.write(configfile)
		
class NiceText:
	"""A place to keep functions which format the output."""
	@staticmethod
	def colorCode(colorName):
		"""Returns an ANSI color code by name from the config, printing this code to a 
		terminal will change the text color."""
		try:
			to = config.get("ansi", config.get("colors", colorName)).decode('string_escape')
			return to
		except ConfigParser.Error:
		# In case no color is defined in config/no config file given/found set color to default
			to = "\033[0;0m"
			return to

	@staticmethod
	def resetCode():
		"""Returns the ANSI reset attribute code into a string, printing this to a terminal
		will reset all color options."""
		try:
			creset = config.get("ansi", "reset").decode('string_escape')
			return creset
		except ConfigParser.Error:
		# In case reset is not defined in config/no config given/found use default reset code
			creset = "\033[0;0m"
			return creset

	@staticmethod
	def colorText(text, colorName):
		"""Returns a string containing colored text which can be output to the console."""
		return '{color}{text}{reset}'.format(color=NiceText.colorCode(colorName),
		                                     text =text,
		                                     reset=NiceText.resetCode())

class MtGoxError(Exception):
	pass

class NoCredentialsError(Exception):
	pass

class LoginError(Exception):
	pass

class MtGox(object):
	def __init__(self, user_agent):
		self.unset_credentials()
		self.__url_parts = urlparse.urlsplit("https://mtgox.com/api/0/")
		self.__headers = {
			"User-Agent": user_agent
		}
		
	def get_username(self):
		return self.__credentials[0] if self.have_credentials() else None
	
	def have_credentials(self):
		return self.__credentials is not None
		
	def set_credentials(self, username, key, secret):
		if not username:
			raise ValueError(u"Empty username.")
		if not key:
			raise ValueError(u"Empty key.")
		if not secret:
			raise ValueError(u"Empty secret.")
		self.__credentials = (username, key, secret)
		
	def unset_credentials(self):
		self.__credentials = None
		
	def activate(self, devicename, activationkey, appkey):
		return self.__get_json("activate.php", params = {
			u"name": devicename,
			u"key": activationkey,
			u"app": appkey
		}, auth = False)
		
	def buy(self, amount, price):
		return self.__get_json("buyBTC.php", params = {
			u"amount": amount,
			u"price": price
		})
	
	def cancel_order(self, kind, oid):
		return self.__get_json("cancelOrder.php", params = {
			u"oid": oid,
			u"type": kind
		})[u"orders"]
	
	def get_balance(self):
		usd = self.__get_json("info.php")[u"Wallets"][u"USD"][u"Balance"][u"value"]
		btc = self.__get_json("info.php")[u"Wallets"][u"BTC"][u"Balance"][u"value"]
		balance = {u"usds":usd, u"btcs":btc}
		return balance
	
	def get_orders(self):
		return self.__get_json("getOrders.php")[u"orders"]
	
	def get_ticker(self):
		return self.__get_json("data/ticker.php", auth = False)[u"ticker"]
	
	def sell(self, amount, price):
		return self.__get_json("sellBTC.php", params = {
			u"amount": amount,
			u"price": price
		})
	
	def withdraw(self, address, amount):
		return self.__get_json("withdraw.php", params = {
			u"group1": u"BTC",
			u"btca": address,
			u"amount": amount
		})
		
	def get_commission(self):
		return self.__get_json("info.php")[u"Trade_Fee"]
		
	def get_depth(self):
		return self.__get_json("data/getDepth.php", auth = False)
		
	def __get_json(self, rel_path, params = {}, auth = True):
		if auth and not self.have_credentials():
			raise NoCredentialsError()
		params = params.items()
		if auth:
			# Access counter
			global counter
			# Use time.time() to get a steadily increasing nonce
			# *1000+counter to make more than one request per second possible
			params += [
				(u"nonce", int(time.time())*1000+counter)
			]
			# Increase counter by 1
			counter += 1
			# Encode params within POST
			post_data = urllib.urlencode(params) if len(params) > 0 else None
			key = self.__credentials[1]
			secret = self.__credentials[2]
			# Sign request by base64-encoding the not base64-encoded secert and the hmac-sha512-hashed post_data
			sign = None
			try:
				sign = base64.b64encode(str(hmac.new(base64.b64decode(secret), post_data, hashlib.sha512).digest()))
			except TypeError:
				print u"Could not sign request. Please log in again."
				self.unset_credentials()
			# Create header for auth-requiring operations
			user_agent = "goxsh"
			self.__headers = {
				"User-Agent": user_agent,
				"Rest-Key": key,
				"Rest-Sign": sign
			}
		else:
			post_data = urllib.urlencode(params) if len(params) > 0 else None
			
		url = urlparse.urlunsplit((
			self.__url_parts.scheme,
			self.__url_parts.netloc,
			self.__url_parts.path + rel_path,
			self.__url_parts.query,
			self.__url_parts.fragment
		))			
		req = urllib2.Request(url, post_data, self.__headers)
		with closing(urllib2.urlopen(req, post_data)) as res:
			data = json.load(res)
		if u"error" in data:
			if data[u"error"] == u"Not logged in.":
				raise LoginError()
			else:
				raise MtGoxError(data[u"error"])
		else:
			return data

class TokenizationError(Exception):
	pass

class CommandError(Exception):
	pass

class ArityError(Exception):
	pass

class GoxSh(object):
	def __init__(self, mtgox, encoding):
		self.__mtgox = mtgox
		self.__encoding = encoding
		readline.parse_and_bind("tab: complete")
		readline.set_completer(self.__complete)
		self.__btc_precision = Decimal("0.00000001")
		self.__usd_precision = Decimal("0.00001")
		self.__usd_re = re.compile(r"^\$(\d*\.?\d+)$")
		collapse_escapes = partial(re.compile(r"\\(.)", re.UNICODE).sub, "\\g<1>")
		self.__token_types = (
			( # naked (unquoted)
				re.compile(r"(?:\\[\s\\\"';#]|[^\s\\\"';#])+", re.UNICODE),
				collapse_escapes
			),
			( # double-quoted
				re.compile(r"\"(?:\\[\\\"]|[^\\])*?\"", re.UNICODE),
				lambda matched: collapse_escapes(matched[1:-1])
			),
			( # single-quoted
				re.compile(r"'(?:\\[\\']|[^\\])*?'", re.UNICODE),
				lambda matched: collapse_escapes(matched[1:-1])
			),
			( # whitespace and comments
				re.compile(r"(?:\s|#.*)+", re.UNICODE),
				lambda matched: None
			),
			( # semicolon
				re.compile(r";", re.UNICODE),
				lambda matched: matched
			)
		)
	
	def __tokenize_command(self, line):
		remaining = line
		while remaining:
			found = False
			for (pattern, sub) in self.__token_types:
				match = pattern.match(remaining)
				if match:
					raw_token = match.group(0)
					assert len(raw_token) > 0, u"empty token"
					token = sub(raw_token)
					if token is not None:
						yield token
					remaining = remaining[len(raw_token):]
					found = True
					break
			if not found:
				message = "\n".join(
					u"  {0}^".format(u" " * (len(line) - len(remaining)),
					u"Syntax error."))
				raise TokenizationError(message)
	
	def __parse_tokens(self, tokens):
		cmd = None
		args = []
		for token in tokens:				
			if token == u";":
				if cmd:
					yield (cmd, args)
					cmd = None
					args = []
			elif not cmd:
				cmd = token
			else:
				args.append(token)
		if cmd:
			yield (cmd, args)
	
	def prompt(self):
		procs = []
		args = []
		try:
			raw_line = None
			try:
				text = u"{userName}{prompt} ".format(userName=NiceText.colorText(self.__mtgox.get_username() or u'', "shell_user"),
				                                     prompt  =NiceText.colorText(u'$', "shell_self"))

				line = raw_input(text).decode(self.__encoding)
			except EOFError, e:
				print u"exit"
				self.__cmd_exit__()
			commands = self.__parse_tokens(self.__tokenize_command(line))
			for (cmd, args) in commands:
				try:
					proc = self.__get_cmd_proc(cmd, self.__unknown(cmd))
					(min_arity, max_arity) = self.__get_proc_arity(proc)
					arg_count = len(args)
					if min_arity <= arg_count and (max_arity == None or arg_count <= max_arity):
						proc(*args)
					else:
						if min_arity == max_arity:
							arity_text = unicode(min_arity)
						elif max_arity == None:
							arity_text = u"{0}+".format(min_arity)
						else:
							arity_text = u"{min}-{max}".format(min=min_arity, max=max_arity)
						arg_text = u"argument" + (u"" if arity_text == u"1" else u"s")
						raise ArityError(u"Expected %s %s, got %s." % (arity_text, arg_text, arg_count))
				except MtGoxError, e:
					print u"Mt. Gox error: {0}".format(e)
				except CommandError, e:
					print e
				except ArityError, e:
					print e
				except NoCredentialsError:
					print u"No login credentials entered. Use the login command first."
				except LoginError:
					print u"Mt. Gox rejected the login credentials. Maybe you made a typo?"
		except EOFError, e:
			raise e
		except TokenizationError, e:
			print e
		except KeyboardInterrupt:
			print
		except Exception, e:
			traceback.print_exc()
	
	def __get_cmd_proc(self, cmd, default = None):
		return getattr(self, "__cmd_{0}__".format(cmd), default)
	
	def __cmd_name(self, attr):
		match = re.match(r"^__cmd_(.+)__$", attr)
		return match.group(1) if match != None else None
	
	def __get_cmds(self, prefix = ""):
		return sorted(
			filter(
				lambda cmd: cmd != None and cmd.startswith(prefix),
				(self.__cmd_name(attr) for attr in dir(self))
			)
		)
	
	def __print_cmd_info(self, cmd):
		proc = self.__get_cmd_proc(cmd)
		if proc:
			print cmd,
			argspec = inspect.getargspec(proc)
			args = argspec.args[1:]
			if argspec.defaults:
				i = -1
				for default in reversed(argspec.defaults):
					args[i] = (args[i], default)
					i -= 1
			for arg in args:
				if not isinstance(arg, tuple):
					print arg,
				elif len(arg) == 2:
					print u"[{0}={1}]".format(*arg),
				else:
					print u"[{0}]".format(arg[0]),
			if argspec.varargs:
				print u"[...]",
			print
			doc = proc.__doc__ or u"--"
			for line in doc.splitlines():
				print "	" + line
		else:
			self.__unknown(cmd)
	
	def __get_proc_arity(self, proc):
		argspec = inspect.getargspec(proc)
		maximum = len(argspec.args[1:])
		minimum = maximum - (len(argspec.defaults) if argspec.defaults != None else 0)
		if argspec.varargs:
			maximum = None
		return (minimum, maximum)
	
	def __complete(self, text, state):
		cmds = self.__get_cmds(text)
		try:
			return self.__get_cmds(text)[state] + (" " if len(cmds) == 1 else "")
		except IndexError:
			return None
	
	def __exchange(self, proc, amount, price):
		match = self.__usd_re.match(amount)
		if match:
			usd_amount = Decimal(match.group(1))
			btc_amount = str((usd_amount / Decimal(price)).quantize(self.__btc_precision))
		else:
			btc_amount = amount
		ex_result = proc(btc_amount, price)
		statuses = filter(None, ex_result[u"status"].split(u"<br>"))
		for status in statuses:
			print status
		if u"orders" in ex_result:
			for order in ex_result[u"orders"]:
				self.__print_order(order)
	
	def __print_balance(self, balance):
		print u"{btcSymbol}\t{btcBalance}".format(btcSymbol =NiceText.colorText("BTC:",           "balance_btcsymbol"),
		                                          btcBalance=NiceText.colorText(balance[u"btcs"], "balance_btcamount"))
		print u"{usdSymbol}\t{usdBalance}".format(usdSymbol =NiceText.colorText("USD:",           "balance_usdsymbol"),
		                                          usdBalance=NiceText.colorText(balance[u"usds"], "balance_usdamount"))
	
	def __print_order(self, order):
		kind = {1: u"sell", 2: u"buy"}[order[u"type"]]
		timestamp = datetime.fromtimestamp(int(order[u"date"])).strftime("%Y-%m-%d %H:%M:%S")
		properties = []
		# Append status to orders
		properties.append(order[u"real_status"])
		if kind == u"sell":
			print "{lb}{timeStamp}{rb} {kind}\t{oid}\t{sellAmnt}{btc} {at} {sellPrice}{usd}{props}".format(
				lb       =NiceText.colorText("[",              "orders_selltimebrackets"),
				timeStamp=NiceText.colorText(timestamp,        "orders_selltime"),
				rb       =NiceText.colorText("]",              "orders_selltimebrackets"),
				kind     =NiceText.colorText(kind,             "orders_sellkind"),
				oid      =NiceText.colorText(order[u'oid'],    "orders_selloid"),
				sellAmnt =NiceText.colorText(order[u'amount'], "orders_sellamount"),
				btc      =NiceText.colorText("BTC",            "orders_sellcurrysymbol"),
				at       =NiceText.colorText("@",              "orders_sellATsymbol"),
				sellPrice=NiceText.colorText(order[u"price"],  "orders_sellprice"),
				usd      =NiceText.colorText("USD",            "orders_sellcurrysymbol"),
				props    =" (" + ",".join(properties) + ")" if properties else "")
		elif kind == u"buy":
			print "{lb}{timeStamp}{rb} {kind}\t{oid}\t{buyAmnt}{btc} {at} {buyPrice}{usd}{props}".format(
				lb       =NiceText.colorText("[",              "orders_buytimebrackets"),
				timeStamp=NiceText.colorText(timestamp,        "orders_buytime"), 
				rb       =NiceText.colorText("]",              "orders_buytimebrackets"), 
				kind     =NiceText.colorText(kind,             "orders_buykind"), 
				oid      =NiceText.colorText(order[u"oid"],    "orders_buyoid"), 
				buyAmnt  =NiceText.colorText(order[u"amount"], "orders_buyamount"), 
				btc      =NiceText.colorText("BTC",            "orders_buycurrsymbol"), 
				at       =NiceText.colorText("@",              "orders_buyATsymbol"), 
				buyPrice =NiceText.colorText(order[u"price"],  "orders_buyprice"), 
				usd      =NiceText.colorText("USD",            "orders_buycurrsymbol"), 
				props    =" (" + ", ".join(properties) + ")" if properties else "")
		
	def __unknown(self, cmd):
		def __unknown_1(*args):
			print u"{0}: Unknown command.".format(cmd)
		return __unknown_1
	
	def __cmd_balance__(self):
		u"Display account balance."
		self.__print_balance(self.__mtgox.get_balance())
	
	def __cmd_buy__(self, amount, price):
		u"Buy bitcoins.\nPrefix the amount with a '$' to spend that many USD and calculate BTC amount\nautomatically."
		self.__exchange(self.__mtgox.buy, amount, price)
	
	def __cmd_cancel__(self, kind, order_id):
		u"Cancel the order with the specified kind (buy or sell) and order ID."
		try:
			num_kind = {u"sell": 1, u"buy": 2}[kind]
			orders = self.__mtgox.cancel_order(num_kind, order_id)
			print u"Canceled {0} {1}.".format(kind, order_id)
			if orders:
				for order in orders:
					self.__print_order(order)
			else:
				print u"No remaining orders."
		except KeyError:
			raise CommandError(u"{0}: Invalid order kind.".format(kind))
	
	def __cmd_exit__(self):
		u"Exit goxsh."
		raise EOFError()
	
	def __cmd_help__(self, command = None):
		u"Show help for the specified command or list all commands if none is given."
		if not command:
			cmds = self.__get_cmds()
		else:
			cmds = [command]
		for cmd in cmds:
			self.__print_cmd_info(cmd)
	
	def __cmd_login__(self):
		u"Set login credentials."
		try:
			config = cfgp.readCfg()
			username = config.get('userauth', 'username').decode('string_escape')
			secret = config.get('userauth', 'secret').decode('string_escape')
			length = config.get('userauth', 'length').decode('string_escape')
			key = config.get('userauth', 'key').decode('string_escape')
			perror = False
		except ConfigParser.Error:
			perror = True
			print u"Some user credentials are missing. Check configuration."
		if not perror:
			if all((username, secret, length, key)):
				password = u""
				# Providing password to decrypt secret
				while not password:
					password = getpass.getpass("Password: ").decode('string_escape')
				hash = SHA256.new()
				# Hash password
				hash.update(password)
				# base64-encode password
				password = binascii.b2a_base64(hash.digest())
				# Truncating hash to get a valid length
				password = password[0:32]
				# Set password for decryption
				aes = AES.new(password, AES.MODE_ECB)
				secret = binascii.a2b_base64(secret)
				secret = aes.decrypt(secret)
				# Truncate leading zeros
				length = int(length)
				length = 128-length
				length = str(length)
				secret = re.sub(r"\b0{"+length+"}","",secret)
				self.__mtgox.set_credentials(username, key, secret)
			else:
				print u"Some user credentials are missing. Check configuration."
	
	def __cmd_logout__(self):
		u"Unset login credentials."
		if self.__mtgox.have_credentials():
			self.__mtgox.unset_credentials()
		else:
			print u"Not logged in."
	
	def __cmd_orders__(self, kind = None):
		u"List open orders.\nSpecifying a kind (buy or sell) will list only orders of that kind."
		try:
			num_kind = {None: None, u"sell": 1, u"buy": 2}[kind]
			orders = self.__mtgox.get_orders()
			if orders:
				for order in orders:
					if num_kind in (None, order[u"type"]):
						self.__print_order(order)
			else:
				print u"No orders."
		except KeyError:
			raise CommandError(u"{0}: Invalid order kind.".format(kind))
	
	def __cmd_profit__(self, price):
		u"Calculate profitable short/long prices for a given initial price, taking\ninto account Mt. Gox's commission fee."
		try:
			# Get Mt. Gox trading fee (in %) and devide it by 100 to get it in decimal
			self.__mtgox_commission = Decimal(str(self.__mtgox.get_commission()))/100
			dec_price = Decimal(price)
			if dec_price < 0:
				raise CommandError(u"{0}: Invalid price.".format(price))
			min_profitable_ratio = (1 - self.__mtgox_commission)**(-2)
			short_value = (dec_price / min_profitable_ratio).quantize(self.__usd_precision, ROUND_DOWN)
			long_value  = (dec_price * min_profitable_ratio).quantize(self.__usd_precision, ROUND_UP)
			print u"{short}\t{shortSign} {value}".format(
				short    =NiceText.colorText("Short:",    "profit_shorttext"),
				shortSign=NiceText.colorText("<",         "profit_shortsign"),
				value    =NiceText.colorText(short_value, "profit_shortvalue"))
			print u"{long}\t{longSign} {value}".format(
				long     =NiceText.colorText("Long:",     "profit_longtext"),
				longSign =NiceText.colorText(">",         "profit_longsign"),
				value    =NiceText.colorText(long_value,  "profit_longvalue"))

		except InvalidOperation:
			raise CommandError(u"{0}: Invalid price.".format(price))
	
	def __cmd_sell__(self, amount, price):
		u"Sell bitcoins.\nPrefix the amount with a '$' to receive that many USD and calculate BTC\namount automatically."
		self.__exchange(self.__mtgox.sell, amount, price)

	def __cmd_ticker__(self):
		u"Display ticker."
		ticker = self.__mtgox.get_ticker()
		print u"Last:\t{0}".format(NiceText.colorText(ticker[u"last"], "ticker_last"))
		print u"Buy:\t{0}".format(NiceText.colorText(ticker[u"buy"], "ticker_buy"))
		print u"Sell:\t{0}".format(NiceText.colorText(ticker[u"sell"], "ticker_sell"))
		print u"High:\t{0}".format(NiceText.colorText(ticker[u"high"], "ticker_high"))
		print u"Low:\t{0}".format(NiceText.colorText(ticker[u"low"], "ticker_low"))
		print u"Volume:\t{0}".format(NiceText.colorText(ticker[u"vol"], "ticker_vol"))

	def __cmd_withdraw__(self, address, amount):
		u"Withdraw bitcoins."
		withdraw_info = self.__mtgox.withdraw(address, amount)
		print withdraw_info[u"status"]
		print u"Updated balance:"
		# replaced self.__print_balance(withdraw_info) by:
		self.__print_balance(self.__mtgox.get_balance())
		
	def __cmd_set__(self, section, name, value):
		u"Set configuration values."
		cfgp.setCfg(section, name, value)
		
	def __cmd_activate__(self, activationkey):
		u"Activate goxsh."
		secret = None
		password = None
		# Get app auth info
		config = cfgp.readCfg()
		try:
			# Get devicename
			devicename = config.get('appauth', 'devicename').decode('string_escape')
		except ConfigParser.Error:
			# If key "devicename" doesn't exist assign a random name+_goxsh-suffix
			devicename = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(10))
			devicename += "_goxsh"
		# If key "devicename" is given but value is empty assign a randome name+_goxsh-suffix
		if (len(devicename) <= 0):
			devicename = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(10))
			devicename += "_goxsh"
		try:
			# Get appkey
			appkey = config.get('appauth', 'appkey').decode('string_escape')
		except ConfigParser.Error:
			# If key "appkey" doesn't exist in config assign Optonic's goxsh appkey
			appkey = "d96f4e85-990a-4115-81ef-0c8baedf6895"
		# If key "appkey" is given but value is empty assign Optonic's goxsh appkey
		if (len(appkey) <= 0):
			appkey = "d96f4e85-990a-4115-81ef-0c8baedf6895"
		# Obtain API-key and secret		
		activate = self.__mtgox.activate(devicename, activationkey, appkey)
		# Get user's key
		key = activate[u"Rest-Key"].decode('string_escape')
		# Get user's secret
		secret = activate[u"Secret"].decode('string_escape')
		# Get user's rights
		rights = activate[u"Rights"]
		# rights = rights.decode('string_escape')
		# Get secret length
		length = len(secret)
		# Write user's key, secret length and rights to config
		cfgp.setCfg("userauth", "key", key)
		cfgp.setCfg("userauth", "length", length)
		cfgp.setCfg("userauth", "rights", rights)
		print u"Enter password for secret encryption."
		# Providing password to encrypt secret
		while not password:
			pass1 = getpass.getpass("Password: ").decode('string_escape')
			pass2 = getpass.getpass("Repeat: ").decode('string_escape')
			if pass1 == pass2:
				password = pass1
			else:
				print u"Passwords don't match, try again."

		hash = SHA256.new()
		# Hash password
		hash.update(password)
		# base64-encode password
		password = binascii.b2a_base64(hash.digest())
		# Truncating hash to get a valid length
		password = password[0:32]
		# Set password to encrypt secret with
		aes = AES.new(password, AES.MODE_ECB)
		# Fill secret with leading zeros to get a valid length
		secret = str.zfill(secret, 128)
		# AES-encrypt secret
		secret = aes.encrypt(secret)
		# base64-encode secret
		secret = binascii.b2a_base64(secret).decode('string_escape')
		# Writing encrypted secret to config file
		cfgp.setCfg("userauth", "secret", secret)
		config = cfgp.readCfg()			

	def __cmd_reload__(self):
		u"Reload config file."
		global config
		config = cfgp.readCfg()
	
	def __cmd_bids__(self, steps=0, price=0):
		u"Show orderbook (market depth) - bids side.\nsteps:\tNumber of rows to be printed.\n\tIf set to 0 all bids of orderbook are printed.\nprice:\tSpecify price to start with. If not given/set to 0\n\tit starts with first bid."
		try:
			try:
				steps = int(steps)
			except:
				print u"Argument \"steps\" requires a positive value (integer)."
				raise Exception
			try:
				price = Decimal(price)
			except:
				print u"Argument \"price\" requires a positive value (decimal)."
				raise Exception
			if (price < 0):
				print u"Argument \"price\" requires a positive value (decimal)."
			# Show depth in x steps with last trade as starting point
			elif (steps == 0) and (price == 0):
				# Get current bids of order book (aka market depth) as a list
				bids = list(self.__mtgox.get_depth()[u"bids"])
				# Reverse order of bids for cumulation
				bids.reverse()
				# Create empty array cumulatedBids[]
				cumulatedBids = []
				# Set cumulateBids to 0
				cumulateBids = 0
				for i in bids:
					cumulateBids += i[1]
					cumulatedBids.append(cumulateBids)
				# Re-reverse order of bids and reverse order of cumulatedBids
				bids.reverse()
				cumulatedBids.reverse()
				print u""
				print u"Type | Price      | Amount         | Sum"
				print u"==================================================="
				# icb -> Iterator for cumulatedBids[]
				icb = 0
				for i in bids:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					formatCumulate = str(format(cumulatedBids[icb], '.8f')).rjust(14, ' ')
					print u"Bid  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_bid"), formatAmount, formatCumulate)
					icb += 1
				print u"---------------------------------------------------"
			elif (steps > 0) and (price == 0):
				# Get current bids of order book (aka market depth) as a list
				bids = list(self.__mtgox.get_depth()[u"bids"])
				# Reverse order of bids for cumulation
				bids.reverse()
				# Create empty array cumulatedBids[]
				cumulatedBids = []
				# Set cumulateBids to 0
				cumulateBids = 0
				# Get x steps of bids only
				bids = bids[:steps]
				for i in bids:
					cumulateBids += i[1]
					cumulatedBids.append(cumulateBids)
				# Re-reverse order of bids and reverse order of cumulatedBids
				bids.reverse()
				cumulatedBids.reverse()
				print u""
				print u"Type | Price      | Amount         | Sum"
				print u"==================================================="
				# icb -> Iterator for cumulatedBids[]
				icb = 0
				for i in bids:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					formatCumulate = str(format(cumulatedBids[icb], '.8f')).rjust(14, ' ')
					print u"Bid  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_bid"), formatAmount, formatCumulate)
					icb += 1
				print u"---------------------------------------------------"
			elif (steps == 0) and (price > 0):
				# Get current bids of order book (aka market depth) as a list
				bids = list(self.__mtgox.get_depth()[u"bids"])
				# Reverse order of bids for cumulation
				bids.reverse()
				# Create empty array cumulatedBids[]
				cumulatedBids = []
				# Set cumulateBids to 0
				cumulateBids = 0
				for i in bids:
					cumulateBids += i[1]
					cumulatedBids.append(cumulateBids)
				# Re-reverse order of bids and reverse order of cumulatedBids
				bids.reverse()
				cumulatedBids.reverse()
				print u""
				print u"Type | Price      | Amount         | Sum"
				print u"==================================================="
				# icb -> Iterator for cumulatedBids[]
				icb = 0
				for i in bids:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					formatCumulate = str(format(cumulatedBids[icb], '.8f')).rjust(14, ' ')
					keyvalue = Decimal(str(i[0]))
					if (keyvalue <= price):
						if (keyvalue < price):
							print u"Bid  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_bid"), formatAmount, formatCumulate)
							icb += 1
						elif (keyvalue == price):
							print u"---------------------------------------------------"	
							print u"Bid  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_bid"), formatAmount, formatCumulate)
							break
					else:
						formatPrice = str(format(price, '.5f')).rjust(10, ' ')
						print u"---------------------------------------------------"	
						print u"n/a  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_no"), NiceText.colorText("No amount at given price", "depth_no"))
						break
				print u"---------------------------------------------------"
			elif (steps > 0) and (price > 0):
			 print u"Not yet implemented. Tell me if you really need this :-)"
		except:
			print u"Execution aborted."
			
	def __cmd_asks__(self, steps=0, price=0):
		u"Show orderbook (market depth) - asks side.\nsteps:\tNumber of rows to be printed.\n\tIf set to 0 all asks of orderbook are printed.\nprice:\tSpecify price to start with. If not given/set to 0\n\tit starts with first ask."
		try:
			try:
				steps = int(steps)
			except:
				print u"Argument \"steps\" requires a positive value (integer)."
				raise Exception
			try:
				price = Decimal(price)
			except:
				print u"Argument \"price\" requires a positive value (decimal)."
				raise Exception
			if (price < 0):
				print u"Argument \"price\" requires a positive value (decimal)."
			# Show depth in x steps with last trade as starting point
			elif (steps == 0) and (price == 0):
				# Get current asks of order book (aka market depth) as a list
				asks = list(self.__mtgox.get_depth()[u"asks"])
				# Create empty array cumulatedasks[]
				cumulatedAsks = []
				# Set cumulateasks to 0
				cumulateAsks = 0
				for i in asks:
					cumulateAsks += i[1]
					cumulatedAsks.append(cumulateAsks)
				print u""
				print u"Type | Price      | Amount         | Sum"
				print u"==================================================="
				# icb -> Iterator for cumulatedasks[]
				icb = 0
				for i in asks:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					formatCumulate = str(format(cumulatedAsks[icb], '.8f')).rjust(14, ' ')
					print u"Ask  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_ask"), formatAmount, formatCumulate)
					icb += 1
				print u"---------------------------------------------------"
			elif (steps > 0) and (price == 0):
				# Get current asks of order book (aka market depth) as a list
				asks = list(self.__mtgox.get_depth()[u"asks"])
				# Create empty array cumulatedasks[]
				cumulatedAsks = []
				# Set cumulateasks to 0
				cumulateAsks = 0
				# Get x steps of asks only
				asks = asks[:steps]
				for i in asks:
					cumulateAsks += i[1]
					cumulatedAsks.append(cumulateAsks)
				print u""
				print u"Type | Price      | Amount         | Sum"
				print u"==================================================="
				# icb -> Iterator for cumulatedasks[]
				icb = 0
				for i in asks:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					formatCumulate = str(format(cumulatedAsks[icb], '.8f')).rjust(14, ' ')
					print u"Ask  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_ask"), formatAmount, formatCumulate)
					icb += 1
				print u"---------------------------------------------------"
			elif (steps == 0) and (price > 0):
				# Get current asks of order book (aka market depth) as a list
				asks = list(self.__mtgox.get_depth()[u"asks"])
				# Create empty array cumulatedasks[]
				cumulatedAsks = []
				# Set cumulateasks to 0
				cumulateAsks = 0
				for i in asks:
					cumulateAsks += i[1]
					cumulatedAsks.append(cumulateAsks)
				print u""
				print u"Type | Price      | Amount         | Sum"
				print u"==================================================="
				# icb -> Iterator for cumulatedasks[]
				icb = 0
				for i in asks:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					formatCumulate = str(format(cumulatedAsks[icb], '.8f')).rjust(14, ' ')
					keyvalue = Decimal(str(i[0]))
					if (keyvalue <= price):
						if (keyvalue < price):
							print u"Ask  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_ask"), formatAmount, formatCumulate)
							icb += 1
						elif (keyvalue == price):
							print u"---------------------------------------------------"	
							print u"Ask  | {0} | {1} | {2}".format(NiceText.colorText(formatPrice, "depth_ask"), formatAmount, formatCumulate)
							break
					else:
						formatPrice = str(format(price, '.5f')).rjust(10, ' ')
						print u"---------------------------------------------------"	
						print u"n/a  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_no"), NiceText.colorText("No amount at given price", "depth_no"))
						break
				print u"---------------------------------------------------"
			elif (steps > 0) and (price > 0):
			 print u"Not yet implemented. Tell me if you really need this :-)"
		#except:
		#	print u"Execution aborted."
		except Exception, e:
			print e
			
	def __cmd_depth__(self, steps, price=0, cumulate=0):
		u"Show orderbook (market depth).\nsteps:\t\tNumber of rows to be printed before\n\t\tand after last trade/given price.\nprice:\t\tSpecify price (if not given last trade is assumed).\ncumulate:\tSet to 1 to cumulate amount.\n\t\tWorks only if price is set to 0 (e.g. depth 5 0 1)."
		try:
			try:
				steps = int(steps)
			except:
				print u"Argument \"steps\" requires a positive value (integer)."
				raise Exception
			try:
				price = Decimal(price)
			except:
				print u"Argument \"price\" requires a positive value (decimal)."
				raise Exception
			try:
				cumulate = int(cumulate)
			except:
				print u"Allowed values for argument \"cumulate\" are 0 and 1 (integer)."
				raise Exception
			if (price < 0):
				print u"Argument \"price\" requires a positive value (decimal)."
			elif (cumulate != 0) and (cumulate != 1):
				print u"Allowed values for argument \"cumulate\" are 0 and 1."
			# Show depth in x steps with last trade as starting point
			elif (steps) and (price == 0) and (cumulate == 0):
				# Get current bids of order book (aka market depth) as a list
				bids = list(self.__mtgox.get_depth()[u"bids"])
				# Get current asks of order book (aka market depth) as a list
				asks = list(self.__mtgox.get_depth()[u"asks"])
				# Get x steps of bids only (reversed)
				bids = bids[-steps:]
				# Get x steps of asks only
				asks = asks[:steps]
				print u""
				print u"Type | Price      | Amount"
				print u"==================================================="
				for i in bids:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					print u"Bid  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_bid"), formatAmount)
				print u"---------------------------------------------------"
				formatLast = str(format(self.__mtgox.get_ticker()[u"last"], '.5f')).rjust(10, ' ')
				print u"Last | {0} |".format(NiceText.colorText(formatLast, "depth_last"))
				print u"---------------------------------------------------"
				for i in asks:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatAmount = str(format(i[1], '.8f')).rjust(14, ' ')
					print u"Ask  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_ask"), formatAmount)
				print u"---------------------------------------------------"
			# Show depth in x steps with given price as starting point	
			elif (steps) and (price > 0) and (cumulate == 0):
				# Get current bids of order book (aka market depth) as a dict
				bids = dict(self.__mtgox.get_depth()[u"bids"])
				# Get current asks of order book (aka market depth) as a dict
				asks = dict(self.__mtgox.get_depth()[u"asks"])
				# Merge bids and asks together (both, seperated and non-seperated dicts are needed)
				depth = bids
				depth.update(asks)
				# Just some iterators, starting at 1
				ia = 1
				ib = 1
				print u""
				print u"Type | Price      | Amount"
				print u"==================================================="			
				for key in sorted(depth.iterkeys(), reverse=True):
					# key -> Price
					# depth[key] -> Amount
					keyvalue = Decimal(str(key))
					if (keyvalue < price) and (ia <= steps):
						if key in bids:
							formatPrice = str(format(key, '.5f')).rjust(10, ' ')
							formatAmount = str(format(depth[key], '.8f')).rjust(14, ' ')
							print u"Bid  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_bid"), NiceText.colorText(formatAmount, "depth_bid"))
						elif key in asks:
							formatPrice = str(format(key, '.5f')).rjust(10, ' ')
							formatAmount = str(format(depth[key], '.8f')).rjust(14, ' ')
							print u"Ask  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_ask"), NiceText.colorText(formatAmount, "depth_ask"))
						ia += 1
				print u"---------------------------------------------------"					
				if (price in depth):
					if price in bids:
						formatPrice = str(format(price, '.5f')).rjust(10, ' ')
						formatAmount = str(format(depth[price], '.8f')).rjust(14, ' ')
						print u"Bid  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_bid"), NiceText.colorText(formatAmount, "depth_bid"))
					elif price in asks:
						formatPrice = str(format(price, '.5f')).rjust(10, ' ')
						formatAmount = str(format(depth[price], '.8f')).rjust(14, ' ')
						print u"Ask  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_ask"), NiceText.colorText(formatAmount, "depth_ask"))
				else:
					print u"n/a  | {0}\t| {1}".format(NiceText.colorText(price, "depth_no"), NiceText.colorText("No amount at given price", "depth_no"))
				print u"---------------------------------------------------"	
				for key in sorted(depth.iterkeys()):
					keyvalue = Decimal(str(key))
					if (keyvalue > price) and (ib <= steps):
						if key in bids:
							formatPrice = str(format(key, '.5f')).rjust(10, ' ')
							formatAmount = str(format(depth[key], '.8f')).rjust(14, ' ')
							print u"Bid  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_bid"), NiceText.colorText(formatAmount, "depth_bid"))
						elif key in asks:
							formatPrice = str(format(key, '.5f')).rjust(10, ' ')
							formatAmount = str(format(depth[key], '.8f')).rjust(14, ' ')
							print u"Ask  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_ask"), NiceText.colorText(formatAmount, "depth_ask"))
						ib += 1
				print u"---------------------------------------------------"	
			# Show depth in x steps with last trade as starting point and cumulate amount
			elif (steps) and (price == 0) and (cumulate == 1):
				# Get current bids of order book (aka market depth) as a list
				bids = list(self.__mtgox.get_depth()[u"bids"])
				# Get current asks of order book (aka market depth) as a list
				asks = list(self.__mtgox.get_depth()[u"asks"])
				# Get x steps of bids only (reversed)
				bids = bids[-steps:]
				# Reverse order of bids for cumulation
				bids.reverse()
				# Create empty array cumulatedBids[]
				cumulatedBids = []
				# Set cumulateBids to 0
				cumulateBids = 0
				for i in bids:
					cumulateBids += i[1]
					cumulatedBids.append(cumulateBids)
				# Re-reverse order of bids and reverse order of cumulatedBids
				bids.reverse()
				cumulatedBids.reverse()
				# Get x steps of asks only
				asks = asks[:steps]
				print u""
				print u"Type | Price      | Amount (cumulated)"
				print u"==================================================="
				# icb -> Iterator for cumulatedBids[]
				icb = 0
				for i in bids:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					formatCumulate = str(format(cumulatedBids[icb], '.8f')).rjust(14, ' ')
					print u"Bid  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_bid"), formatCumulate)
					icb += 1
				print u"---------------------------------------------------"
				formatLast = str(format(self.__mtgox.get_ticker()[u"last"], '.5f')).rjust(10, ' ')
				print u"Last | {0} |".format(NiceText.colorText(formatLast, "depth_last"))
				print u"---------------------------------------------------"
				cumulateAsks = 0
				for i in asks:
					# i[0] -> Price
					# i[1] -> Amount
					formatPrice = str(format(i[0], '.5f')).rjust(10, ' ')
					cumulateAsks += i[1]
					formatCumulate = str(format(cumulateAsks, '.8f')).rjust(14, ' ')
					print u"Ask  | {0} | {1}".format(NiceText.colorText(formatPrice, "depth_ask"), formatCumulate)		
				print u"---------------------------------------------------"
			# Show depth in x steps with given price as starting point and cumulate amount
			elif (steps) and (price > 0) and (cumulate == 1):
				print u"Cumulation for specific prices is not supported within the depth-command."
		except:
			print u"Execution aborted."
			
def main():
	# Counter for transaction-nonce
	global counter
	counter = 0
	# Prepare parsing of config file
	global cfgp
	cfgp = CfgParse()
	# Read in config file
	global config
	config = cfgp.readCfg()
	locale.setlocale(locale.LC_ALL, "")
	encoding = locale.getpreferredencoding()
	sh = GoxSh(MtGox(u"goxsh"), encoding)
	print u"Welcome to goxsh!"
	print u"Type 'help' to get started."
	try:
		while True:
			sh.prompt()
	except EOFError:
		pass

if __name__ == "__main__":
	main()