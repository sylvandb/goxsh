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

class MtGoxError(Exception):
	pass

class NoCredentialsError(Exception):
	pass

class LoginError(Exception):
	pass

class MtGox(object):	
	def __init__(self, user_agent):
		self.unset_credentials()
		self.__url_parts = urlparse.urlsplit("https://mtgox.com/code/")
		self.__headers = {
			"User-Agent": user_agent
		}
	
	def get_username(self):
		return self.__credentials[0] if self.have_credentials() else None
	
	def have_credentials(self):
		return self.__credentials != None
		
	def set_credentials(self, username, password):
		if len(username) == 0:
			raise ValueError(u"Empty username.")
		if len(password) == 0:
			raise ValueError(u"Empty password.")
		self.__credentials = (username, password)

	def unset_credentials(self):
		self.__credentials = None
	
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
		return self.__get_json("getFunds.php")
	
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

	def __get_json(self, rel_path, params = {}, auth = True):
		if auth and not self.have_credentials():
			raise NoCredentialsError()
		params = params.items()
		if auth:
			params += [
				(u"name", self.__credentials[0]),
				(u"pass", self.__credentials[1])
			]
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
		self.__mtgox_commission = Decimal("0.003") # Be careful: this could change!
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
					if token != None:
						yield token
					remaining = remaining[len(raw_token):]
					found = True
					break
			if not found:
				message = "\n".join((
					u"  %s^" % (u" " * (len(line) - len(remaining))),
					u"Syntax error."
				))
				raise TokenizationError(message)
	
	def __parse_tokens(self, tokens):
		cmd = None
		args = []
		for token in tokens:				
			if token == u";":
				if cmd != None:
					yield (cmd, args)
					cmd = None
					args = []
			elif cmd == None:
				cmd = token
			else:
				args.append(token)
		if cmd != None:
			yield (cmd, args)
	
	def prompt(self):
		procs = []
		args = []
		try:
			raw_line = None
			try:
				text = u"\033[0;0m\033[1;36m%s$\033[0;0m " % (self.__mtgox.get_username() or u"")
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
							arity_text = u"%s+" % min_arity
						else:
							arity_text = u"%s-%s" % (min_arity, max_arity)
						arg_text = u"argument" + (u"" if arity_text == u"1" else u"s")
						raise ArityError(u"Expected %s %s, got %s." % (arity_text, arg_text, arg_count))
				except MtGoxError, e:
					print u"Mt. Gox error: %s" % e
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
		return getattr(self, "__cmd_%s__" % cmd, default)
	
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
		if proc != None:
			print cmd,
			argspec = inspect.getargspec(proc)
			args = argspec.args[1:]
			if argspec.defaults != None:
				i = -1
				for default in reversed(argspec.defaults):
					args[i] = (args[i], default)
					i -= 1
			for arg in args:
				if not isinstance(arg, tuple):
					print arg,
				elif arg[1]:
					print u"[%s=%s]" % arg,
				else:
					print u"[%s]" % arg[0],
			if argspec.varargs != None:
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
		if argspec.varargs != None:
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
		for order in ex_result[u"orders"]:
			self.__print_order(order)
	
	def __print_balance(self, balance):
		print u"BTC:\t", balance[u"btcs"]
		print u"USD:\t", balance[u"usds"]
	
	def __print_order(self, order):
		kind = {1: u"sell", 2: u"buy"}[order[u"type"]]
		timestamp = datetime.fromtimestamp(int(order[u"date"])).strftime("%Y-%m-%d %H:%M:%S")
		properties = []
		if bool(int(order[u"dark"])):
			properties.append(u"dark")
		if order[u"status"] == u"2":
			properties.append(u"not enough funds")
		print "[%s] %s\t%s:\t%sBTC @ %sUSD%s" % (timestamp, kind, order[u"oid"], order[u"amount"], order[u"price"], (" (" + ", ".join(properties) + ")" if properties else ""))
		
	def __unknown(self, cmd):
		def __unknown_1(*args):
			print u"%s: Unknown command." % cmd
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
			print u"Canceled %s %s." % (kind, order_id)
			if orders:
				for order in orders:
					self.__print_order(order)
			else:
				print u"No remaining orders."
		except KeyError:
			raise CommandError(u"%s: Invalid order kind." % kind)
	
	def __cmd_exit__(self):
		u"Exit goxsh."
		raise EOFError()
	
	def __cmd_help__(self, command = None):
		u"Show help for the specified command or list all commands if none is given."
		if command == None:
			cmds = self.__get_cmds()
		else:
			cmds = [command]
		for cmd in cmds:
			self.__print_cmd_info(cmd)
	
	def __cmd_login__(self, username = u""):
		u"Set login credentials."
		if not username:
			while not username:
				username = raw_input(u"Username: ").decode(self.__encoding)
			try:
				readline.remove_history_item(readline.get_current_history_length() - 1)
			except AttributeError:
				# Some systems lack remove_history_item
				pass
		password = u""
		while not password:
			password = getpass.getpass()
		self.__mtgox.set_credentials(username, password)
	
	def __cmd_logout__(self):
		u"Unset login credentials."
		self.__mtgox.unset_credentials()
	
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
			raise CommandError(u"%s: Invalid order kind." % kind)
	
	def __cmd_profit__(self, price):
		u"Calculate profitable short/long prices for a given initial price, taking\ninto account Mt. Gox's commission fee."
		try:
			dec_price = Decimal(price)
			if dec_price < 0:
				raise CommandError(u"%s: Invalid price." % price)
			min_profitable_ratio = (1 - self.__mtgox_commission)**(-2)
			print u"Short:\t< %s" % (dec_price / min_profitable_ratio).quantize(self.__usd_precision, ROUND_DOWN)
			print u"Long:\t> %s" % (dec_price * min_profitable_ratio).quantize(self.__usd_precision, ROUND_UP)
		except InvalidOperation:
			raise CommandError(u"%s: Invalid price." % price)
	
	def __cmd_sell__(self, amount, price):
		u"Sell bitcoins.\nPrefix the amount with a '$' to receive that many USD and calculate BTC\namount automatically."
		self.__exchange(self.__mtgox.sell, amount, price)

	def __cmd_ticker__(self):
		u"Display ticker."
		ticker = self.__mtgox.get_ticker()
		print u"Last:\t\033[1;33m%s\033[0;0m" % ticker[u"last"]
		print u"Buy:\t\033[1;32m%s\033[0;m"  % ticker[u"buy"]
		print u"Sell:\t\033[1;31m%s\033[0;m" % ticker[u"sell"]
		print u"Hight:\t%s" % ticker[u"high"]
		print u"Low:\t%s" % ticker[u"low"]
		print u"Volume:\t%s" % ticker[u"vol"]

	def __cmd_withdraw__(self, address, amount):
		u"Withdraw bitcoins."
		withdraw_info = self.__mtgox.withdraw(address, amount)
		print withdraw_info[u"status"]
		print u"Updated balance:"
		self.__print_balance(withdraw_info)

def main():
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
