#!/usr/bin/env python3.8

import os, sys
import csv
import re
import datetime as dt
from datetime import datetime, timedelta
import time
import argparse

import py_helper as ph
from py_helper import Msg, DebugMode, CmdLineMode, ErrMsg, DbgMsg, DbgAuto

import psearch

#
# Variables/Constants
#

# Argument Parser
parser = None

# Datastore being used (csv,sqlite3,mysql)
Datastore = "csv"

# Stop After Flag
stop_after = -1

# Ignorecase Flag
ignorecase = False

# Date Search Field Options
choices = { "ip" : 1, "mac" : 2, "dev" : 3 }

# Date Converter
StampConverter = ph.TimestampConverter()

# Destination Data File
CSV_Database="dhcp.log"

# Sqlite3 DB File
SQLite_Database="dhcp.sqlite"

# MySQL DB Connection String
MySQL_Database=""

# LogName/LiveLog
LiveLog = LogName = "dhcp"
# Log Extraction Expression
LogExp = r"^(?P<timestamp>\w+\s+\d{1,2}\s+[\d\:]{8})\s+[\S]+\s+(?P<assignedip>\S+)\s+(?P<macaddress>\S+)\s+(?P<devname>\S+)"
# Default Log Output
Output = "rezdhcp.txt"

# Augmented Mount Helper
Mount = psearch.Mounter("/srv/masergy")

#
# Lambdas
#

#
# Functions
#

# Convert Data to Date @ Midnight
def Midnight(date_in=None):
	"""Convert Date to Start of Day"""

	d = None

	if date_in == None:
		d = datetime.now().date()
	elif type(date_in) is datetime:
		d = date_in.date()
	elif type(date_in) is date:
		d = date_in

	t = dt.time(0,0,0)

	nd = datetime.combine(d,t)

	return nd

# Alias for Midnight
def StartOfDay(date_in=None):
	"""Alias for Midnight"""

	return Midnight(date_in)

# Convert DateTime to End of Day (Just before midnight)
def EndOfDay(date_in=None):
	"""Convert Date to End of Day"""

	d = None

	if date_in == None:
		d = datetime.now().date()
	elif type(date_in) is datetime:
		d = date_in.date()
	elif type(date_in) is date:
		d = date_in

	t = dt.time(23,59,59)

	nd = datetime.combine(d,t)

	return nd

# Sort Findings Rows By Date
def SortFindingsByDate(rows):
	"""Sort Findings Rows by Date"""

	sortkey = lambda row : row[0]

	sorted_findings = sorted(rows,key=sortkey)

	return sorted_findings

# Fix IP Searches
def FixIP(pattern):
	"""If a stand alone IP, fix it so RE does not go off the rails"""

	if re.search(pattern,"^([0-9]{1,3}\.){3}[0-9]{1,3}$"):
		# If IP, make sure "." is not interpreted as a regexp "." instead of a period seperator
		pattern = pattern.replace(".",r"\.")

	return pattern

# Search Live Log
def SearchLive(pattern,column,start,end):
	"""Search Live Log"""

	global Mount, LiveLog, StampConverter, LogExp

	DbgMsg(f"Entering SearchLive {pattern}, {column}, {start}, {end}")

	found = list()

	today = datetime.now()
	yesterday = today - timedelta(days=1)

	today_stamp = today.strftime("%Y%m%d")
	yesterday_stamp = yesterday.strftime("%Y%m%d")

	DbgMsg(f"Selected dates - {yesterday_stamp} to {today_stamp}")

	tmpfile = ph.TmpFilename()
	csv_out = ph.TmpFilename()

	# call psearch
	cmdline = f"--mount search --local --out {tmpfile} --start {yesterday_stamp} --end {today_stamp} --query ack {LiveLog}"
	parameters = cmdline.split(" ")

	try:
		psearch.run(arguments=parameters)
	except Exception as err:
		ErrMsg(err,"An error occurred while attempting to search the logs")

		return found

	splitter = re.compile("\s+")

	# extract, search
	ph.ExtractFromFile(LogExp,tmpfile,csv_out)

	with open(csv_out,newline='') as f_in:
		reader = csv.reader(f_in)

		for row in reader:
			date_arr = splitter.split(row[0])
			date_arr.insert(2,str(datetime.now().year))
			date_value = " ".join(date_arr)

			lts = StampConverter.ConvertTimestamp(date_value)

			if pattern.search(row[column]) != None:
				found.append([ lts, row[1], row[2], row[3] ])

	if os.path.exists(tmpfile): os.remove(tmpfile)
	if os.path.exists(csv_out): os.remove(csv_out)

	DbgMsg(f"Found {len(found)} matching records")

	return found

# Search CSV Data Store
def SearchCSVLog(pattern,column,start,end,searchlive=False):
	"""Search CSV Data Store"""

	global CSV_Database, stop_after, StampConverter, Mount

	found = list()

	foundCount = 0

	with open(CSV_Database,"r",newline='') as f_in:
		reader = csv.reader(f_in)

		for row in reader:
			lts = StampConverter.ConvertTimestamp(row[0])

			if lts == None:
				Msg("This line/row had some issues")
				Msg(row)
				continue

			if pattern.search(row[column]) != None:
				if start != None and lts >= start and lts <= end:
					foundCount += 1
					found.append([ lts, row[1], row[2], row[3] ])
				elif start == None:
					foundCount += 1
					found.append([ lts, row[1], row[2], row[3] ])

			if stop_after > 0 and foundCount >= stop:
				break

	if searchlive:
		live_items = SearchLive(pattern,column,start,end)

		if live_items and len(live_items) > 0:
			found.extend(live_items)

	if len(found) > 0:
		found = SortFindingsByDate(found)

	return found

# Generic Log Search
def SearchLog(pattern,column,start,end,searchlive=False):
	"""Search Log, Generic"""

	global Datastore

	found = None

	if Datastore == "csv":
		found = SearchCSVLog(pattern,column,start,end,searchlive)
	elif Datastore == "sqlite3":
		ph.NotYetImplemented()
	elif Datastore == "mysql":
		ph.NotYetImplemented()
	elif Datastore == "redis":
		ph.NotYetImplemented()

	return found

# Search By Date
def DateSearch(args):
	"""Search By Date, Primarily"""
	global ignorecase, choices, StampConverter

	found = list()

	field = "ip"
	pattern = None
	start = None
	end = None

	if len(args.field) > 0: field = args.field
	column = choices[field]

	pattern = args.pattern

	if args.start == None:
		start = Midnight()
	else:
		start = StampConverter.ConvertTimestamp(args.start)

	if args.end == None:
		end = EndOfDay()
	else:
		end = StampConverter.ConvertTimestamp(args.end)

	psrch = None

	if field == "ip":
		pattern = FixIP(pattern)

	if ignorecase:
		psrch = re.compile(pattern,re.IGNORECASE)
	else:
		psrch = re.compile(pattern)

	found = SearchLog(psrch,column,start,end,args.live)

	if args.biggerpicture and field == "ip" or field == "mac":

		newfield = "ip" if field == "mac" else "mac"

		additions = list()

		for timestamp,ip,mac,devname in found:
			if field == "ip":
				if not mac in additions:
					additions.append(mac)
			elif field == "mac":
				if not ip in additions:
					additions.append(ip)

		for item in additions:
			ps = None

			if ignorecase:
				ps = re.compile(item,re.IGNORECASE)
			else:
				ps = re.compile(item)

			found.extend(SearchLog(ps,choices[newfield]),start,end,args.live)

		if len(found) > 0:
			found = SortFindingsByDate(found)

	return found

#Search by IP
def IPSearch(args):
	"""Search By IP, Primarily"""
	global ignorecase, StampConverter

	found = list()

	field = "ip"
	column = choices[field]

	ip = args.ip

	if re.search(ip,"^([0-9]{1,3}\.){3}[0-9]{1,3}$"):
		# If IP, make sure "." is not interpreted as a regexp "." instead of a period seperator
		ip = ip.replace(".",r"\.")

	psrch = None

	if ignorecase:
		psrch = re.compile(ip,re.IGNORECASE)
	else:
		psrch = re.compile(ip)

	start = None
	end = None

	if args.start == None:
		start = Midnight()
	else:
		start = StampConverter.ConvertTimestamp(args.start)

	if args.end == None:
		end = EndOfDay()
	else:
		end = StampConverter.ConvertTimestamp(args.end)

	found = SearchLog(psrch,column,start,end,args.live)

	return found

# Search By Mac
def MACSearch(args):
	"""Search by MAC, Primarily"""

	global ignorecase

	found = list()

	field = "mac"
	column = choices[field]

	mac = args.mac

	psrch = None

	if ignorecase:
		psrch = re.compile(mac,re.IGNORECASE)
	else:
		psrch = re.compile(mac)

	start = None
	end = None

	if args.start == None:
		start = Midnight()
	else:
		start = StampConverter.ConvertTimestamp(args.start)

	if args.end == None:
		end = EdnOfDay()
	else:
		end = StampConverter.ConvertTimestamp(args.end)

	found = SearchLog(psrch,column,start,end,args.live)

	return found

# Search By Dev
def DevSearch(args):
	"""Search by Dev, Primarily"""
	global ignorecase

	found = list()

	field = "dev"
	column = choices[field]

	dev = args.dev

	psrch = None

	if ignorecase:
		psrch = re.compile(dev,re.IGNORECASE)
	else:
		psrch = re.compile(dev)

	start = None
	end = None

	if args.start == None:
		start = Midnight()
	else:
		start = StampConverter.ConvertTimestamp(args.start[0])

	if args.end == None:
		end = EndOfDay()
	else:
		end = StampConverter.ConvertTimestamp(args.end)

	found = SearchLog(psrch,column,start,end,args.live)

	return found

# Post Process Search Output to SQL DB
def PostProcessSQLite(output_file,logdate=None):
	"""Post Process Search Output File"""

	# Open/Create SQLite Database
	def OpenSqliteDatabase():
		"""Open/Create Database"""

		global SQLite_Database

		connection = None

		table_spec = """CREATE TABLE IF NOT EXISTS dhcplog (
				recordid VARCHAR(36),
				timestamp INT,
				ip VARCHAR(15),
				mac VARCHR(17),
				devname VARCHAR(56)
				);
				"""

		index_cmd = """CREATE INDEX dhcplog_index ON dhcplog;"""


		try:
			if Database == ":memory:" or not os.path.exists(SQLite_Database):
				connection = sql.Open(SQLite_Database,table_spec)

				result = sql.Execute(index_cmd)
			else:
				connection = sql.Open(SQLite_Database)

			sql.BulkOn()
		except Error as dberr:
			ErrMsg(dberr,f"An error occurred trying to open {Database}")
		except Exception as err:
			ErrMsg(err,f"An error occurred trying to open {Database}")

		return connection

	# Insert Into Database (If not already there)
	def InsertRecord(timestamp,ip,mac,devname):
		"""Insert tuple into Database, if there is no matching record"""

		inserted = False

		posix_timestamp = int(timestamp.timestamp())

		msg = f"{timestamp},{ip},{mac},{devname},{posix_timestamp}"

		search_cmd = f"SELECT * from dhcplog where timestamp=? and ip=? and mac=?"
		parameters = [ posix_timestamp, ip, mac ]

		results = sql.Select(search_cmd,parameters)

		fetch = 0

		# Check to see if there is a result, if so, record already exists and we bypass
		for row in results:
			fetch += 1
			break

		if fetch == 0:
			ins = """INSERT INTO dhcplog (recordid,timestamp,ip,mac,devname) VALUES(?,?,?,?,?)"""

			parameters = [ str(uuid.uuid1()), posix_timestamp, ip, mac, devname ]

			result = sql.Insert(ins,parameters)

			inserted = True

		return inserted

	global LogExp, TimestampConverter

	success = False

	OpenSqliteDatabase()

	exp = re.compile(LogExp)
	splitter = re.compile("\s+")

	if logdate == None:
		logdate = datetime.now()

	count = 0
	processed = 0
	existing = 0

	with open(output_file,"r") as f_in:
		connection = OpenDatabase()

		if connection != None:
			for line in f_in:
				matches = exp.search(line)

				processed += 1

				if matches != None:
					timestamp = matches.group("timestamp")
					assigned_ip = matches.group("assignedip")
					macaddress = matches.group("macaddress")
					devname = matches.group("devname")

					devname = devname if devname != "None" else ""

					tsl = splitter.split(timestamp)

					timestamp = f"{tsl[0]} {tsl[1]} {logdate.year} {tsl[2]}"

					ts = TimestampConverter.ConvertTimestamp(timestamp)

					inserted = InsertRecord(ts,assigned_ip,macaddress,devname)

					if inserted:
						count += 1
					else:
						existing += 1

					if count % 1000 == 0:
						Msg(f"Processed {processed} lines so far")
				else:
					Msg(f"Line {processed} in search output rejected")

			Msg(f"{processed} lines processed, {count} lines extracted, {existing} already in database")
			success = True

			connection.close()
		else:
			Msg("Database could not be opened")

	if os.path.exists(output_file): os.remove(output_file)

	return success

# Post Process Search Output To CSV
def PostProcessCSV(output_file,csv_filename,mode="w",logdate=None):
	"""Post Process Search Output To CSV"""

	global LogExp, StampConverter

	success = False

	exp = re.compile(LogExp)
	splitter = re.compile("\s+")

	if logdate == None:
		logdate = datetime.now()

	count = 0
	processed = 0

	with open(output_file,"r") as f_in:
		with open(csv_filename,mode) as f_out:
			writer = csv.writer(f_out)

			for line in f_in:
				matches = exp.search(line)

				processed += 1

				if matches != None:
					timestamp = matches.group("timestamp")
					assigned_ip = matches.group("assignedip")
					macaddress = matches.group("macaddress")
					devname = matches.group("devname")

					devname = devname if devname != "None" else ""

					# This is a hack to insert a "year" in the log
					# For storage economy, some logs leave the
					# year out of the entry
					tsl = splitter.split(timestamp)
					timestamp = f"{tsl[0]} {tsl[1]} {logdate.year} {tsl[2]}"

					ts = StampConverter.ConvertTimestamp(timestamp)

					writer.writerow([ ts, assigned_ip, macaddress, devname ])

					count += 1
				else:
					Msg(f"Line {processed} in search output rejected")

			Msg(f"{processed} lines processed, {count} lines extracted")
			success = True

	if os.path.exists(output_file): os.remove(output_file)

	return success

# Extract Logs
def ExtractLogs(**kwargs):
	"""Extract Logs"""

	global CSV_Database, LogName, Output, Datastore, parser

	arguments = kwargs.get("arguments",None)
	args = kwargs.get("args",None)

	if arguments != None:
		arguments.insert(0,"extract")

		args = parser.parse_args(arguments)

	start_date = None
	end_date = None

	logfname = CSV_Database if args.logout == None else args.logout
	output = Output if args.output == None else args.output

	mode = "a" if args.append else "w"

	if len(args.start) > 0:
		start_date = args.start[0]
	else:
		start_date = datetime.now().strftime("%Y%m%d")

	if args.end != None:
		end_date = args.end
	else:
		end_date = datetime.now().strftime("%Y%m%d")

	cmdline = [ "--silent", "search", "--local", "--out", output, "--start", start_date, "--end", end_date, "--query", "ack", LogName ]

	success = False

	if not args.exists or not os.path.exists(output):
		# Run P-Search
		try:
			psearch.run(arguments=cmdline)

			success = True
		except Exception as err:
			ErrMsg(err,"An error occurred while trying to extract log data")
	else:
		success = True

	#
	# ***BIG*** TODO: Logs, particularly this reznet1 does not contain a "year"
	# in the text... we have to extract that info and pass along for timestamp
	# purposes. psearch output does not contain this.
	# although, THIS might be the right place to fix it, in PSEARCH.
	# For NOW, assume all dates are this YEAR.
	# The only trouble spot for this will be the 4/5 days surrounding
	# Jan 1st of any given year.
	#

	if success:
		start = datetime.now()

		if args.sqlite:
			Datastore="sqlite"
			success = PostProcessSQLite(output)
		elif args.mysql:
			Datastore="mysql"
			ph.NotYetImplemented()
		elif args.redis:
			Datastore="redis"
			ph.NotYetImplemented()
		elif args.elastic:
			Datastore="elastic"
			ph.NotYetImplemented()
		elif args.hadoop:
			Datatore="hadoop"
			ph.NotYetImplemented()
		else:
			# Also CSV Mode
			Datastore="csv"
			success = PostProcessCSV(output,logfname,mode)

		end = datetime.now()
		diff = end - start

		Msg(f"Took {diff.total_seconds() / 60} minutes")

	if not success:
		Msg("Bummer man")

	return success

def BuildParser():
	"""Build Parser"""

	global choices, parser

	dchoices = list(choices.keys())

	parser = argparse.ArgumentParser(prog="dhcpd.py",description="DHCP Log Search")

	parser.add_argument("-d","--debug",action="store_true",help="Enter Debug Mode")
	parser.add_argument("-t","--test",action="store_true",help="Run test stub")
	parser.add_argument("-l","--live",action="store_true",help="Search live log")
	parser.add_argument("--silent",action="store_true",help="No informational output")
	parser.add_argument("--stop",help="Stop after finding X results")
	parser.add_argument("-i","--ignorecase",action="store_true",help="In Regex patterns, ignore case")

	sub_parsers = parser.add_subparsers(help="commands",dest="command")

	date_search = sub_parsers.add_parser("date",help="Date based searches")
	date_search.add_argument("-b","--biggerpicture",action="store_true",help="When searching for IP's or MAC's, use the results of the first search to search for the other")
	date_search.add_argument("field",choices=dchoices,help="Field to search")
	date_search.add_argument("pattern",help="Search pattern")
	date_search.add_argument("start",nargs=1,help="Search start date")
	date_search.add_argument("end",nargs="?",help="End date for search, if omitted one day is added to start")

	ip_search =  sub_parsers.add_parser("ip",help="IP based searches")
	ip_search.add_argument("ip",help="IP/IP expression to search for")
	ip_search.add_argument("start",nargs="?",help="Starting Date for search")
	ip_search.add_argument("end",nargs="?",help="End date for search")

	mac_search = sub_parsers.add_parser("mac",help="MAC Address based search")
	mac_search.add_argument("mac",help="MAC Address/Expression to search for")
	mac_search.add_argument("start",nargs="?",help="Starting Date for search")
	mac_search.add_argument("end",nargs="?",help="End date for search")

	dev_search = sub_parsers.add_parser("dev",help="Device name Based searches")
	dev_search.add_argument("dev",help="Device Name/Expression to search for")
	dev_search.add_argument("start",nargs="?",help="Starting Date for search")
	dev_search.add_argument("end",nargs="?",help="End date for search")

	extract_data = sub_parsers.add_parser("extract",help="Extract DHCP data from logs")
	# Should make the mode elements mutually exclusive
	extract_data.add_argument("--csv",action="store_true",help="Place in csv mode (default)")
	extract_data.add_argument("--sqlite",action="store_true",help="Place in SQLite mode (as opposed to CSV mode)")
	extract_data.add_argument("--mysql",action="store_true",help="Place in MySql Mode")
	extract_data.add_argument("--redis",action="store_true",help="Place in Redis Mode")
	extract_data.add_argument("--elastic",action="store_true",help="Place in Elastic Mode")
	extract_data.add_argument("--hadoop",action="store_true",help="Place in Hadoop Mode")
	# Regular Options
	extract_data.add_argument("-o","--output",help=f"Where to output (Default:{Output})")
	extract_data.add_argument("-l","--logout",help="Alternate DHCP log output")
	extract_data.add_argument("-a","--append",action="store_true",help="Append to DHCP Log, instead of overwrite")
	extract_data.add_argument("-e","--exists",action="store_true",help="If output already exists, just process it")
	extract_data.add_argument("--live",action="store_true",help="Get live log to, if possible")
	extract_data.add_argument("start",nargs=1,help="Start date in YYYYMMDD format")
	extract_data.add_argument("end",nargs="?",help="End date in YYYYMMDD format, if not supplied, today is assumed")

# Parser Arguments
def ParseArgs(**kwargs):
	"""Parser Arguments"""

	global parser, choices

	arguments = kwargs.get("arguments",None)
	unknowns = kwargs.get("unknowns",None)
	args = None

	if arguments:
		args = parser.parse_args(arguments)
	else:
		args = parser.parse_args()

	if args.debug: DebugMode(True)

	if args.stop != None: stop_after = int(args.stop)
	if args.ignorecase: ignorecase=args.ignorecase
	if args.silent: CmdLineMode(False)

	return args

# Run Pattern Entry Point
def run(arguments=None):
	"""Run pattern entry point"""

	global Mount

	args = None

	if arguments:
		args = ParserArgs(arguments)
	else:
		args = ParseArgs()

	found = None

	if args.live:
		Mount.Mount(sudome=True)

	if args.test:
		Test(args=args)
	if args.command == "date":
		found = DateSearch(args)
	elif args.command == "ip":
		found = IPSearch(args)
	elif args.command == "mac":
		found = MACSearch(args)
	elif args.command == "dev":
		found = DevSearch(args)
	elif args.command == "extract":
		ExtractLogs(args=args)

	if args.live:
		Mount.Unmount(sudome=True)

	if found != None and len(found) > 0:
		for row in found:
			Msg(f"{row[0]} {row[1]} {row[2]} {row[3]}")
	elif not args.command in [ "extract" ] and not args.test:
		Msg("Nothing found...")

	return found

# Test Stub
def Test(**kwargs):
	"""Test Stub"""

	arguments = kwargs.get("arguments",None)
	args = kwargs.get("args",None)
	unknowns = kwargs.get("unknowns",None)

	if not args:
		if arguments:
			args = ParseArgs(arguments)
		else:
			args = ParseArgs()

		args = ParseArgs()


# Initialize Module Code
def Initialize(**kwargs):
	"""Init Module"""

	BuildParser()

#
# Init Code
#

Initialize()

#
# Main Loop
#

if __name__ == "__main__":
	CmdLineMode(True)

	run()

