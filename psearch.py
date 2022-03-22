#!/usr/bin/env python3.8

import os, sys, io, socket, select
import re, random, queue
import argparse,configparser,logging
from collections import deque
import xml, json, csv, hashlib
import xml.etree.ElementTree as ET
import gzip

# Debug Stuff
import inspect
import traceback
import pdb

# For Keyboard character scanning
import termios, fcntl

from datetime import datetime,timedelta,date,time
import time as tm

import multiprocessing
from concurrent.futures import ProcessPoolExecutor


import py_helper as ph
from py_helper import DebugMode,CmdLineMode,Pause,Log,Msg,ErrMsg,DbgMsg,DbgAuto
from py_helper import TmpFilename,ItemID,Taggable,MountHelper, TimestampConverter

#
# Globals
#

# Debug Args for Interactive Sessions
DEBUGSRVARGS = [ '--debug','--trace','--server','--out','users.txt','--query','users','wifi' ]
DEBUGCLTARGS = [ '--debug','--trace','--client','sol.infosec.stonybrook.edu' ]

# Version Info
Version = "1.0"

# Config Stuff
ConfigFile="psearch.ini"
# Config Parser Object
AppConfig = None

# Parser
Parser = None
# ShowCmd Choices
ShowChoices = [ "all", "good", "failed", "sources" ]

# Processed Arguments
Args = None

# Log Metas
LogMetas = list()

# For interactive Inspection
searchManager = None

# Default Tracer States Filename (must be local to execution)
TRACEStatefile = "trace_ex.txt"
# Tracer
tracer = None

# Thread terminate semaphore
TerminateFlag = ""

# Mounts (for log sources)
Mounts = list()

# Log Mount
LogMount = "/srv/masergy"

# Log sources list
LogSources="/srv/storage/data/logsources.xml"
# Locations where files are
LogLocations=[ "/srv/equallogic/fsm_logs", "/srv/array2/fsm_logs", LogMount ]

# Temp Space for intemediate output
TempSpace = "/tmp"

# Default Seconds to Wait For a Connection to Client or Server
DefaultConnectionWait = 585

# Server Defaults
DefaultAddress = "0.0.0.0"
DefaultServerAddress = DefaultAddress
DefaultPort = 6530

# Expression for date stamps on files
dateExpr = "^(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})$"

# List of logs determine to be in scope for searching
logInfo = [ ]

# App Helper
app = None

# Logging Config
logFilename = "/tmp/psearch.log.{}".format(os.getpid())
logging.basicConfig(filename=logFilename, level=logging.DEBUG)
logger = logging.getLogger(__name__)

#
# Lambdas
#

CreationTime = lambda filename : datetime.fromtimestamp(os.path.getctime(filename))
ModificationTime = lambda filename : datetime.fromtimestamp(os.path.getmtime(filename))
AccessTime = lambda filename : datetime.fromtimestamp(os.path.getatime(filename))

#
# Top Level Functions
#

# Search Through Open File
def OpenFileSearch(log,f_in,patterns,streamers,limit,termflag):
	tracer.Entering("global::OpenFileSearch")

	textStream = False

	logOut = "stdout"
	f_out = sys.stdout

	# if streamers.... setup pipes on output???
	if log.Output and type(log.Output) is str:
		logOut = log.Output
		f_out = open(log.Output,"wb")
	elif log.Output and type(log.Output) is io.TextIOWrapper:
		logOut = "Using existing open text stream"
		textStream = True
		f_out = log.Output
	elif log.Output and type(log.Output) is io.BufferedWriter:
		logOut = "Using existing open BufferedWriter stream"
		f_out = log.Output
	elif log.Output and log.Output is sys.stdout:
		logOut = "Output supplied was stdout"
		textStream = True
		f_out = log.Output

	progs = []

	for pattern in patterns:
		if pattern is str:
			progs.append(Query(pattern))
		else:
			progs.append(pattern)

	linesProcessed = 0
	matchingLines = 0

	# Init File size
	logSize = log.Size

	# Get Base Name
	logName = os.path.basename(log.Filename)

	# Init Pattern Count
	patternCount = len(progs)

	tracer.Inside("global::OpenFileSearch",postfix=f"Beginning Search of {log.Filename}")

	# If we want to use multiple indexes, we have to merge the indexes and order the
	# the positions in ascending order. In reality, we will probably just be using one
	# at a time.

	for rawline in f_in:
		if os.path.exists(termflag):
			break

		try:
			decoded, used, line = log.Decode(rawline)

			if not decoded:
				DbgMsg("{} - Decoding line {} failed".format(logName,processedLines+1))
				continue

			if patternCount > 0:
				for prog in progs:
					matches = prog.Match(line)

					if matches:
						# Run line through stream
						matchingLines += 1

						# Check for named groups, then only print named groups
						groups = matches.groupdict()

						if groups and len(groups) > 0:
							keys = groups.keys()

							newline = ""

							for key in keys:
								newline += f"{groups[key]} "

							line = newline.strip() + "\n"

						if textStream:
							f_out.write(line)
						else:
							f_out.write(bytearray(line,used))

						break
			else:
				# Run line through streamer
				matchingLines += 1
				if textStream:
					f_out.write(line)
				else:
					f_out.write(bytearray(line,used))

			linesProcessed += 1

			if limit > 0 and matchingLines >= limit:
				break

		except Exception as err:
			DbgMsg(f"{logName} - OpenFileSearch : {err}")

	if type(log.Output) is str:
		f_out.close()

	log.Track(f"search completed, {matchingLines} matches")

	# DbgMsg(f"{logName} - {linesProcessed} processed, {matchingLines} lines matched")

	tracer.Exitting("global::OpenFileSearch")

	return matchingLines

# Begin Log Search
def SearchLog(log,patterns,streamers,limit,termflag):
	tracer.Entering("global::SearchLog")

	lines = 0

	try:
		# Here the log.Open function determines if the log is compressed or not
		# and takes the appropriate action to open the file
		with log.Open() as f_in:
			lines = OpenFileSearch(log,f_in,patterns,streamers,limit,termflag)

	except Exception as err:
		DbgMsg(f"Error SearchLog : {err}")

	tracer.Exitting("global::SearchLog")

	return lines

# Show Log Info
# Params:
# showpattern - True/False, show the log file name pattern expression
# filter - optional expression to filter results on (inclusive)
# status - optional, if provided, list logs with given status
def ShowLogsInfo(showpattern=False,filter=None,status=None,showCounts=False,sample=None,headtail=False):
	"""Show Logs Info"""

	global LogMetas, LogLocations

	fmt = "{:12} {:13} {:6} {:20} "
	columns = [ "alias", "groups", "status", "name" ]

	if sample != None:
		sample = int(sample) if sample != 'all' else -1
	else:
		sample = 0

	if showpattern:
		fmt += "{:45} "
		columns.append("pattern")

	if status == "all": status = None

	Msg(fmt.format(*columns))

	for meta in LogMetas:
		if status and not re.match(status,meta.Status):
			continue

		if filter:
			prog = re.compile(filter)

			isMatch = False

			searchables = meta.Searchables()

			for value in searchables:
				if prog.match(value):
					isMatch = True
					break

			if not isMatch:
				continue

		statusField = meta.Status

		if showCounts:
			count = 0

			for logPath in LogLocations:
				count += len(meta.GetLogFiles(folder=logPath))

			statusField = f"{meta.Status}/{count}"

		columns = [ meta.Nickname, ",".join(meta.LogGroups), statusField, meta.Name ]

		if showpattern:
			columns.append(meta.ParseInfo[0])

		Msg(fmt.format(*columns))

		if sample > 0:
			# Show 'sample' lines from latest log

			files = meta.GetLogFiles(folder=LogLocations[0])
			file = files[random.randint(0,len(files)-1)]

			with file.Open() as f_in:
				head = 0
				count = 0

				queue = deque(maxlen=sample)

				for rawline in f_in:
					count += 1
					head += 1

					decoded, used, line = file.Decode(rawline)

					queue.append(line)

					if (headtail and head == sample) or (not headtail and count == sample):
						if headtail:
							Msg(ph.CombiBar("Head of Log"))
						else:
							Msg(f"Log sample - {sample} lines")

						for item in queue:
							Msg(item)

						if not headtail:
							break

				if headtail:
					Msg(ph.CombiBar("\nTail for Log"))
					for item in queue:
						Msg(item)

		elif sample < 0:
			# Dump latest log

			files = meta.GetLogFiles(folder=LogLocations[0])
			file = files[random.randint(0,len(files)-1)]

			with file.Open() as f_in:
				for rawline in f_in:
					decoded, used, line = file.Decode(rawline)

					Msg(line)

# Show list of existing logs using supplied names (Defaults to only "good" logs)
def ShowLogs(status,logspec):
	"""Show Logs"""

	global LogMetas, LogLocations

	valids = [ "all", "good", "failed" ]

	if not status in valids:
		status = "good"

	metas = [ meta for meta in LogMetas if meta.Status == status or status == "all" ]

	selected = list()

	if logspec != None:
		selected = [ meta for meta in metas if logspec in meta.Searchables() ]
	else:
		selected.extend(metas)

	for logPath in LogLocations:
		Msg(f"Logs in Storage Location : {logPath}\n" + "=" * 40)

		for meta in selected:
			logs = meta.GetLogFiles(folder=logPath)

			Msg(f"Logs Of {meta.Name} / {meta.Nickname} / {meta.Description} - {len(logs)}")

			for log in logs:
				Msg(f"{log.Filename}")

#
# Classes
#

# Mounter : MountHelper with some Safety Checks
class Mounter(MountHelper):
	"""Mount Helper With Safety Check"""

	# Already Mounted Flag
	AlreadyMounted = False

	# Init Instance
	def __init__(self,path=None):
		"""Init instance"""
		super().__init__(path)

	# Hide Mount, Add Safety Check
	def Mount(self,ignore=False,sudome=False):
		"""Safe Mount"""

		if self.Mounted():
			self.AlreadyMounted = True
		else:
			self.AlreadyMounted = False

			super().Mount(ignore,sudome)

	# Unmount
	def Unmount(self,ignore=False,sudome=False):
		"""Unmount Mounted Volume, Safely"""

		if not self.AlreadyMounted and self.Mounted():
			super().Unmount(ignore,sudome)

	# Unmount
	def Umount(self,ignore=False,sudome=False):
		"""Shortcut for Die Hard Unix Pipple"""
		self.Unmount(ignore,sudome)


# Title/Value Formatted Class
class TitleValueFormatter:
	# Print Formatted Title : Value Pair
	def PrintFormatted(self,title,value,postfix=None,size=20,align="<",seperator=":"):
		fmt = "{:" + align + str(abs(size)) + "} " + seperator + " {}"

		if postfix:
			fmt += (" " + postfix)

		print(fmt.format(title,str(value)))

	# Alias for PrintFormatted
	def Pfmt(self,title,value,postfix=None,size=20,align="<",seperator=":"):
		self.PrintFormatted(title,value,postfix,size,align,seperator)

# Tracing Class
class Tracable:
	# State File
	Statefile = None
	# Active States
	TraceStates = None
	# Trace Enable Flag
	Enabled = False
	# Last Called
	LastCalled = None

	# Init Intance
	def __init__(self,statefile=None,enabled=False):
		self.LoadStates(statefile)
		self.Enabled = enabled
		self.TraceStates = []

	# Load State file
	def LoadStates(self,statefile=None):
		if statefile:
			self.Statefile = statefile

		if self.Statefile:
			if os.path.exists(self.Statefile):
				with open(self.Statefile,"rt") as f_in:
					self.TraceStates.clear()

					for line in f_in:
						line = line.strip()

						if not line.startswith("#") or line != "":
							tuple = line.split(",")

							self.TraceStates.append(tuple)
			else:
				print(f"{self.Statefile} does not appear to exist")

	# Save State Table
	def SaveStates(self,filename):
		self.Statefile = filename

		with open(self.Statefile,"wt") as f_out:
			for entry in self.TraceStates:
				f_out.write(f"{entry[0]},{entry[1]}\n")

	# Add State to Trace State Lit
	def AddState(self,callerid,state=None):
		if type(callerid) is list and state is None:
			self.TraceStates.append(callerid)
		else:
			if state is None:
				state = "none"

			self.TraceStates.append([callerid,state])

	# Add States To Trace State List
	def AddStates(self,spairs):
		for pair in spairs:
			if type(pair) is list:
				self.AddState(pair)

	# Get Caller Framer (from where this was called as a starting reference)
	def GetCallerFrame(self):
		callerframe = inspect.currentframe().f_back.f_back

		return callerframe

	# Add Reference To State Table
	def AddReference(self,object):
		if object.__class__.__name__ == "function":
			callerid = f"function::{object.__name__}"
		else:
			attributes = dir(object)

			for attribute in attributes:
				if not attribute.startswith("__") and object.__getattribute__(object,attribute).__class__.__name__ == "function":
					entry = [ f"{object.__name__}::{attribute}", "all" ]

	# Add Multiple References To State Table
	def AddReferences(self,*kwargs):
		for item in kwargs:
			self.AddReference(item)

	# Enable Tracing
	def Enable(self):
		self.Enabled = True

	# Disable Tracing
	def Disable(self):
		self.Enabled = False

	# Get Trace Entry
	def GetTraceEntry(self,traceCaller):
		callerid = ""

		if type(traceCaller) is str:
			callerid = traceCaller
		else:
			callerframe = inspect.currentframe().f_back

			callerclass = traceCaller.__class__.__name__
			callername = callerframe.f_code.co_name
			callerid = f"{callerclass}::{callername}"

		entry = None

		for tuple in self.TraceStates:
			if tuple[0] == callerid:
				entry = tuple
				break

		return entry

	# Get Trace State of supplied Caller
	def GetTraceState(self,traceCaller):
		callerid = ""

		if type(traceCaller) is str:
			callerid = traceCaller
		else:
			callerframe = inspect.currentframe().f_back

			callerclass = traceCaller.__class__.__name__
			callername = callerframe.f_code.co_name
			callerid = f"{callerclass}::{callername}"

		state = None

		entry = self.GetTraceEntry(callerid)

		if entry:
			state = entry[1]

		return state

	# Set State of Callerid (or clear) callerid for Trace Processing
	def SetTraceState(self,traceCaller,state="none"):
		"""Set Trace State"""

		if type(traceCaller) is list:
			for id in traceCaller:
				callerid = ""

				if type(id) is str:
					callerid = id
				else:
					callerframe = inspect.currentframe().f_back
					callerclass = id.__class__.__name__
					callername = callerframe.f_code.co_name

					callerid = f"{callerclass}::{callername}"

				entry = self.GetTraceEntry(callerid)

				if entry:
					entry[1] = state
				elif callerid != "":
					self.AddState([ callerid, state ])
		else:
			callerid = ""

			if type(traceCaller) is str:
				callerid = traceCaller
			else:
				callerframe = inspect.currentframe().f_back
				callerclass = traceCaller.__class__.__name__
				callername = callerframe.f_code.co_name

				callerid = f"{callerclass}::{callername}"

			entry = self.GetTraceEntry(callerid)

			if entry:
				entry[1] = state
			elif callerid != "":
				self.AddState([ callerid, state ])

	# Trace Function : Display tracing messages
	def Trace(self,traceCaller,callerframe=None,prefix="",postfix=""):

		if self.Enabled:
			callerid = ""

			if callerframe is None:
				callerframe = inspect.currentframe().f_back

			if type(traceCaller) is str:
				callerid = traceCaller
			else:
				callerclass = traceCaller.__class__.__name__
				callername = callerframe.f_code.co_name
				callerid = f"{callerclass}::{callername}"

			if callerid == "":
				print(f"Could not determine trace caller for {traceCaller}")
			else:
				entry = self.GetTraceEntry(callerid)
				state = None

				if entry:
					state = entry[1]

				if entry and not (state in [ "both", "all" ] or not entry):

					trcmsg = f"File {callerframe.f_code.co_filename} line {callerframe.f_lineno} : {prefix}{callerid} {postfix}"

					# If set to "once", disable
					if (entry and state == "once"):
						entry[1] = "all"

					print(trcmsg)

				self.LastCalled = callerid

	# Entering Trace Alias
	def Entering(self,traceCaller,allow=True,postfix=""):
		"""Issue Entering Trace Message"""

		if allow and self.Enabled:
			callerframe = inspect.currentframe().f_back

			callerid = ""
			if type(traceCaller) is str:
				callerid = traceCaller
			else:
				callerclass = traceCaller.__class__.__name__
				callername = callerframe.f_code.co_name
				callerid = f"{callerclass}::{callername}"

			if callerid == "":
				Msg(f"Could not determine trace caller for {traceCaller}")
			else:
				entry = self.GetTraceEntry(callerid)
				state = None

				if entry:
					state = entry[1]

				if not entry or not state in [ "enter", "both", "all" ]:
					self.Trace(f"{callerid}",callerframe,prefix="Entering ",postfix=postfix)

	# Inside Function Trace Statement
	def Inside(self,traceCaller,allow=True,postfix=""):
		"""Issue Inside Trace Message"""

		if allow and self.Enabled:
			callerframe = inspect.currentframe().f_back

			callerid = ""

			if type(traceCaller) is str:
				callerid = traceCaller
			else:
				callerclass = traceCaller.__class__.__name__
				callername = callerframe.f_code.co_name
				callerid = f"{callerclass}::{callername}"

			if callerid == "":
				print(f"Could not determine trace caller for {traceCaller}")
			else:
				entry = self.GetTraceEntry(callerid)
				state = None

				if entry:
					state = entry[1]

				if not entry or not state in [ "inside", "both", "all" ]:
					self.Trace(f"{callerid}",callerframe,prefix="Inside ",postfix=postfix)

	# Exitting Trace Alias
	def Exitting(self,traceCaller,allow=True,postfix=""):
		"""Issue Exitting Trace Message"""

		if allow and self.Enabled:
			callerframe = inspect.currentframe().f_back

			callerid = ""

			if type(traceCaller) is str:
				callerid = traceCaller
			else:
				callerclass = traceCaller.__class__.__name__
				callername = callerframe.f_code.co_name
				callerid = f"{callerclass}::{callername}"

			if callerid == "":
				print(f"Could not determine trace caller for {traceCaller}")
			else:
				entry = self.GetTraceEntry(callerid)
				state = None

				if entry:
					state = entry[1]

				if not entry or not state in [ "exit", "both", "all" ]:
					self.Trace(f"{callerid}",callerframe,prefix="Exitting ",postfix=postfix)

# Do Something Peridically
class Periodic(TitleValueFormatter,Taggable):
	# Time Delta Interval
	Interval = None
	# Next Event Time Stamp
	NextEvent = None
	# Last Event Time Stamp
	LastEvent = None
	# Started Time Stamp
	Started = None
	# Trigger Limit
	TriggerLimit = 0
	# Trigger Count
	TriggerCount = 0
	# Lambda
	Lambda = None

	# Initialize Instance
	def __init__(self,interval=None,trigger=None):
		if interval:
			if type(interval) is int:
				self.Interval = timedelta(seconds=interval)
		else:
			self.Interval = interval

		if trigger:
			self.TriggerLimit = trigger

	# Print Status
	def Print(self):
		self.Pfmt("Interval",self.Interval)
		self.Pfmt("Next Event",self.NextEvent)
		self.Pfmt("Last Event",self.LastEvent)
		self.Pfmt("Started",self.Started)
		self.Pfmt("TriggerLimit",self.TriggerLimit)
		self.Pfmt("TriggerCount",self.TriggerCount)
		self.Pfmt("Lambda",self.Lambda)
		self.Pfmt("Tag",self.Tag)

	# Set NextEvent Time Stamp
	def Next(self):
		if self.Interval:
			if self.LastEvent:
				self.NextEvent = self.LastEvent + self.Interval
			else:
				self.NextEvent = self.Started + self.Interval

		if self.TriggerLimit > 0:
			self.TriggerCount += 1

	# Start the Clock
	def Start(self):
		self.Started = datetime.now()

		if self.Interval:
			self.Next()
		else:
			self.TriggerCount = 0

	# Set Last Event Time
	def Last(self,timestamp=None):
		if timestamp:
			self.LastEvent = timestamp
		else:
			self.LastEvent = datetime.now()

	# Check for Trigger Limit
	def TriggerLimitReached(self):
		return (self.TriggerLimit > 0 and self.TriggerCount >= self.TriggerLimit)

	# Check for Trigger (if True, internal has been met)
	def Trigger(self,*kwargs):
		flag = False

		if self.Interval and not self.NextEvent:
			self.Start()

		if (self.Interval and datetime.now() >= self.NextEvent) or (not self.Interval and self.TriggerLimit > 0):
			flag = True

			self.Last()

			if self.Lambda and kwargs:
				self.Lambda(*kwargs)
			else:
				self.Lambda()

			self.Next()

		return flag

#
# Global Triggers
#

debugTrigger = Periodic(trigger=1)

# App Level Helper Functions
class App(TitleValueFormatter,Taggable):
	# App Termination Flag
	TerminateFlag = "/tmp/psearch.terminate"

	# Init Instance
	def __init__(self):
		self.TerminateFlag = f"{self.TerminateFlag}.{os.getpid()}"

	# Print Status
	def Print(self):
		self.Pfmt("TerminateFlag",self.TerminateFlag)
		self.Pfmt("Tag",self.Tag)

	# Equivalent of Unix Touch (just create a file)
	def Touch(self,fname,data=None):
		tracer.Entering(self)

		if not os.path.exists(fname):
			with open(fname,"wt") as f_out:
				if data:
					f_out.write(data)
		tracer.Exitting(self)

	# Create Terminate Flag
	def CreateTerminateFlag(self):
		self.Touch(self.TerminateFlag)

	# Remove Termination Flag
	def RemoveTerminateFlag(self):
		if os.path.exists(self.TerminateFlag):
			os.remove(self.TerminateFlag)

	# Determine If Terminate Flag Exists
	def IfTerminate(self):
		tracer.Entering(self)

		flag = False

		if self.TerminateFlag and os.path.exists(self.TerminateFlag):
			flag = True

		tracer.Exitting(self)

		return flag

	# Calculate Elapsed Time From a Starting Time Stamp (using "now()")
	def ElapsedTime(self,started):
		tracer.Entering(self)

		finished = datetime.now()

		elapsed = finished - started

		tracer.Exitting(self)

		return elapsed

	# Find Meta
	def FindMeta(self,pattern,metas):
		"""Find Metas That Match 'pattern', Name,Nickname nd LogGroup searched for pattern"""
		tracer.Entering(self)

		progs = []
		patterns = []

		if type(pattern) is str:
			patterns = [ pattern ]
		else:
			patterns = pattern

		for expr in patterns:
			progs.append(re.compile(expr))

		found = [ ]
		groups = [ ]

		for prog in progs:
			for meta in metas:
				if meta.Name in patterns or prog.match(meta.Name):
					found = meta
				elif meta.Nickname in patterns or prog.match(meta.Nickname):
					found = meta
				elif meta.LogGroup in patterns or prog.match(meta.LogGroup) or prog.pattern == "all":
					groups.append(meta)

				if found:
					break

		if len(groups) > 0:
			found = groups

		tracer.Exitting(self)

		return found

	# Load Log Meta Info (deprecated 3/3/2022)
	def LoadLogMeta(self,filename):
		"""Load Log Meta Info File"""

		tracer.Entering(self)

		items = []

		try:
			sources = ET.parse(filename)

			root = sources.getroot()

			metas = root.findall("log")

			for meta in metas:
				items.append(LogMeta(meta))

		except Exception as err:
			Msg(f"An error occurred attempting to open {filename} : {err}")

		tracer.Exitting(self)

		return items

	# Attempt to Get Keyboard Input Without Blocking
	def GetChar(self):
		"""Get Keyboard Char if one Waiting, Otherwise, Continue"""

		returnChar = None

		fd = sys.stdin.fileno()

		# Backup and copy current terminal config
		oldterm = termios.tcgetattr(fd)
		newattr = termios.tcgetattr(fd)

		# Change terminal attribute[3] to negated ECHO and ICANON modes (i.e. clear them)
		newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
		# Set terminal to new mode
		termios.tcsetattr(fd,termios.TCSANOW,newattr)

		# Get Old Fcntl flags add O_NONBLOCK to make non blocking
		oldflags = fcntl.fcntl(fd,fcntl.F_GETFL)
		fcntl.fcntl(fd,fcntl.F_SETFL,oldflags | os.O_NONBLOCK)

		try:
			# Check for character, if none, we get an IOError and that is ok
			# If there is one, we get first char and we return it.
			# this try block is non-blocking so it returns immediately if
			# there is no char in the buffer
			try:
				returnChar = sys.stdin.read(1)
			except IOError: pass
		finally:
			# Restore old input mode on terminal
			termios.tcsetattr(fd,termios.TCSAFLUSH,oldterm)
			fcntl.fcntl(fd,fcntl.F_SETFL,oldflags)

		return returnChar

# Streamer Class
class Streamer(TitleValueFormatter,Taggable,ItemID):
	# Streamer Name
	Name = ""
	# Streamer Filename
	Filename = ""

	# Init Instance
	def __init__(self,name="",filename=""):
		self.Name = name
		self.Filename = filename
		ItemID.RandomID(self)

	# Print State
	def Print(self):
		self.Pfmt("ID",self.ID)
		self.Pfmt("Name",self.Name)
		self.Pfmt("Filename",self.Filename)
		self.Pfmt("Tag",self.Tag)

# Query Class
class Query(TitleValueFormatter,Taggable,ItemID):
	# Search Expression
	Expression = None
	# Matches Object
	Matches = None
	# Compiled Expression
	Program = None

	# Init Instance
	def __init__(self, expression = None):
		self.Expression = expression

		self.Compile()

		ItemID.RandomID(self)

	# Print State
	def Print(self):
		self.Pfmt("ID",self.ID)
		self.Pfmt("Expression",self.Expression)
		self.Pfmt("Matches",self.Matches)
		self.Pfmt("Program",self.Program)
		self.Pfmt("Tag",self.Tag)

	# Compile Expression
	def Compile(self):
		if self.Expression:
			self.Program = re.compile(self.Expression)

	# Check for matches
	def Match(self,buffer):
		self.Matches = None

		if self.Program:
			self.Matches = self.Program.match(buffer)

		return self.Matches

# Log Meta Prepackaged Query
class NamedQuery(Query):
	# Name of Query
	Name = None

	# Init Query Instance
	def __init__(self, xnode = None):
		self.Name = ""
		self.Expression = ""

		if not xnode is None:
			self.Read(xnode)

		ItemID.RandomID(self)

	# Print State
	def Print(self):
		self.Pfmt("Name",self.Name)
		Query.Print(self)

	# Read In XElement
	def Read(self,xnode):
		self.Name = xnode.attrib['name']
		self.Expression = xnode.text

		self.Compile()

	# Manually Set Named Query (really should modify Init to handle both cases)
	def Set(self,name,expression):
		self.Name = name
		self.Expression = expression

		self.Compile()

# Log Meta Data
class LogMeta(TitleValueFormatter,Taggable,ItemID):
	"""Log Source Meta Data Information Class"""

	DateExpression = "^(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})$"

	# Official Name of Log
	Name = None
	# Current Status of log, good or not good (i.e. being fed or stopped)
	Status = None
	# Primary Log Group (also in LogGroups)
	LogGroup = None
	# Log groups this log belongs to, CSV-Str
	LogGroups = None
	# Nickname of log (short name)
	Nickname = None
	# Description of Log
	Description = None
	# Log Owner
	Owner = None
	# IP Source of Log (Part of Name)
	Source = None
	# ???
	Targets = None
	# Parsing info (filename pattern)
	ParseInfo = None
	# ??
	Streamers = None
	# Named Queries
	Queries = None
	# Log Meta Comment
	Comment = None
	# Any Notes
	Notes = None

	# Init Instance
	def __init__(self, xnode = None):
		"""Init Instance"""

		super(Taggable,self).__init__()
		super(ItemID,self).__init__()
		super(TitleValueFormatter,self).__init__()

		self.Targets = list()
		self.ParseInfo = list()
		self.Queries = list()
		self.LogGroups = list()

		if not xnode is None:
			self.Read(xnode)

		ItemID.RandomID(self)

	# Default Print
	def Print(self):
		"""Pretty Print Instance"""

		self.Pfmt("ID",self.ID)
		self.Pfmt("Name",self.Name)
		self.Pfmt("Status",self.Status)
		self.Pfmt("Group",self.LogGroup)
		self.Pfmt("Nickname",self.Nickname)
		self.Pfmt("Description",self.Description)
		self.Pfmt("Owner",self.Owner)
		self.Pfmt("Source",self.Source)
		self.Pfmt("Comment",self.Comment)
		self.Pfmt("Notes",self.Notes)

		self.Pfmt("Groups","")

		for lgrp in self.LogGroups:
			self.Pfmt("\t",lgrp)

		self.Pfmt("Targets","")

		for target in self.Targets:
			self.Pfmt("\t",target)

		self.Pfmt("File Exprs","")

		for expr in self.ParseInfo:
			self.Pfmt("\t",expr)

		self.Pfmt("Streamers","")

		if self.Streamers:
			for streamer in self.Streamers:
				self.Pfmt("\t",f"{streamer.Name} {streamer.Filename}")
		else:
			self.Pfmt("Streamers","None")

		self.Pfmt("Queries","")

		for query in self.Queries:
			self.Pfmt("\t",f"{query.Name} {query.Expression}")

		self.Pfmt("Tag",self.Tag)

	# Read Data From XElement
	def Read(self,xnode):
		"""Read Log Meta Info From XNode"""

		self.Name=xnode.attrib['name']
		self.Nickname = xnode.attrib['nick']
		loggroups = xnode.attrib['group']

		self.LogGroups = list(loggroups.split(","))

		self.LogGroup = self.LogGroups[0]

		self.Status=xnode.attrib['status']
		self.Description=xnode.find("description").text
		self.Owner=xnode.find("owner").text
		self.Source=xnode.find("source").text
		self.Comment=xnode.find("comment").text
		self.Notes=xnode.find("notes").text

		for name in xnode.find("parse-info").findall("name"):
			self.ParseInfo.append(name.text)

		for target in xnode.find("targets").findall("target"):
			self.Targets.append([ target.attrib["comment"],target.text ])

		queries = xnode.find("queries")

		if queries:
			for query in queries.findall("query"):
				qry = NamedQuery(query)

				self.Queries.append(qry)

	# Unpack Packed Line
	def Unpack(self,lines):
		"""Unpack a Packed Line of Meta Info"""

		self.Name = lines.pop(0)
		self.Nickname = lines.pop(0)
		self.LogGroup = lines.pop(0)

		self.LogGroups = list(lines.pop(0).split(","))

		self.Status = lines.pop(0)
		self.Description = lines.pop(0)
		self.Owner = lines.pop(0)
		self.Source = lines.pop(0)
		self.Comment = lines.pop(0)
		self.Notes = lines.pop(0)

		line = lines.pop(0)

		while not line == "endmeta":
			prefix, sep, data = line.partition(":")

			if prefix == "name":
				self.ParseInfo.append(data)
			elif prefix == "target":
				self.Targets.append(data)
			elif prefix == "streamer":
				data = data.split(",")
				streamer = Streamer(data[0],data[1])
				self.Streamers.append(streamer)
			elif prefix == "query":
				data = data.split(",")
				query = NamedQuery(data[0],data[1])
				self.Queries.append(query)

			line = lines.pop(0)

	# Pack Meta for Network Transfer
	def Pack(self):
		"""Pack Meta Into a Dat Line for XFer"""

		lines = []

		lines.append(self.Name)
		lines.append(self.Nickname)
		lines.append(self.LogGroup)
		lines.append(",".join(self.LogGroups))
		lines.append(self.Status)
		lines.append(self.Description)
		lines.append(self.Owner)
		lines.append(self.Source)
		lines.append(self.Comment)
		lines.append(self.Notes)

		for name in self.ParseInfo:
			lines.append(f"name:{name}")

		for target in self.Targets:
			lines.append(f"target:{target}")

		for streamer in self.Streamers:
			lines.append(f"streamer:{streamer.Name},{streamer.Filename}")

		for query in self.Queries:
			lines.append(f"query:{query.Name},{query.Expression}")

		lines.append("endmeta")

		return lines

	# Return list of searchable fields
	def Searchables(self):
		"""Return a List of Searchable Fields"""

		lst = [ self.Nickname, self.LogGroup, self.Source, self.Owner ]

		lst.extend(self.LogGroups)

		return lst

	# Convert File Date YYYYMMDD into Date
	def ConvertStringToDate(self,dateString):
		"""Convert YYMMDD date string into Date"""


		# TODO: This can be fixed or use py_helper date conversions

		year = date.today().year
		month = date.today().month

		inlen = len(dateString)

		if inlen <= 2: # If just day, assume this year and this month
			dateString = "{:4}{:2}{:2}".format(str(year).zfill(4),str(month).zfill(2),str(dateString).zfill(2))
		elif inlen <= 4: # if month and day, assume this year
			dateString = "{:4}{:4}".format(str(year).zfill(4),str(dateString).zfill(4))

		match = re.match(self.DateExpression,dateString)

		computed_date = None

		if match != None:
			computed_date = date(int(match.group("year")),\
				int(match.group("month")), \
				int(match.group("day")))
		else:
			DbgMsg(f"Bad Date String : {dateString}")

		return computed_date

	# Convert Date into YYYYMMDD String
	def ConvertDateToString(self,inputDate):
		"""Convert Date Into YYYMMDD String"""

		# TODO : Replace with python built in functionality or py_helper date conversion facilities

		output = "{}{}{}".format(str(inputDate.year).zfill(4),str(inputDate.month).zfill(2),str(inputDate.day).zfill(2))

		return output

	# Get Archive Date
	def GetDate(self,filename=None,match=None):
		"""Get Date Encoded Into Filename (YYYYMMDD)"""

		date_cvt = None

		if filename:
			match = re.match(self.ParseInfo[0],os.path.basename(filename))

		if match:
			filedate = match.group("date")

			if filedate != None:
				date_cvt = self.ConvertStringToDate(filedate)
			else:
				date_cvt = ModificationTime(filename).date()

		return date_cvt

	# Get Matching Log Files
	def GetLogFiles(self,folder,startDate=None,endDate=None):
		"""Get Matching Log Files From Storage With Matching Dates"""

		matching_items = [ ]

		files = os.listdir(folder)

		for log in files:
			match = re.match(self.ParseInfo[0],log)

			if match:
				objLog = Log(os.path.join(folder,log),self)

				if startDate or endDate:
					archiveDate = objLog.EncodedDate

					# start set, no end
					# end set, no start
					# both start and end

					if (startDate and not endDate) and archiveDate >= startDate:
						# Hachacha
						matching_items.append(objLog)
					elif (not startDate and endDate) and archiveDate <= endDate:
						# Hachacha
						matching_items.append(objLog)
					elif archiveDate >= startDate and archiveDate <= endDate:
						# Hachacha...
						matching_items.append(objLog)
				else:
					matching_items.append(objLog)

		return matching_items

	# Check for Prepackaged Queries
	def HasQuery(self,name):
		qry = None

		for query in self.Queries:
			if query.Name == name:
				qry = query

				break

		return qry

	# Check for Prepackaged Streamer Filters
	def HasStreamer(self,name):
		strmr = None

		for streamer in self.Streamers:
			if streamer.Name == name:
				strmr = streamer
				break

		return strmr

	# Get Named Streamers
	def GetStreamers(self,names):
		strmrs = []

		for name in names:
			strmr = self.HasStreamer(name)

			if strmr:
				strmrs.append(strmr)

		return strmrs

	# Get Named Queries
	def GetQueries(self,names):
		qrys = []

		for name in names:
			query = self.HasQuery(name)

			if query:
				qrys.append(query)

		return qrys

	#
	# Static Members
	#

	# LoadMetas
	def LoadMetas(filename):
		"""Load Log Metas from a Log Meta XML Source File"""

		global tracer

		tracer.Entering("LogMeta::LoadMetas")

		metas = list()

		if os.path.exists(filename):
			try:
				sources = ET.parse(filename)

				root = sources.getroot()

				xmetas = root.findall("log")

				for meta in xmetas:
					metas.append(LogMeta(meta))

			except Exception as err:
				ErrMsg(err,f"An error occurred attempting to open {filename}")
		else:
			Msg(f"{filename} does not exist")

		tracer.Exitting("LogMeta::LoadMetas")

		return metas

# Log Class
class Log(TitleValueFormatter,Taggable,ItemID):
	"""Log File Instance Helper Class"""

	# List of encodings to try when decoding raw line
	EncodingsList = [ "utf-8", "latin-1", "utf-16" ]

	# Meta this log belongs to
	Meta = None
	# Filename of log
	Filename = None
	# Encoded Time Stamp of log
	EncodedDate = None
	# Size of file
	Size = 0
	# Output stream handle
	OpenHandle = None
	# Output File
	Output = None
	# Handling Hitory
	History = None
	# Output Ordering Flag
	WasOutput = False

	# Init Instance
	def __init__(self,filename = None,logMeta = None,output=None):
		# Log Meta this log belongs to
		self.Meta = logMeta
		# Name of log file
		self.Filename = filename

		self.History = []

		if filename:
			self.EncodedDate = self.Meta.GetDate(filename)
			self.Size = os.path.getsize(filename)
		else:
			self.EncodedDate = None
			self.Size = 0

		# Open Stream Handle for searching
		self.OpenHandle = None
		# Output stream or output file name
		self.Output = output
		# Just a tag
		self.Tag = None

		ItemID.RandomID(self)

		self.Track("created")

	# Default Print
	def Print(self):
		self.Pfmt("ID",self.ID)
		self.Pfmt("Encodings List",self.EncodingsList)
		self.Pfmt("Filename",self.Filename)
		self.Pfmt("Encoded Date",self.EncodedDate)
		self.Pfmt("Size",self.Size)
		self.Pfmt("Open Handle",self.OpenHandle)
		self.Pfmt("Output",self.Output)
		self.Pfmt("Was Out Yet",self.WasOutput)
		self.Pfmt("History Entries",len(self.History))

		self.Pfmt("Meta","")
		self.Meta.Print()

		self.Pfmt("Tag",self.Tag)

	# Print History List
	def PrintHistory(self):
		self.Pfmt("History","")

		for event in self.History:
			self.Pfmt("\t",event)

	# Add message to history tracker
	def Track(self,msg):
		tracer.Entering("Log::Track",False)

		self.History.append(f"{datetime.now()} - {msg}")

		tracer.Exitting("Log::Track")

	# Return Last Track Msg
	def LastTrack(self):
		tracer.Entering("Log::Print",False)

		tracer.Exitting("Log::Print (one statement in return)")

		return self.History[-1]

	# Track output file changes
	def SetOutput(self,output):
		tracer.Entering("Log::SetOutput",False)

		if output is None:
			self.Track("output set to None")
		elif output is sys.stdout:
			self.Track("output set to stdout")
		elif type(output) is io.BufferedWriter or type(output) is io.TextIOWrapper:
			self.Track("output set to file stream")
		elif output is str:
			self.Track(f"output set to {output}")
		else:
			self.Track(f"output to unknown type")

		self.Output = output

		tracer.Exitting("Log::SetOutput",False)

	# Convert Coded Date Into Date String
	def EncodedDateStr(self):
		return self.Meta.ConvertDateToString(self.EncodedDate)

	# Open Log File
	def Open(self):
		if ".gz" in self.Filename:
			self.Track("opened as gzip stream")
			self.OpenHandle = gzip.open(self.Filename,"rb")
		else:
			self.Track("opened as regular file stream")
			self.OpenHandle = open(self.Filename,"rb")

		return self.OpenHandle

	# Clean Up - Assume File Already Closed
	def Cleanup(self):
		self.OpenHandle = None

	# Close OpenHandle (if Allocated)
	def Close(self):
		if self.OpenHandle:
			self.Track("stream closed")
			self.OpenHandle.close()
			self.Cleanup()

	# Decode Raw Line
	def Decode(self,rawline):
		decoded = False
		used = None

		# Cycle through encodings to attempt to decode the line
		for encoding in self.EncodingsList:
			try:
				line = rawline.decode(encoding)
				used = encoding
				decoded = True
				break
			except:
				decoded = False

		return decoded, used, line

# Tokenized Message Packet (Verb\nData....
class MsgPacket:
	Verb = None
	Data = None
	Encoding = "utf-8"
	Succeeded = False

	# Init Instance
	def __init__(self,verb=None,data=None,encoding=None):
		if encoding:
			self.Encoding = encoding

		self.SetPacket(verb,data)

	# Fill Packet
	def SetPacket(self,verb=None,data=None,encoding=None):
		if encoding:
			self.Encoding = encoding

		if verb:
			self.Verb = verb

		if data:
			if type(data) is list:
				self.Data = "\n".join(data)
			else:
				self.Data = data

	# Send Message Packet
	def SendMsg(self,socket,verb=None,data=None,encoding=None):
		tracer.Entering("MsgPacket::SendMsg")

		self.SetPacket(verb,data,encoding=encoding)

		self.Succeeded = False

		encoded_pkt = ""

		if self.Verb and not self.Data:
			encoded_pkt = self.Verb
		elif self.Data and self.Verb:
			encoded_pkt += f"{self.Verb}\n{self.Data}"
		elif self.Data and not self.Verb:
			encoded_pkt = self.Data

		sze = len(encoded_pkt)

		if sze > 0:
			try:
				tracer.Inside("MsgPacket::SendMsg",postfix=f"Msg {self.Verb} {self.Data}")
				socket.send(sze.to_bytes(4,'little',signed=False))

				socket.send(bytes(encoded_pkt,self.Encoding))
				self.Succeeded = True
			except Exception as err:
				print(f"An error occurred sending packet : {err}")

		tracer.Exitting("MsgPacket::SendMsg")

		return self.Succeeded

	# Receive A Msg Packet
	def RecvMsg(self,socket):
		tracer.Entering("MsgPacket::RecvMsg")

		verb = "none"
		data = []
		self.Succeeded = False

		count = 0
		try_again = True

		while try_again and count < 4:
			try_again = False

			try:
				sze = socket.recv(4)

				packetSize = int.from_bytes(sze,'little',signed=False)

				raw_pkt = socket.recv(packetSize)

				decoded_pkt = raw_pkt.decode(self.Encoding).split("\n")

				self.Verb = decoded_pkt[0]

				if len(decoded_pkt) > 1:
					self.Data = decoded_pkt[1:]

				tracer.Inside("MsgPacket::RecvMsg",postfix=f"Msg {self.Verb} {self.Data}")

				self.Succeeded = True

			except BlockingIOError:
				try_again = True
				count += 1
				tm.sleep(0.25)
			except Exception as err:
				print(f"An error occurred receiving packet : {err}")


		tracer.Exitting("MsgPacket::RecvMsg")

		return self.Succeeded

# Networking Base Class
class NetworkingBase(TitleValueFormatter,Taggable,ItemID):
	Host = "0.0.0.0"
	Port = 0
	Socket = None
	SocketFamily = None
	SocketType = None
	Encoding = "utf-8"

	Debug = False		# Internal Debug Flag

	ACK = "ACK"		# Acknowledge Flag/Verb
	NACK = "NACK"		# No Acknowledge Flag/Verb
	FIN = "FIN"		# Operation FINished Flag/Verb
	RETRY = "retry"		# Retry operation
	NOREPLY = "noreply"	# No reply.... reply

	HELLO = "hello"		# Hello (ask for assignments) Verb
	ASSIGN = "assignments"	# Assignment Verb
	PATTERN = "patterns"	# Pattern Exchange
	NAMEDQUERY ="namedqueries"	# Named Query Exchange
	REJECTED = "rejected"	# Rejected verb
	COMPLETED = "completed"	# Completed Verb (assignment completed)

	FILE = "file"		# File Verb (send or receive)
	INFORM = "inform"	# Inform Verb (Generic message)
	PING = "ping"		# Ping Verb (ACK is reply)
	TERM = "term"		# Terminate Verb

	EOF = "EOF"		# End of File Verb
	CLOSE = "close"		# Close connection Verb

	# Init Class
	def __init__(self):
		self.Host = "0.0.0.0"
		self.Port = 0
		self.Socket = None
		self.SocketFamily = socket.AF_INET
		self.SocketType = socket.SOCK_STREAM
		self.Encoding = "utf-8"

		ItemID.RandomID(self)

	# Print State
	def Print(self):
		self.Pfmt("ID",self.ID)
		self.Pfmt("Host",self.Host)
		self.Pfmt("Port",self.Port)
		self.Pfmt("Socket",self.Socket)
		self.Pfmt("Socket Family",self.SocketFamily)
		self.Pfmt("Socket Type",self.SocketType)
		self.Pfmt("Encoding",self.Encoding)

		self.Pfmt("Tag",self.Tag)

	# Create New Socket
	def NewSocket(self):
		self.Socket = socket.socket(self.SocketFamily,self.SocketType)

	# Convert Bytes To String
	def ToString(self,data):
		value = str(data,encoding=self.Encoding)

		return value

	# Convert String To Bytes
	def ToBytes(self,data):
		value = bytes(data,encoding=self.Encoding)

		return value

	# Who am I talking to
	def WhoAmITalkingTo(self,sock=None):
		if sock is None:
			sock = self.Socket

		return sock.getpeername()

	# Get Connection Info (i.e. my IP)
	def WhoAmI(self,sock=None):
		if sock is None:
			sock = self.Socket

		return sock.getsockname()

	# Set Timeout On Socket
	def SetTimeout(self,interval,sock=None):
		if sock is None:
			sock = self.Socket

		sock.settimeout(interval)

	# Get Timeout on Socket
	def GetTimeout(self,sock=None):
		if sock is None:
			sock = self.Socket

		return sock.gettimeout()

	# Set Blocking Behavior on Socket
	def SetBlocking(self,blocking,sock=None):
		tracer.Entering("NetworkingBase::SetBlocking",postfix=f"{blocking}")

		if sock is None:
			sock = self.Socket

		sock.setblocking(blocking)

		tracer.Exitting("NetworkingBase::SetBlocking")

	# Get Current Blockign Mode On Socket
	def GetBlocking(self,sock=None):
		tracer.Entering("NetworkingBase::GetBlocking")

		flag = False

		if sock is None:
			sock = self.Socket

		flag = sock.gettimeout() == 0

		tracer.Exitting("NetworkingBase::GetBlocking")

		return flag

	# Bind To Server Port (for listening Servers)
	def Bind(self,blocking=True):
		self.NewSocket()

		self.Socket.bind((self.Host,self.Port))

		self.SetBlocking(blocking)

	# Listen (Bind if needed, assumes listening server)
	def Listen(self,backlog=5,blocking=True):
		if not self.Socket:
			self.Bind(blocking=blocking)

		self.Socket.listen(backlog)

	# Send Using Current Connection
	def Send(self,msgpkt,connection=None):
		tracer.Entering("NetworkingBase::Send")

		if connection is None:
			DbgMsg("Networking::Send connection supplied was None")
			connection = self.Socket

		succeeded = msgpkt.SendMsg(connection)

		tracer.Exitting("NetworkingBase::Send")

		return succeeded

	# Receive Data
	def Receive(self,connection=None):
		tracer.Entering("NetworkingBase::Receive")

		if connection is None:
			connection = self.Socket

		msgpkt = MsgPacket()

		succeeded = msgpkt.RecvMsg(connection)

		return msgpkt

	# Send File
	def SendFile(self,filename,connection=None):
		tracer.Entering("NetworkingBase::SendFile")

		if not connection:
			connection = self.Socket

		completed = False

		fsize = os.path.getsize(filename)

		self.PackMsg(self.FILE,str(fsize),sock=connection)

		verb, data = self.WaitReply(sock=connection,unpack=True)

		if verb == self.ACK:
			with open(filename,"rb") as f_in:
				buff = f_in.read(4096)

				self.Send(buffer)

		verb, data = self.WaitReply(sock=connection,unpack=True)

		if verb == self.ACK:
			completed = True

		tracer.Exitting("NetworkingBase::SendFile")

		return completed

	# Receive File
	def ReceiveFile(self,filename,connection=None):
		tracer.Entering("NetworkingBase::ReceiveFile",postfix=f"{filename}")

		if not connection:
			connection = self.Socket

		completed = False

		verb, data = self.UnpackMsg(sock=connection)

		if verb == self.FILE:
			size = int(data)

			self.PackMsg(self.ACK,"",sock=connection)

			tally = 0

			with open(filename,"wb") as f_out:
				while tally < size:
					buffer = self.Receive(connection=connection,buffsize=4096,decode=False)

					tally += len(buffer)

					if len(buffer) == 0:
						tally = size

				self.PackMsg(self.ACK,"",sock=connection)

				completed = True

		tracer.Exitting("NetworkingBase::ReceiveFile")

		return completed

	# Wait For Reply From Server
	def WaitReply(self,sock=None):
		tracer.Entering("NetworkingBase::WaitReply")

		if sock is None:
			sock = self.Socket

		msgpkt = MsgPacket()

		succeeded = msgpkt.RecvMsg(sock)

		tracer.Exitting("NetworkingBase:WaitReply")

		return msgpkt

	# HELLO Helper
	def SendHELLO(self,maxthreads,metacount=0,sendPatterns=0,sock=None):
		tracer.Entering("NetworkingBase::SendHELLO")

		if sock is None:
			sock = self.Socket

		msgpkt = MsgPacket(self.HELLO,[ str(os.getpid()), str(maxthreads), str(metacount), str(sendPatterns) ])

		succeeded = msgpkt.SendMsg(sock)

		tracer.Exitting("NetworkingBase::SendHELLO")

		return succeeded

	# ACK Helper Function
	def SendACK(self,sock=None,data=None):
		tracer.Entering("NetworkingBase::SendACK")

		if sock is None:
			sock = self.Socket

		msgpkt = MsgPacket()

		if data is None:
			msgpkt.SetPacket(self.ACK, str(os.getpid()))
		else:
			msgpkt.SetPacket(self.ACK, data)

		succeeded = msgpkt.SendMsg(sock)

		tracer.Exitting("NetworkingBase::SendACK")

		return succeeded

	# NACK Helper Function
	def SendNACK(self,sock=None):
		tracer.Entering("NetworkingBase::SendNACK")

		if sock is None:
			sock = self.Socket

		msgpkt = MsgPacket(self.NACK, str(os.getpid()))

		succeeded = msgplt.SendMsg(sock)

		tracer.Exitting("NetworkingBase::SandNACK")

		return succeeded

	# FIN (Operation finished) Helper Function
	def SendFIN(self,sock=None):
		tracer.Entering("NetworkingBase::SendFIN")

		if sock is None:
			sock = self.Socket

		msgpkt = MsgPacket(self.FIN,str(os.getpid()))

		msgpkt.SendMsg(sock)

		tracer.Exitting("NetworkingBase::SendFIN")

	# Send Terminate Flag
	def SendTERM(self,sock=None):
		tracer.Entering("NetworkingBase::SendTERM")

		if sock is None:
			sock = self.Socket

		msgpkt = MsgPacket(self.TERM, str(os.getpid()))

		succeeded = msgpkt.SendMsg(sock)

		tracer.Exitting("NetworkingBase::SendTERM")

		return succeeded

	# Send Inform
	def SendINFORM(self,payload,sock=None):
		tracer.Entering("NetworkingBase::SendINFORM")

		if sock is None:
			sock = self.Socket

		msgpkt = MgPacket(self.INFORM,payload)

		succeeded = msgpkt.SendMsg(sock)

		tracer.Exitting("NetworkingBase::SendINFORM")

		return succeeded

	# Send Ping
	def SendPING(self,sock=None,payload=None):
		tracer.Entering("NetworkingBase::SendPING")

		if sock is None:
			sock = self.Socket

		block_status = self.GetBlocking(sock)

		if payload is None:
			payload = str(os.getpid())

		msgpkt = MsgPacket(self.PING, payload)

		succeeded = msgpkt.SendMsg(sock)

		if not block_status:
			self.SetBlocking(True,sock=sock)

		msgpkt = self.WaitReply(sock=sock)

		if not block_status:
			self.SetBlocking(block_status,sock=sock)

		tracer.Exitting("NetworkingBase::SendPING")

		return msgpkt

	# Accept Incoming Connection
	def Accept(self):
		tracer.Entering("NetworkingBase::Accept")

		data = None

		connection, remoteAddress = self.Socket.accept()

		msgpkt = MsgPacket()

		succeeded = msgpkt.RecvMsg(connection)

		tracer.Inside("NetworkingBase:Accept",postfix=f"Accept Succeeded {succeeded} {msgpkt.Verb}")

		tracer.Exitting("NetworkingBase::Accept")

		return connection, remoteAddress, msgpkt

	# Close Open Socket
	def Close(self,sock=None):
		tracer.Entering("NetworkingBase::Close")

		if sock is None:
			sock = self.Socket

		if sock:
			sock.shutdown(socket.SHUT_RDWR)
			sock.close()

			if sock is self.Socket:
				self.Socket = None

		tracer.Exitting("NetworkingBase::Close")

# Remove Assignment Class
class RemoteAssignment(TitleValueFormatter,Taggable,ItemID):
	Log = None
	Address = None
	ProcessId = None

	# Init Instance
	def __init__(self,log=None,address=None,pid=None):
		self.Log = log
		self.Address = address
		self.ProcessID = pid

		ItemID.RandomID(self)

	# Print Status
	def Print(self):
		self.Pfmt("ID",seld.ID)
		self.Pfmt("Address",self.Addres)
		self.Pfmt("Process ID",self.ProcessId)
		self.Pfmt("Tag",self.Tag)
		self.Log.Print()

# Server Class
class SearchServer(NetworkingBase,App):
	# Client Connections
	Connections = None
	# Terminate Flag
	TerminateRemoteWorkers = False
	# Patterns Sent Flag
	PatternsSent = False

	# Init Server
	def __init__(self,host=None,port=None,socketFamily=socket.AF_INET,socketType=socket.SOCK_STREAM,encoding=None):
		# Prep
		if host:
			self.Host = host
		if port:
			self.Port = port

		if encoding:
			self.Encoding = encoding

		self.Connections = []
		self.SocketFamily = socketFamily
		self.SocketType = socketType

		self.Socket = self.Bind()
		self.Listen(backlog=5)

		self.SetBlocking(False)

	# Print Basic  Info About Search Manager
	def Print(self):
		self.Pfmt("Connections",len(self.Connections))
		self.Pfmt("Term Flag",self.TerminateRemoteWorkers)
		NetworkingBase.Print(self)
		App.Print(self)

	# Inspect Field
	def Inspect(self,field,prefix=None,postfix=None,limit=-1,filter=None):
		value = ""
		ex = None

		if filter:
			ex = re.compile(filter)

		if field in self.__dict__:
			if type(self.__dict__[field]) is str:
				value = (prefix if prefix else "") + self.__dict__[field] + (postfix if postfix else "")
			elif type(self.__dict__[field]) is list:
				value = (prefix if prefix else "")

				count=0
				for item in self.__dict__[field]:
					if ex:
						if ex.match(str(item)):
							value += f"{item}\n"

					count += 1

					if limit > 0 and count >= limit:
						break

				value += (postfix if postfix else "")
		else:
			value = f"{field} not in this object"

		return value

	# Add A Connection To Live Connections List
	def AddConnection(self,connection):
		tracer.Entering("SearchServer::AddConnection",postfix=f"Last Caller : {tracer.LastCalled}")

		self.Connections.append(connection)

		tracer.Exitting("SearchServer::AddConnection")

	# Remove A Connection From List
	def RemoveConnection(self,connection):
		tracer.Entering("SearchServer::RemoveConnection")

		if connection in self.Connections:
			self.Connections.remove(connection)
		else:
			DbgMsg(f"Asked to remove {connection}, did not find it")

		tracer.Exitting("SearchServer::RemoveConnection")

	# Accept Waiting Data And Crack Message
	def AcceptMsg(self,sock=None):
		connection, remoteAddress, msgpkt = self.Accept()

		self.SetBlocking(False,sock=connection)

		self.AddConnection(connection)

		# connection, remAddr, verb, data
		return (connection, remoteAddress, msgpkt )

	# Pack Metas for Transfer
	def PackMetas(self,metas):
		tracer.Entering("SearchServer::PackMetas")

		lines = []

		for meta in metas:
			lines.extend(meta.Pack())

		tracer.Exitting("SearchServer::PackMetas")

		return lines

	# Send Patterns
	def SendPatterns(self,patterns,sock):
		tracer.Entering("SearchServer::SendPatterns")

		payload = []

		for pattern in patterns:
			payload.append(pattern)

		msgpkt = MsgPacket(self.PATTERN,payload)

		succeeded = msgpkt.SendMsg(sock)

		msgpkt = self.WaitReply(sock=sock)

		tracer.Exitting("SearchServer::SendPatterns")

		return msgpkt

	# Send Named Queries
	def SendNamedQueries(self,namedQueries,sock):
		tracer.Entering("SearchServer::SendNamedQueries")

		payload = []

		for query in namedQueries:
			payload.append(f"{query}")

		msgpkt = MsgPacket(self.NAMEDQUERY,payload)

		succeeded = msgpkt.SendMsg(sock)

		msgpkt = self.WaitReply(sock=sock)

		tracer.Exitting("SearchServer::SendNamedQueries")

		return msgpkt

	# Send Assignment Helper Function
	def SendAssignment(self,log,sock):
		tracer.Entering("SearchServer::SendAssignment")

		payload = [ ]

		# Payload Construction : Format (per line) Meta Name, Filename, Output, patterns, one per line
		payload.append(log.Meta.Name)
		payload.append(log.Filename)
		payload.append(log.Output if log.Output else "")

		log.Track("Sent to remote thread as assignment")

		msgpkt = MsgPacket(self.ASSIGN,payload)

		succeeded = msgpkt.SendMsg(sock)

		tracer.Exitting("SearchServer::SendAssignment")

		return succeeded

	# Send Assignments
	def SendAssignments(self,assignments,patterns=None,namedQueries=None,sock=None):
		postfix = str(self.WhoAmITalkingTo(sock or self.Socket))

		tracer.Entering("SearchServer::SendAssignments",postfix=postfix)

		DbgMsg(f"Sending Assignments {postfix}")

		client_cancelled = False

		# While we are sending the assignments, we want blocking
		#self.SetBlocking(True,sock=sock)

		try:
			# Send Patterns and named queries
			if patterns:
				msgpkt = self.SendPatterns(patterns,sock)
			if namedQueries:
				msgpkt = self.SendNamedQueries(namedQueries,sock)

			for log in assignments:
				DbgMsg(f"Sending An Assignment {log.Filename}")

				self.Tag = ( log, "SearchServer::SendAssignments" )

				verb = self.ACK

				self.SendAssignment(log,sock)

				msgpkt = self.WaitReply(sock=sock)

				if msgpkt.Verb == self.NACK:
					client_cancelled = True
					break

			# Tell Client we are done
			if not client_cancelled:
				succeeded = self.SendFIN(sock=sock)
		finally:
			# Restore Non Blocking
			#self.SetBlocking(False,sock=sock)
			pass

		tracer.Exitting("SearchServer::SendAssignments")

	# Clear Dead Sockets
	def ClearDeadConnections(self):
		tracer.Entering("SearchServer::ClearDeadConnections")

		deadsockets = []

		for sock in self.Connections:
			if sock.fileno() < 0:
				deadsockets.append(sock)

		for sock in deadsockets:
			self.Connections.remove(sock)

		tracer.Exitting("SearchServer::ClearDeadConnections")

	# Select On Sockets
	def Select(self):
		tracer.Entering("SearchServer::Select")

		sockList = []

		# Always Listen to Server Socket
		if self.Socket:
			sockList.append(self.Socket)

		deadSockets = []

		# Listen to Live Sockets
		for sock in self.Connections:
			if sock:
				# Try to sort out some problematic sockets.... these should not be here.... but nobodies perfect
				if sock.fileno() > -1:
					sockList.append(sock)
				else:
					# TODO : Debug
					# This should not be needed, server should remove sockets
					# that disconnect
					deadSockets.append(sock)

		if len(deadSockets) > 0:
			DbgMsg("****** Removing Dead Socket in Select, WHY?")
			for deadSocket in deadSockets:
				self.RemoveConnection(deadSocket)

		readable = []
		writable = []
		exceptional = []

		if len(sockList) > 0:
			readable, writable, exceptional = select.select(sockList, sockList, sockList, 1 )

		tracer.Exitting("SearchServer::Select")

		return readable, writable, exceptional

	# Possibly deprecated
	# Remove Assignment From Assignments List
	def RemoveAssignment(self,connection,item,remoteAssignments):
		tracer.Entering("SearchServer::RemoveAssignment")

		for assignment in remoteAssignments:
			if connection in assignment:
				if item in assignment[1]:
					assignment.remove(item)
				if len(assignment[1]) == 0:
					remoteAssignments.remove(assignment)

				break

		tracer.Exitting("SearchServer::RemoveAssignment")

	# Server Processing Loop
	def Process(self,metas,logList,patterns,namedQueries,streamers,remoteAssignments):
		tracer.Entering("SearchServer::Process")

		completed = []

		callerids_tl = [ "MsgPacket::RecvMsg", \
		"MsgPacket::SendMsg", \
		"NetworkingBase::Accept", \
		"NetworkingBase::WaitReply", \
		"NetworkingBase::Receive", \
		"NetworkingBase::SendACK", \
		"NetworkingBase::SendFIN", \
		"NetworkingBase::SendPING", \
		"NetworkingBase::SetBlocking" ]

		tracer.SetTraceState(callerids_tl,"none")

		# Get sockets with waiting data, we ignore the writable ones and the exceptional ones.... for now.
		readable, writeable, exceptional = self.Select()

		# If we have some readables, time to start servicing them.
		if len(readable) > 0:
			for ready in readable:
				logLen = len(logList)

				verb = None
				data = None

				msgpkt = MsgPacket()

				# If there is a new connection on the server socket, handle it.
				if ready is self.Socket:
					# Server class handles adding connection to list here
					connection,remoteAddress,msgpkt = self.AcceptMsg()

					ready = connection
					self.SetBlocking(True,ready)

					self.AddConnection(connection)

					DbgMsg(f"Remote client connected {ready.getpeername()} with {msgpkt.Verb}")
				else:
					self.SetBlocking(True,ready)
					msgpkt.RecvMsg(ready)
					DbgMsg(f"Remote client has something to say : {msgpkt.Verb}")


				if msgpkt.Verb == self.HELLO:
					# Hello is a default request for assignments, the thread count tells you how many
					# The remote client wants. It does not necessarily reflect the total number of
					# running threads or CPUs.... just what the remote worker wants.

					IPAddress = ready.getpeername()
					PIDOf = msgpkt.Data[0]
					threads = int(msgpkt.Data[1])
					rmMetas = int(msgpkt.Data[2])
					sendPatterns = int(msgpkt.Data[3])

					# If rmMetas (Remote Metas) is zero, it means we have to pack the
					# Metas collection for transfer over the network connection
					if rmMetas == 0:
						data = self.PackMetas(metas)
					else:
						data = ""

					# Determine the lesser of, how many assignments the remote work wants
					# and how many are available
					threads = min(threads,logLen)

					# If the number of requested assignments and available assignments is non-zero,
					# Then assign something
					if threads > 0 and logLen > 0:
						# If rmMetas is 0, we packed in the metas to the ACK Response
						self.SendACK(sock=ready,data=data)

						# Extract "threads" count logs from log list
						items = logList[-threads:]

						for item in items:
							remoteAssignment = RemoteAssignment(item,IPAddress,PIDOf)
							remoteAssignments.append(remoteAssignment)
							logList.remove(item)

						assignments = []
						assignments.extend(items)

						ptns = (patterns if sendPatterns > 0 else None)
						nqry = (namedQueries if sendPatterns > 0 else None)

						callerids = [ "SearchServer::SendAssignments", \
							"SearchServer::SendAssignment", \
							"NetworkingBase::WaitReply", \
							"NetworkingBase::Receive", \
							"NetworkingBase::SendACK", \
							"NetworkingBase::SendFIN", \
							"NetworkingBase::SetBlocking", \
							"MsgPacket::SendMsg", \
							"MsgPacket::RecvMsg" ]
						tracer.SetTraceState(callerids,"none")

						self.SendAssignments(assignments,ptns,nqry,sock=ready)

						tracer.SetTraceState(callerids,"all")
					else:
						# If there are no assignments, an empty assignment list means the remote
						# worker can terminate
						self.SendNACK(sock=ready)

				elif msgpkt.Verb == self.REJECTED:
					# add assignments back into logList
					# remove from remoteAssignments
					DbgMsg(f"Rejected {data}")

					while msgpkt.Verb != self.FIN:
						for item in remoteAssignments:
							if item.Log.Filename == data:
								item.Track("rejected by remote thread")
								remoteAssignments.remove(item)
								logList.append(item.Log)
								break

						self.SendACK(ready)
						msgpkt = self.WaitReply(ready)

				elif msgpkt.Verb == self.COMPLETED:
					# if fname add to list, if network, dump to file, add to list
					# Data,output == log fname

					filename = msgpkt.Data[0]
					output = msgpkt.Data[1]
					PIDOf = int(msgpkt.Data[2])

					DbgMsg(f"Item completed : {filename} - {output}")

					log = None

					# Remove From Remote Assignments since it's done
					for item in remoteAssignments:
						if item.Log.Filename == filename:
							log=item.Log
							remoteAssignments.remove(item)
							break

					if log:
						if output == "" or not os.path.exists(output):
							log.Track("remote thread changed output filename or will transfer over network")
							# output will be passed back over the connection
							# place in tmp file, return in completed list
							output = TmpFilename(prefix="logsearch_",postfix=f"_{log.EncodedDateStr()}")

							log.SetOutput(output)

							self.ReceiveFile(log.Output,connection=ready)

						completed.append(log)
						log.Track("search completed by remote thread")
					else:
						DbgMsg("***** Item completed but not found in remoteAssignments")

				elif msgpkt.Verb == self.INFORM:
					# Client sent a generic message
					Msg("Client is Informing us :\n{}".format(msgpkt.Data.join(",")))

				elif msgpkt.Verb == self.PING:
					if self.TerminateRemoteWorkers:
						DbgMsg(f"Telling {ready.getpeername()} to terminate")

						IPAddress = ready.getpeername()
						PIDOf = int(msgpkt.Data)

						removables = []
						# Remove ALL assignments for this Process and Address
						for item in remoteAssignments:
							if item.Address == IPAddress and item.ProcessID == PIDOf:
								removables.append(item)

						for item in removables:
							remoteAssignments.remove(item)

						self.SendTERM(sock=ready)
					else:
						self.SendACK(sock=ready)

				elif msgpkt.Verb == self.CLOSE and ready != self.Socket:
					# Client is done with this conversation
					DbgMsg(f"Client {ready.getpeername()} is closing the connection")

					self.Close(ready)
					self.RemoveConnection(ready)

				elif msgpkt.Verb != self.ACK:
					# Ignore this, but it probably indicates a failure someplace
					DbgMsg(f"When receiving from a live connection an unexpected verb was returned : {str(msgpkt.Verb)} {str(msgpkt.Data)}")

				self.SetBlocking(False,ready)

		tracer.SetTraceState(callerids_tl,"all")

		tracer.Exitting("SearchServer::Process")

		return completed

# Client Class
class RemoteSearcher(NetworkingBase,App):
	# Connected Flag
	Connected = None
	# Patterns Received Flag
	PatternsReceived = False

	# Init Client
	def __init__(self,host=None,port=DefaultPort,socketFamily=socket.AF_INET,socketType=socket.SOCK_STREAM,encoding=None):
		if host:
			self.Host = host
		if port:
			self.Port = port

		if encoding:
			self.Encoding = encoding

		self.SocketFamily = socketFamily
		self.SocketType = socketType

		self.Socket = socket.socket(self.SocketFamily,self.SocketType)

		self.Connected = False

	# Print State
	def Print(self):
		self.Pfmt("Connected",self.Connected)
		self.Pfmt("PatternsReceived",self.PatternsReceived)

		NetworkingBase.Print(self)
		App.Print(self)

	# Connect To Remote Server
	def Connect(self,waitfor=None,retry=True):
		tracer.Entering("RemoteSearcher::Connect")

		if waitfor is None:
			waitfor = DefaultConnectionWait

		started = datetime.now()

		self.Connected = False

		if self.Socket is None:
			self.NewSocket()

		while retry:
			try:
				self.Socket.connect((self.Host,self.Port))

				self.Connected = True
				break
			except ( socket.timeout, ConnectionRefusedError ) as trouble:
				current = datetime.now()

				delta = current - started

				if waitfor and delta.seconds > waitfor:
					DbgMsg(f"Server {self.Host}, not responding")
					retry = False
				else:
					tm.sleep(0.5)
			except KeyboardInterrupt:
				break
			except OSError as oserr:
				DbgMsg("Attempt to connect with an open socket, closing and creating a new one")
				self.Close()
				self.NewSocket()
			except Exception as err:
				Msg("RemoteSearcher::Connect - {} {}".format(type(err),err))

		tracer.Exitting("RemoteSearcher::Connect")

		return self.Connected

	# Complete Ping Solution
	def Ping(self,payload=None):
		tracer.Entering("RemoteSearcher::Ping")

		msgpkt = MsgPacket(self.NACK,"")

		if self.Connected:
			msgpkt = self.SendPING(payload=payload)

		tracer.Exitting("RemoteSearcher::Ping")

		return msgpkt

	# Send Inform message
	def Inform(self,msg):
		tracer.Entering("RemoteSeacher::Inform")

		if self.Connected:
			self.SendINFORM(payload)

		tracer.Exitting("RemoteSearcher::Inform")

	# Unpack Requested Metas
	def UnpackMetas(self,data):
		tracer.Entering("RemoteSearcher::UnpackMetas")

		metas = []

		while len(data) > 0:
			meta = LogMeta()
			meta.Unpack(data)

			metas.append(meta)

		tracer.Exitting("RemoteSearcher::UnpackMetas")

		return metas

	# Disconnect - Alias - Call Close
	def Disconnect(self):
		tracer.Entering("RemoteSearcher::Disconnect")

		msgpkt = MsgPacket(self.CLOSE,str(os.getpid()))

		msgpkt.SendMsg(self.Socket)

		self.Close()

		self.Connected = False

		tracer.Exitting("RemoteSearcher::Disconnect")

	# Send String To Server (assumes socket already connected)
	def SendStr(self,msg):
		self.Socket.sendall(bytes(msg,encoding=self.Encoding))

	# Check for Assignment File Availability
	def CheckAvailability(self,assignments,altmount=None):
		tracer.Entering("RemoteSearcher::CheckAvailability")

		available = []
		rejected = []

		basename = None
		newfname = None

		for log in assignments:
			if altmount:
				basename = os.path.basename(log.Filename)
				newfname = os.path.join(altmount,basename)

			if os.path.exists(log.Filename):
				log.Track("log is available and will be processed")
				available.append(log)
			elif altmount and os.path.exists(newfname):
				log.Track("log not available through provided path, but is available from an alternate mount, changing output filename")

				original = ( log.Filename, log.Output )
				log.Tag = original

				log.Filename = newfname

				# Deprecated, Output now set by CreateWorker and respects TempSpace specs
				#oldoutput = os.path.basename(log.Output)

				#log.SetOutput(os.path.join(altmount,oldoutput))
				available.append(log)
			else:
				log.Track("log is not available,rejected")
				rejected.append(log)

		tracer.Exitting("RemoteSearcher::CheckAvailability")

		return available, rejected

	# Connect to server, ask for assignments
	def GetAssignments(self,metas,threadCount=1):
		tracer.Entering("RemoteSearcher::GetAssignments")

		callerids = [ "NetworkingBase::SendHELLO", \
			"NetworkingBase::WaitReply", \
			"RemoteSearcher::UnpackMetas", \
			"RemoteSearcher::CheckAvailability", \
			"RemoteSearcher::Reject", \
			"RemoteSearcher::UnpackIncomingMsg", \
			"NetworkingBase::UnpackMsg", \
			"NetworkingBase::Receive", \
			"RemoteSearcher::Disconnect", \
			"MsgPacket::SendMsg", \
			"MsgPacket::RecvMsg" ]
		tracer.SetTraceState(callerids,"none")

		assignments = []
		patterns = []
		namedQueries = []

		DbgMsg(f"Attempting get assignments : threads = {threadCount}")

		try:
			DbgMsg("Sending Hello...")

			# Tell Server We Want Assignments
			self.SendHELLO(threadCount,len(metas),(0 if self.PatternsReceived else 1))

			DbgMsg("Waiting for reply....")

			# Wait for an ACK to continue
			msgpkt  = self.WaitReply()

			DbgMsg(f"Received {msgpkt.Verb}")

			if msgpkt.Verb == self.NACK:
				# Bummer

				DbgMsg("Received NACK, no assignments to be given")
				return assignments, patterns, namedQueries

			if msgpkt.Verb == self.TERM:
				DbgMsg("Received TERM, shit, can't handle this")
				return assignments, patterns, namedQueries

			# If we sent "0" in the metas field to the server, we can expect
			# that metas were packed into the ACK reply.
			if len(metas) == 0:
				metas.extend(self.UnpackMetas(data))

			msgpkt.Verb = self.ASSIGN

			validVerbs = [ self.ASSIGN, self.PATTERN, self.NAMEDQUERY ]
			termVerbs = [ self.FIN, self.TERM ]

			# For Patterns and NamedQueries, the server will only send them once.
			while msgpkt.Verb in validVerbs:
				patterns = [ ]

				msgpkt.RecvMsg(self.Socket)

				verb = msgpkt.Verb
				lines = msgpkt.Data

				if verb == self.ASSIGN:
					DbgMsg("Received assignment")

					meta = app.FindMeta(lines[0],metas)
					log = Log(lines[1],meta)
					log.Output = lines[2]

					assignments.append(log)
				elif verb == self.PATTERN:
					for pattern in lines:
						patterns.append(pattern)

				elif verb == self.NAMEDQUERY:
					for namedQuery in lines:
						namedQueries.append(namedQuery)

				elif not verb in validVerbs and not verb in termVerbs:
					DbgMsg(f"Unexpected verb received = {verb}")

				if not verb in termVerbs:
					self.SendACK()

			# Once complete, server does not expect an ACK

			DbgMsg("{} assignments received".format(len(assignments)))
		except Exception as err:
			DbgMsg("Error Recieved while trying to receive assignment(s) - {}".format(err))

		if len(patterns) > 0 or len(namedQueries) > 0:
			self.PatternsReceived = True

		tracer.SetTraceState(callerids,"all")

		tracer.Exitting("RemoteSearcher::GetAssignments")

		return assignments, patterns, namedQueries

	# Send Back Rejected Assignments
	def Reject(self,assignments):
		tracer.Entering("RemoteSearcher::Reject")

		succeeded = True

		for assignment in assignments:
			msgpkt = MsgPacket(self.REJECTED,assignment.Filename)

			msgpkt.Send(self.Socket)

			msgpkt = self.WaitReply()

			if msgpkt.Verb != self.ACK:
				succeeded = False
				break

		self.SendFIN()

		tracer.Exitting("RemoteSearcher::Reject")

		return succeeded

	# Send Informational Packet Back To Server
	def Inform(self,msg):
		msgpkt = MsgPacket(self.INFORM,msg)

		msgpkt.Send(self.Socket)

	# Tell Server An Assignment Has Been Completed
	def Completed(self,log):
		tracer.Entering("RemoteSearcher::Completed")

		# Log.Output original or other, if other gets blank output then file transfer
		# if Tag is not None, then path was changed, Tag is the original
		filename = log.Filename
		output = log.Output

		if log.Tag:
			DbgMsg("Using Tag in RS:Completed...why")
			filename = log.Tag[0]
			output = log.Tag[1]

		msgpkt = MsgPacket(self.COMPLETED,[ filename, output, str(os.getpid()) ])

		msgpkt.SendMsg(self.Socket)

		# If output == "" then we have to transfer over net
		# This code here is does not work, output will never be ""
		# We have to know *IF* the provided path and altmount failed
		# Then output will be the local path to the output file
		# Then IT can be sent back
		# TODO: Fix
		if output == "":
			DbgMsg("Sending file???")
			self.SendFile(output)

		tracer.Exitting("RemoteSearcher::Completed")

# Search and Search Server/Client Management
class SearchManager(App):
	# Storage Locations
	StorageLocations = [ ]
	# Log Metas
	LogMetas = []
	# In Scope Logs
	Logs = []
	# Patterns pulled in from Cmd Line
	Patterns = []
	# Named Queries pulled in from Cmd Line
	NamedQueries = []
	# Streamers
	Streamers = []
	# Max Threads for this host
	MaxThreads = 1
	# Potential limit on lines pulled from each file
	LineLimit = -1
	# Active Thread List
	Threads = []
	# List of completed log searches with output
	OutputQueue = []
	# Output Ordering Map
	OutputOrdering = []
	# Thread Executor
	Executor = None
	# Search Server
	Server = None
	# Client Searcher
	Client = None
	# Remote Assignments List
	RemoteAssignments = []
	# List of Completed Logs (local and remote)
	CompletedLogs = []
	# Index Flag (deprecated, never going to use)
	IndexOn = None
	# Cmd Line Args (ArgParser)
	Arguments = None

	# Stats Data

	# Completed Threads
	CompletedThreadCount = 0
	# Line Count (Lines read from log files)
	LineCount = 0
	# Match Count
	MatchCount = 0

	# Init Instance
	def __init__(self,storage_locations = None,log_metas=None):
		# Hack for LogMetas
		global LogMetas

		if storage_locations:
			self.StorageLocations.extend(storage_locations)

		if log_metas:
			self.LogMetas = log_metas
		else:
			self.LogMetas = LogMetas

		self.SetMaxThreads()

		self.InitExecutor(self.MaxThreads)

	# Print Basic  Info About Search Manager
	def Print(self):
		self.Pfmt("Storage Locations",self.StorageLocations)
		self.Pfmt("Log Metas",len(self.LogMetas))
		self.Pfmt("Logs",len(self.Logs), postfix="logs")
		self.Pfmt("Patterns",self.Patterns)
		self.Pfmt("Named Queries",self.NamedQueries)
		self.Pfmt("Streamers",self.Streamers)
		self.Pfmt("MaxThreads",self.MaxThreads)
		self.Pfmt("LineLimit",self.LineLimit)
		self.Pfmt("Threads",len(self.Threads))
		self.Pfmt("OutputQueue",len(self.OutputQueue))
		self.Pfmt("OutputOrdering",len(self.OutputOrdering))
		self.Pfmt("Server",("Is a server" if self.Server else "not a server"))
		self.Pfmt("Client",("Is a client" if self.Client else "not a client"))
		self.Pfmt("RemoteAssignments",len(self.RemoteAssignments))
		self.Pfmt("CompletedLogs",len(self.CompletedLogs))
		self.Pfmt("IndexOn",(self.IndexOn if self.IndexOn else "No Index"))
		self.Pfmt("Arguments",self.Arguments)

		App.Print(self)

	# Inspect Field
	def Inspect(self,field,prefix=None,postfix=None,limit=-1,filter=None):
		value = ""
		ex = None

		if filter:
			ex = re.compile(filter)

		if field in self.__dict__:
			if type(self.__dict__[field]) is str:
				value = (prefix if prefix else "") + self.__dict__[field] + (postfix if postfix else "")
			elif type(self.__dict__[field]) is list:
				value = (prefix if prefix else "")

				count=0
				for item in self.__dict__[field]:
					if ex:
						if ex.match(str(item)):
							value += f"{item}\n"

					count += 1

					if limit > 0 and count >= limit:
						break

				value += (postfix if postfix else "")
		else:
			value = f"{field} not in this object"

		return value

	# Init Executor Convenience Function
	def InitExecutor(self,maxthreads):
		self.MaxThreads = maxthreads
		self.Executor = ProcessPoolExecutor(maxthreads)

	# Set Max Worker Threads
	def SetMaxThreads(self,maxthreads=None,reserve=True):
		if not maxthreads:
			maxthreads = os.cpu_count()

		if reserve:
			if maxthreads < 4:
				self.MaxThreads = 1
			elif maxthreads < 5:
				self.MaxThreads = 2
			else:
				self.MaxThreads = maxthreads - 2
		else:
			self.MaxThreads = maxthreads if maxthreads > 0 else 1

	# Helper Funtion for Getting Waittime on client.Connect()
	def WaitTime(self,defaultTimeout=DefaultConnectionWait):
		return int(self.Arguments.clientwait or str(defaultTimeout))

	# Load Search Patterns From File
	def LoadPatterns(self,filename):
		if os.path.exists(filename):
			# Add reg expressions from the given file
			with open(args.expr,"rt") as f_in:
				for line in f_in:
					pattern = line.strip("\n")
					self.Patterns.append(pattern)
		else:
			Msg(f"Supplied expression file {filename} does not exist")

	# Parse comma seperated patterns
	def ParsePatterns(self,pattern_str):
		tracer.Entering("SearchManager::ParsePatterns")

		prog = re.compile(r"(?<!\\),")
		patterns = prog.split(pattern_str)

		for pattern in patterns:
			self.Patterns.append(pattern)

		tracer.Exitting("SearchManager::ParePatterns")

	# Parser comma Seperated Stream Filters
	def ParseStreamFilters(self,filters):
		tracer.Entering("SearchManager::ParseStreamFilters")

		names = filters.split(",")

		self.Streamers.extend(names)

		tracer.Exitting("SearchManager::ParseStreamFilters")

	# Parse comma seperated Named Queries
	def ParseNamedQueries(self,queries):
		tracer.Entering("SearchManager::ParseNamedQueries")

		patterns = re.split(",",queries)

		for pattern in patterns:
			self.NamedQueries.append(pattern)

		tracer.Exitting("SearchManager::ParseNamedQueries")

	# Deprecated 3/3/2022
	# Show Log Info
	# Params:
	# showpattern - True/False, show the log file name pattern expression
	# filter - optional expression to filter results on (inclusive)
	# status - optional, if provided, list logs with given status
	def ShowLogsInfo(self,showpattern=False,filter=None,status=None,showCounts=False,sample=None):

		fmt = "{:12} {:13} {:6} {:20} "
		columns = [ "alias", "groups", "status", "name" ]

		if sample != None:
			sample = int(sample) if sample != 'all' else -1
		else:
			sample = 0

		if showpattern:
			fmt += "{:45} "
			columns.append("pattern")

		Msg(fmt.format(*columns))

		for meta in self.LogMetas:
			if status and not re.match(status,meta.Status):
				continue

			if filter:
				prog = re.compile(filter)

				isMatch = False

				for value in meta.Searchables():
					if prog.match(value):
						isMatch = True
						break

				if not isMatch:
					continue

			statusField = meta.Status

			if showCounts:
				count = 0

				for logPath in self.StorageLocations:
					count += len(meta.GetLogFiles(folder=logPath))

				statusField = f"{meta.Status}/{count}"

			columns = [ meta.Nickname, ",".join(meta.LogGroups), statusField, meta.Name ]

			if showpattern:
				columns.append(meta.ParseInfo[0])

			Msg(fmt.format(*columns))

			if sample  > 0:
				# Show 'sample' lines from latest log
				pass
			elif sample < 0:
				# Dump latest log
				pass

	# Deprecated 3/3/2022
	# Show list of existing logs using supplied names (Defaults to only "good" logs)
	def ShowLogs(self,loglist):
		logList = loglist.split(",")

		goodLogs = [ meta for meta in self.LogMetas if meta.Status == "good" ]

		logMetas = []

		if loglist == "all":
			logMetas.extend(goodLogs)
		else:
			for log in logList:
				selected = [ meta for meta in goodLogs if meta.Name == log or meta.Nickname == log or meta.LogGroup == log ]

				logMetas.extend(selected)

		for logPath in self.StorageLocations:
			Msg(f"Logs in Storage Location : {logPath}\n" + "=" * 40)

			for logMeta in logMetas:
				logs = logMeta.GetLogFiles(folder=logPath)

				Msg(f"Logs Of {logMeta.Name} / {logMeta.Nickname} / {logMeta.Description} - {len(logs)}")

				for log in logs:
					Msg(f"{log.Filename}")

	#
	# Diags Begin
	#

	# Print Running Status
	def PrintStatus(self):
		# Connections
		# OutputQueue
		# Running Threads
		# Remote Threads
		# Logs, Logs Processed, Logs to Go

		msg = ("=" * 10) + f"\nTotal Logs {len(self.Logs) + len(self.OutputQueue)}"
		msg += f" / Completed {len(self.CompletedLogs)} / Processed {len(self.OutputQueue)}"
		Msg(msg,ignoreModuleMode=True)

		msg = f"Threads {len(self.Threads)}"

		if self.Server:
			msg += f" / Conn {len(self.Server.Connections)}"
			msg += f" / Remote {len(self.RemoteAssignments)}"

		Msg(msg + "\n" + ("=" * 10),ignoreModuleMode=True)


	# Show Current Connections
	def DiagShowConns(self):
		Msg("=" * 10,ignoreModuleMode=True)
		if len(self.Server.Connections):
			for conn in self.Server.Connections:
				Msg("Connected {}".format(str(conn.getpeername()),ignoreModuleMode=True))
		else:
			Msg("No current connections",ignoreModuleMode=True)

		Msg(("=" * 10)+"\n", ignoreModuleMode=True)

	# Show Log Diagnostic
	def DiagShowLog(self,expr):
		Msg("=" * 10,ignoreModuleMode=True)
		if expr:
			expr = re.compile(expr)

		for log in self.Logs:
			if expr:
				if expr.match(log.Filename):
					Msg(log.Filename,ignoreModuleMode=True)
			else:
				Msg(log.Filename,ignoreModuleMode=True)

		Msg(("=" * 10)+"\n", ignoreModuleMode=True)

	# Show Output Ordering
	def DiagShowOrder(self):
		Msg("=" * 10,ignoreModuleMode=True)
		for item in self.OutputOrdering:
			Msg(f"{item.EncodedDate} - {item.Filename}",ignoreModuleMode=True)
		Msg(("=" * 10)+"\n", ignoreModuleMode=True)

	# Show Output Queue
	def DiagShowQueue(self):
		Msg("=" * 10,ignoreModuleMode=True)
		for item in self.OutputQueue:
			Msg(f"{item.Filename} / {item.Output}",ignoreModuleMode=True)
		Msg(("=" * 10)+"\n", ignoreModuleMode=True)

	#
	# Diags End
	#

	# InSearchMenu : An action menu a user can call up during searches
	def InSearchMenu(self,startLogs=0,started=None,keyed_in=None):
		proceed = True
		prompt = False

		totalThreads = self.CompletedThreadCount
		remoteThreads = len(self.RemoteAssignments)

		delta = (datetime.now() - started if started else None)

		if keyed_in and keyed_in == 'q':
			proceed = False
			return proceed
		elif keyed_in and keyed_in == 's':
			self.Print()
			return proceed
		else:
			Msg("In Search Menu",ignoreModuleMode=True)
			Msg("==============",ignoreModuleMode=True)
			Msg("c\t\tTo continue",ignoreModuleMode=True)
			Msg("s|sm\t\tSearch Manager Status",ignoreModuleMode=True)
			Msg("logs [opt-expr]\tTo list log files",ignoreModuleMode=True)
			Msg("conn\t\tShow connections",ignoreModuleMode=True)
			Msg("order\t\tShow output ordering",ignoreModuleMode=True)
			Msg("queue\t\tShow outout queue",ignoreModuleMode=True)
			Msg("q\t\tTo Quit",ignoreModuleMode=True)
			Msg("\n\n",ignoreModuleMode=True)
			Msg("There are {} logs to go and {} running threads, {} remote threads".format(len(self.Logs),len(self.Threads),remoteThreads),ignoreModuleMode=True)
			prompt = True

		if startLogs > 0:
			Msg("Started with {} logs, {} processed so far".format(startLogs,startLogs - len(self.Logs)),ignoreModuleMode=True)

		if totalThreads > 0:
			Msg("Total threads completed {}".format(totalThreads - len(self.Threads)),ignoreModuleMode=True)

		if delta:
			Msg(f"Search has been running for {delta}")


		Msg("=" * 10) # Get extra line

		userinput = ""

		if prompt:
			userinput = input("Choose ").strip()

		items = userinput.split(" ")
		cmd = items[0]
		args = None

		if len(items) > 1:
			args = " ".join(items[1:])

		if cmd == "q" or cmd == "quit":
			proceed = False
		elif cmd == 's' or cmd == "sm" or cmd == "search":
			self.Print()
		elif cmd == "logs":
			self.DiagShowLogs(args)

		elif cmd == "order":
			self.DiagShowOrder()

		elif cmd == "queue":
			self.DiagShowQueue()

		elif cmd == "conn":
			self.DiagShowConns()

		return proceed

	# Get Log Metas (Deprecated 3/3/2022)
	def GetLogMetas(self,filename):
		tracer.Entering("SearchManager::GetLogMetas")

		if os.path.exists(filename):
			self.LogMetas.extend(self.LoadLogMeta(filename))

		tracer.Exitting("SearchManager::GetLogMetas")

		return self.LogMetas

	# Determine if item (Filename or Log instance) Exists In self.Logs List
	def AlreadyInLogs(self,item):
		tracer.Entering("SearchManager::AlreadyInLogs")

		flag = False

		filename = ""

		if type(item) is str:
			filename = item
		else:
			filename = item.Filename

		for log in self.Logs:
			if log.Filename == filename:
				flag = True
				break

		tracer.Exitting("SearchManager::AlreadyInLogs")

		return flag

	# Create Output Ordering Map based on dates
	def CreateOrderMap(self,reverse=False):
		self.OutputOrdering.clear()
		self.OutputOrdering.extend(self.Logs)

		self.OutputOrdering.sort(key=lambda log: log.EncodedDate,reverse=reverse)

	# Get List of In Scope Logs by Date Criteria
	def GetLogList(self):
		tracer.Entering("SearchManager::GetLogList")

		lm = self.LogMetas[0]

		searchThru = []
		self.Logs.clear()

		startDate = None
		endDate = None

		args = self.Arguments

		if args.live:
			global Mounts

			for mh in Mounts:
				try:
					mh.Mount(sudome=True)
				except Exception as err:
					ErrMsg(err,f"Could not mount {mh.Path}")

		tsc = TimestampConverter()

		if args.latest:
			# Since some logs can straddle today and the day before, we include both
			startDate = date.today() - timedelta(days=1)
			endDate = date.today()

		if args.range:
			low = high = ""

			if "," in args.range:
				low, high = args.range.split(",")
			else:
				Msg("Range not supplied, assuming supplied value is simple range: {}" % args.range)
				low = args.range
				high = args.range

			startDate = tsc.ConvertTimestamp(low).date()
			endDate = tsc.ConvertTimestamp(high).date()

		if args.start:
			startDate = tsc.ConvertTimestamp(args.start).date()
			endDate = date.today()

		if args.end:
			endDate = tsc.ConvertTimestamp(args.end).date()

			if not startDate:
				startDate = endDate

		logNicks = list()

		# Log nics are csv
		if len(args.logs) > 0:
			logstr = ""

			if type(args.logs) == list:
				logstr = args.logs[0]
			else:
				logstr = args.logs

			logNicks = logstr.split(",")

		DbgMsg(f"Nicks = {logNicks}")

		selected_metas = []
		for meta in self.LogMetas:
			if meta.Status == "good" or args.all:
				if len(logNicks) > 0:
					for nick in logNicks:
						DbgMsg(f"Checking {nick} against {meta.Name}")
						if nick in meta.LogGroups or nick == meta.LogGroup or nick == meta.Nickname or nick == meta.Name:
							selected_metas.append(meta)
							break
				else:
					selected_metas.append(meta)

		# Look Through storage locations for matching files
		for logFolder in self.StorageLocations:
			for meta in selected_metas:
				matching_logs = meta.GetLogFiles(folder=logFolder,startDate=startDate,endDate=endDate)

				for logObj in matching_logs:
					if not self.AlreadyInLogs(logObj):
						logObj.Output = TmpFilename(file=logObj.Filename)
						self.Logs.append(logObj)

		# Create an Ordering Map for the file (for later output ordering)
		self.CreateOrderMap()

		# If in server mode, sort the logs by size
		# The purpose of which is local threads will be allocated larger files
		# and remote threads will be allocated smaller ones.
		# The list is sorted from largest to smallest. Accordingly, allocate
		# local threads from the top of the list, remote threads from
		# the tail of the list.
		if args.server:
			sortedLogList = sorted(self.Logs,key=lambda log : log.Size,reverse=True)

			self.Logs = sortedLogList

		tracer.Exitting("SearchManager::GetLogList")

		return self.Logs

	# Create Search Workers
	def CreateWorkers(self,clientmode=False):
		global TempSpace

		tracer.Entering("SearchManager::CreateWorkers")

		while len(self.Threads) < self.MaxThreads and len(self.Logs) > 0:
			log = self.Logs.pop()

			self.Tag = ( log, "CreateWorkers::Popped" )

			# Set Patterns up for this log (patterns may be unique to the log)
			thread_patterns = [ ]

			# Get Unnamed Patterns
			thread_patterns.extend([ Query(pattern) for pattern in self.Patterns ])
			# Get Named Queries
			thread_patterns.extend([ query for query in log.Meta.GetQueries(self.NamedQueries) ])

			# If named queries given, but thread_patterns is still empty, skip log, otherwise a
			# full dump will occur and with named queries that is undesirable
			if len(self.NamedQueries) > 0 and len(thread_patterns) == 0:
				DbgMsg(f"No expressions and no named queries, skipping {log.Name}")
				continue

			Msg(f"Searching {log.Filename}...")

			# Output Scenarios
			# Clients default, dump into (default or alternate) NFS share
			# Clients can choose temp space, but this means they have to transfer the file back
			# Server, can choose to dump elsewhere, accordingly, TempName generation
			# has to respect that.

			prefix = "logsearch_"
			postfix = "_"+log.EncodedDateStr()

			if not clientmode:
				if self.Arguments.local or self.Arguments.tmp:
					log.SetOutput(TmpFilename(folder=TempSpace,prefix=prefix,postfix=postfix))
				else:
					# Default to source folder of file
					log.SetOutput(TmpFilename(file=log.Filename,prefix=prefix,postfix=postfix))
			else:
				if self.Arguments.local or self.Arguments.tmp:
					log.SetOutput(TmpFilename(folder=TempSpace,prefix=prefix,postfix=postfix))
				else:
					# Default to source folder of file
					log.SetOutput(TmpFilename(file=log.Filename,prefix=prefix,postfix=postfix))

			log.Track("processing by local thread")

			thread = self.Executor.submit(SearchLog,log,thread_patterns,self.Streamers,self.LineLimit,self.TerminateFlag)

			tuple = ( thread, log )
			self.Threads.append(tuple)

		tracer.Exitting("SearchManager::CreateWorkers")

	# Check on Worker Threads
	def CheckWorkers(self):
		tracer.Entering("SearchManager::CheckWorkers")

		terminated = []

		for threadTuple in self.Threads:
			thread,log = threadTuple

			if not self.IfTerminate() and thread.done():
				err = thread.exception()

				if err:
					Msg(f"Error {err}")

				terminated.append(threadTuple)

				self.Tag = ( log, "SearchManager::CheckWorkers")

				log.Track("search completed")
				self.QueueOutput(log)

			if self.IfTerminate():
				break

		# Checking for dead threads is done, remove them from the active thread list
		for deadThread in terminated:
			DbgMsg("Removing completed thread of {} - maxthreads = {} len-logList = {}".format(len(self.Threads),self.MaxThreads,len(self.Logs)))
			self.Threads.remove(deadThread)

		tracer.Exitting("SearchManager::CheckWorkers")

	# Queue Output Files
	def QueueOutput(self,completed):
		tracer.Entering("SearchManager::QueueOutput")

		if completed:
			if not type(completed) is list:
				self.CompletedLogs.append(completed)
				self.OutputQueue.append(completed)
				self.CompletedThreadCount += 1
			else:
				for log in completed:
					self.CompletedThreadCount += 1
					if os.path.exists(log.Output):
						self.OutputQueue.append(log)
						self.CompletedLogs.append(log)

		tracer.Exitting("SearchManager::QueueOutput")

	# Get Output Logs that are from the top of the ordering list
	def TopOfOrder(self):
		topItem = None

		# Look Through OutputQueue for items that meet the top of the output ordering queue
		for log in self.OutputQueue:
			if log is self.OutputOrdering[0]:
				# If we have a match, we return the log and...
				topItem = log
				# Remove both the log from the output queue AND the ordering queue
				self.OutputQueue.pop(0)
				self.OutputOrdering.pop(0)
				break

		return topItem

	# Process Output Files Waiting In Queue
	def ProcessOutput(self,outputFile=None):
		tracer.Entering("SearchManager::ProcessOutput")

		# We have Items in Queue
		# If any item is at the top of the ordering list, output, remove from queue, pop ordering from top of ordering list, recheck
		# when no item in the queue matches the top of the list, output is complete (for now)

		while len(self.OutputQueue) > 0:
			if self.Arguments.inorder:
				# Grab log at top of list
				log = self.TopOfOrder()
			else:
				log = self.OutputQueue.pop(0)

			if log is None:
				break


			self.Tag = ( log, "SearchManager::ProcessOutput" )

			if not log.Output or not type(log.Output) is str:
				DbgMsg(f"Output for {log.Filename} is not a string - {type(log.Output)}")
				log.Print()
				continue

			if os.path.exists(log.Output):
				with open(log.Output,"rb") as f_in:

					for rawline in f_in:
						self.MatchCount += 1

						decoded, used, line = log.Decode(rawline)

						if decoded:
							if outputFile is sys.stdout:
								Msg(line.strip(),ignoreModuleMode=True)
							else:
								Msg(line.strip(),file=outputFile,ignoreModuleMode=True,binary=True)
						else:
							Msg(f"line {linesInFile} from {log.Output} not decoded",file=outputFile,ignoreModuleMode=True)

						if self.IfTerminate():
							break

						# If there are outstanding logs or assignments, check for new network traffic
						if (self.MatchCount % 500) == 0 and (len(self.Logs) > 0 or len(self.RemoteAssignments) > 0) and self.Server:
							# If select has readables, process the readables, queue any completion output
							readable, writable, exceptional = self.Server.Select()

							if len(readable) > 0:
								completed = self.Server.Process(self.LogMetas,self.Logs,self.Patterns,self.NamedQueries,self.Streamers,self.RemoteAssignments)

								if len(completed) > 0:
									self.QueueOutput(completed)

				os.remove(log.Output)

				log.SetOutput(None)
			else:
				Msg(f"Output file {log.Output} seems to be missing")

			if self.IfTerminate():	# If termination in progress, skip the rest of the output queue
				break

		tracer.Exitting("SearchManager::ProcessOutput")

	# Get Assignments (Also checks for rejects)
	def GetAssignments(self,threads):
		tracer.Entering("SearchManager::GetAssignments")

		available = []
		patterns = []
		namedQueries = []

		newAssignments = 0

		try:
			assignments,patterns,namedQueries = self.Client.GetAssignments(self.LogMetas,threads)
			available, rejected = self.Client.CheckAvailability(assignments,self.Arguments.mount)

			if len(rejected) > 0:
				DbgMsg("Rejecting {len(rejected)} item(s)")
				rejectFailed = self.Client.Reject(rejected)

			if len(available) > 0:
				newAssignments = len(available)
				self.Logs.extend(available)
			else:
				newAssignments = -1

		except Exception as err:
			Msg(f"*** An error occurred inside SearchManager::GetAssignments - {err}",ignoreModuleMode=True)
			newAssignments = -1

		tracer.Exitting("SearchManager::GetAssignments")

		return newAssignments,patterns,namedQueries

	# Let Server Know Assignment(s) have been Completed
	def Complete(self):
		tracer.Entering("SearchManager::Complete")

		queueLength = 0

		try:
			if len(self.OutputQueue) > 0:
				DbgMsg(f"Completing {len(self.OutputQueue)} job(s)")

				for log in self.OutputQueue:
					self.Client.Completed(log)

				# Get number of items just completed, we want that many new assignments
				queueLength = len(self.OutputQueue)

				# Clear recently completed output from queue
				self.OutputQueue.clear()

		except Exception as err:
			Msg(f"*** An error occurred inside SearchManager::Complete - {err}",ignoreModuleMode=True)

		tracer.Exitting("SearchManager::Complete")

		return queueLength

	# Clean Up Early Terminate Request
	def CleanUpEarlyTermination(self):
		tracer.Entering("SearchManager::CleanUpEarlyTermination")

		self.Touch(self.TerminateFlag)

		# Now Manage any remote jobs
		if self.Server and (len(self.Server.Connections) > 0 or len(self.RemoteAssignments) > 0):
			self.Server.TerminateRemoteWorkers = True

			start = datetime.now()

			while len(self.RemoteAssignments) > 0:
				completed = self.Server.Process(self.LogMetas,self.Logs,self.Patterns,self.NamedQueries,self.Streamers,self.RemoteAssignments)
				tm.sleep(0.5)

				elapsedTime = self.ElapsedTime(start)

				# Give time to shutdown, but ultimately quit if no response
				if elapsedTime.seconds > 5:
					break

		# Clean up threads
		while len(self.Threads) > 0:
			doneList = []

			for threadTuple in self.Threads:
				thread = threadTuple[0]
				output = threadTuple[1]

				if thread.done():
					doneList.append(threadTuple)
				else:
					thread.cancel()

			for item in doneList:
				output = item[1].Output
				self.Threads.remove(item)

				if output and os.path.exists(output):
					os.remove(output)

		self.Executor.shutdown()

		# Clean up output files
		for log in self.Logs:
			if log.Output and os.path.exists(log.Output):
				os.remove(log.Output)

		os.remove(self.TerminateFlag)

	# Process Clean Items
	def CleanProcess(self,location,expressions):
		list = os.listdir(location)

		for item in list:
			for expression in expressions:
				if expression.match(item):
					fname = os.path.join(location,item)
					os.remove(fname)

	# Clean up the mess after crash
	def Clean(self,args):
		opPrefix = "^logsearch"
		runPrefix = "^psearch.log"

		locations = [ "/tmp" ]
		locations.extend(self.StorageLocations)

		if args.mount:
			locations.append(args.mount)
		if args.tmp:
			locations.append(args.tmp)

		exprs = [ re.compile(opPrefix), re.compile(runPrefix) ]

		for location in locations:
			self.CleanProcess(location,exprs)

	# Client Search Manager
	def ClientSearch(self,args):
		global Version

		tracer.Entering("SearchManager::ClientSearch")

		DbgMsg(f"SearchManager::ClientSearch - Version {Version}")

		# Set Args
		self.Arguments = args

		# Initialize some things
		self.LineCount = 0
		self.MatchCount = 0
		self.CompletedThreadCount = 0
		self.Threads.clear()
		self.RemoteAssignments.clear()
		self.CompletedLogs.clear()
		self.OutputQueue.clear()
		self.Logs.clear()
		self.Server = None

		# Mark start of search for timing purposes
		clientStarted = datetime.now()

		Msg(f"Beginning Client Based Search - Attempting to connect to {self.Arguments.client} with {self.MaxThreads} available threads")

		# Setup output option
		outputFile=sys.stdout

		# See if user has specified an output file (Redundant, since all client output goes to a temp file, but, user may want to catch other output)
		if self.Arguments.out:
			outputFile=open(args.out,"wb")

		# Create Remote Searcher
		self.Client = RemoteSearcher(self.Arguments.client)

		proceed = True

		logCount = 0

		if not self.Client.Connect(self.WaitTime()):
			Msg("Failed to connect to server")
			return

		try:
			newAssignments,patterns,namedQueries = self.GetAssignments(self.MaxThreads)

			if newAssignments > 0:
				# Fill out pattern and named Query Info
				self.Patterns.extend(patterns)
				self.NamedQueries.extend(namedQueries)

				logCount += newAssignments

				pingFailed = 0
				lastPingAttempt = None

				while (len(self.Logs) > 0 or len(self.Threads) > 0):
					# Create Worker Threads
					self.CreateWorkers()

					# If there are no locally available logs, then we are only waiting on remoteClients
					if len(self.Logs) == 0:
						tm.sleep(0.5)

					# Cycle through the threads looking for completions.
					# When a thread is complete, retrieve the output, dump it, add
					# the thread record to the terminated list and move on.
					self.CheckWorkers()

					# Look for any keystrokes for InSearchMenu to pop up
					result = self.GetChar()

					if result:
						proceed = self.InSearchMenu(startLogs=logCount,started=clientStarted,keyed_in=result)

					if not proceed:
						self.Touch(self.TerminateFlag)
						break

					# Check for terminate here since the InSearchMenu can request a terminate
					if self.IfTerminate():
						break

					# Check for output (completed items), or ping the server
					if len(self.OutputQueue) > 0:
						# Complete items
						itemsCompleted = self.Complete()
						# Ask for as many new assignments as has just been completed
						newAssignments,patterns,namedQueries =  self.GetAssignments(itemsCompleted)

						if newAssignments > 0:
							logCount += newAssignments

					elif lastPingAttempt is None or self.ElapsedTime(lastPingAttempt).seconds > 5:
						lastPingAttempt = datetime.now()

						msgpkt = self.Client.Ping()

						if msgpkt.Verb == self.Client.TERM:
							# TODO : signal early termination
							break
						elif msgpkt.Verb == "none":
							pingFailed += 1
						else:
							DbgMsg(f"Server Replied {msgpkt.Verb}")
							pingFailed = 0

						# If ping failed 5 times, parent remote thread probably died
						if pingFailed > 5:
							break

			else:
				# ElapsedTime function in App Class now
				elapsedtime = self.ElapsedTime(clientStarted)

				prefix = "No assignments available from"

				if newAssignments < 0:
					prefix = "An error occured or the connection timed out talking to"

				Msg(f"{prefix} {self.Server} - time elapsed {elapsedtime}")

		except Exception as err:
			# callerframe = inspect.currentframe()
			# callerframe.f_lineno

			exc_tb = sys.exc_info()[2]

			Msg("SearchManager::ClientSearch - An error occurred talking to the server - type({}) on {} - {}".format(type(err),exc_tb.tb_lineno,err))

		# ElapsedTime function in App Class now
		elapsedTime = self.ElapsedTime(clientStarted)

		Msg(f"Assignments complete (or none available), shutting down - time elapsed {elapsedTime}")

		if self.Arguments.out:
			outputFile.close()

		if self.IfTerminate():
			self.CleanUpEarlyTermination()

		if self.Client.Connected:
			self.Client.Disconnect()

		Msg(f"Client Search/Dump completed - elapsed run time {elapsedTime}")

	# Local Search
	def LocalSearch(self,args,clientmode=False,servermode=False):
		global DefaultAddres,DefaultPort, Version

		tracer.Entering("SearchManager::LocalSearch")

		DbgMsg(f"SearchManager::LocalSearch - Version {Version}")

		# Set Args
		self.Arguments = args

		# Initialize some things
		self.LineCount = 0
		self.MatchCount = 0
		self.CompletedThreadCount = 0
		self.Threads.clear()
		self.RemoteAssignments.clear()
		self.CompletedLogs.clear()
		self.OutputQueue.clear()
		self.Logs.clear()
		self.Server = None

		# Init Pattern Count (informational)
		patternCount = len(self.Patterns)

		# Using log nicks provided and any date criteria from cmdline args, get a list
		# of pertinent log files for this search/dump, also fills in Output, which can
		# Be altered if needed
		self.GetLogList()

		# Init logCount (informational)
		logCount = len(self.Logs)

		if logCount == 0:
			Msg("No logs meet the supplied criteria, log count is zero",ignoreModuleMode=True)
			return

		# Start Server if asked for
		if servermode:
			Msg("Starting Server")
			self.Server = SearchServer(host=DefaultAddress,port=DefaultPort)

		# Mark start of search for timing purposes
		searchStarted = datetime.now()

		Msg(f"Beginning search with {logCount} logs, {patternCount} patterns ({len(self.NamedQueries)} named queries) and {self.MaxThreads} threads")

		# Setup output option
		outputFile=sys.stdout

		# See if user has specified an output file
		if self.Arguments.out:
			outputFile=open(args.out,"wb")

		statusInterval = Periodic(timedelta(seconds=10))

		if DebugMode():
			statusInterval.Start()

		# While there are logs in the list and there are active threads, keep looping
		while len(self.Logs) > 0 or len(self.Threads) > 0 or len(self.RemoteAssignments) > 0:
			if DebugMode() and statusInterval.Trigger():
				self.PrintStatus()

			# Create Threaded Workers if there are logs available
			if len(self.Logs) > 0 and not self.Arguments.disablelocal:
				self.CreateWorkers(clientmode)

			# If Server defined, process incoming comms
			if self.Server:
				completed = self.Server.Process(self.LogMetas,self.Logs,self.Patterns,self.NamedQueries,self.Streamers,self.RemoteAssignments)

				if len(completed) > 0:
					DbgMsg(f"{len(completed)} logs completed")
					self.CompletedLogs.extend(completed)
					self.QueueOutput(completed)

			# If there are no locally available logs, then we are only waiting on remoteClients
			if len(self.Logs) == 0:
				tm.sleep(0.5)

			# Cycle through the threads looking for completions.
			# When a thread is complete, retrieve the output, dump it, add
			# the thread record to the terminated list and move on.
			self.CheckWorkers()

			# Look for any keystrokes for InSearchMenu to pop up
			if CmdLineMode():
				result = self.GetChar()

				if result:
					proceed = self.InSearchMenu(startLogs=logCount,started=searchStarted,keyed_in=result)

					if not proceed:
						self.Touch(self.TerminateFlag)
						break

			# Check for terminate here since the InSearchMenu can request a terminate
			if self.IfTerminate():
				break

			# Process Output
			self.ProcessOutput(outputFile)

			# Deprecated : Since we are attempting to print them in order
			# they will be dequeued as they are printed
			# Process Queued Output files, sending to provided stream (stdout, mostly)
			#if len(self.OutputQueue) > 0:
			#	self.OutputQueue.clear()

		if self.Arguments.out:
			outputFile.close()

		if self.IfTerminate():
			self.CleanUpEarlyTermination()

		# Each processing scenario, pattern or dump, should loop-sleep until all remote clients are finished
		# if searchServer is not None. By the time running gets here, all remote clients should be completed
		# *IF* not, the shutdown process should tell the remote clients that they are abandoned, they should
		# clean up after themselves and terminate.
		if self.Server:		# If there is a searchServer, shut it down here.
			pass

		elapsedTime = self.ElapsedTime(searchStarted)

		Msg(f"Search/Dump completed - elapsed run time {elapsedTime}")

# Main Loop
def Search(args):
	global TempSpace, LogLocations, LogSources, searchManager, tracer, app

	metas = []

	# Initialize pattern variable for showing log meta data
	status = None

	# However, the user can limit the thread count OR expand it. Dealer's choice
	if args.threads:
		searchManager.SetMaxThreads(int(args.threads))

	# If a file of expressions is provided, read it in and set the expressions list
	if args.expr:
		searchManager.LoadPatterns(args.expr)

	# Add any pattern provided by itself to the expressions list
	if args.pattern and args.pattern != "none":
		searchManager.ParsePatterns(args.pattern)

	# Add any Streamers
	if args.stream:
		searchManager.ParseStreamFilters(args.stream)

	# Add any named queries
	if args.query:
		searchManager.ParseNamedQueries(args.query)

	if args.clean:
		searchManager.Clean(args)
	elif args.logs:
	#elif args.logs or args.client:			# User requested log search or client mode
	#	if args.client:				# Go into Client Mode
	#		searchManager.ClientSearch(args)
	#	else:					# Go into local search mode, with optional server thread
		searchManager.LocalSearch(args)
	else:
		Msg("You need to provide a log source or comma seperated list of log sources to search through")
		Msg("Use the --show command line flag to see what logs are available")

	if DebugMode() and os.path.exists(logFilename):
		os.system("less {}".format(logFilename))
		os.remove(logFilename)

	# Just to be sure
	if os.path.exists(TerminateFlag):
		os.remove(TerminateFlag)

	if os.path.exists(logFilename) and os.path.getsize(logFilename) == 0:
		os.remove(logFilename)

	# Last Ditch effort to remove straggling output files.
	for log in searchManager.OutputQueue:
		try:
			if log.Output and os.path.exists(log.Output):
				os.remove(log.Output)
		except:
			pass

# Build Parser
def BuildParser():
	"""Build Parser"""

	global Parser, ShowChoices, DefaultConnectionWait

	Parser = argparse.ArgumentParser(description="Parallel Log Searcher")

	subparsers = Parser.add_subparsers(help="commands",dest="command")

	Parser.add_argument("--debug",action="store_true",help="Put script in debug mode")
	Parser.add_argument("--config",help="Use supplied config file")
	Parser.add_argument("--sources",help="Load alternate log sources meta data file")
	Parser.add_argument("--logsrc",help="Path to log storage location, can be csv")
	Parser.add_argument("--mount",action="store_true",help="If there are listed mountable filesystems, mount them for seaching")
	Parser.add_argument("--trace",action="store_true",help="Enable tracing messages")
	Parser.add_argument("--clean",action="store_true",help="Clean up temp files")
	Parser.add_argument("--test",action="store_true",help="Execute test function")
	Parser.add_argument("--limit",help="Limit result to [count] lines")
	Parser.add_argument("--threads",help="Set max thread limit")
	Parser.add_argument("--tmp",help="Set temp space to be used")
	Parser.add_argument("--silent",action="store_true",help="Suppress output (except debug output)")

	showcmds = subparsers.add_parser("show",help="Show logs and sources")
	showcmds.add_argument("--sample",help="Show 'sample' lines from random log from population")
	showcmds.add_argument("--headtail",action="store_true",help="Show head and tail of sample log")
	showcmds.add_argument("--dump",action="store_true",help="Dump random log from population")
	showcmds.add_argument("--list",action="store_true",help="List current log files from supplied logs or groups")
	showcmds.add_argument("--counts",action="store_true",help="When showing log sources, include current counts of matching files")
	showcmds.add_argument("--patterns","--pat",action="store_true",help="Show filename pattern also")
	showcmds.add_argument("parameter",choices=ShowChoices,help="Log or source to show")
	showcmds.add_argument("logspec",nargs="?",help="Log name, nickname or log group for show command")

	searchcmds = subparsers.add_parser("search",help="Search logs")
	searchcmds.add_argument("--all",action="store_true",help="When searching, logs not marked 'good' are ignored, this flag includes them")
	searchcmds.add_argument("--out",help="Send results to supplied filename")
	searchcmds.add_argument("--expr","-f",help="File containing multiple search expressions (one per line)")
	searchcmds.add_argument("--stream",help="Use named stream filter(s) on search output [comma seperated]")
	searchcmds.add_argument("--query","-q",help="Execute named query in Log Meta against the log(s)")
	searchcmds.add_argument("--latest",action="store_true",help="Search only latest log")
	searchcmds.add_argument("--live",action="store_true",help="Search live logs")
	searchcmds.add_argument("--range",help="Date Ranges for search (YYYYMMDD format)")
	searchcmds.add_argument("--inorder",action="store_true",help="Best effort to display output in date ascending order")
	searchcmds.add_argument("--local",action="store_true",help="User local temp space for temp files to ease mount congestion")
	searchcmds.add_argument("--start","-s",help="Start Date, iso format [YYYY][MM]DD")
	searchcmds.add_argument("--end","-e",help="End Date, iso format [YYYY][MM]DD")
	searchcmds.add_argument("--server",action="store_true",help="Make this thread a search cluster controller")
	searchcmds.add_argument("--disablelocal",action="store_true",help="Disable local search threads")
	searchcmds.add_argument("logs",nargs="?",default="none",help="Log(s) to search, can be a csv list of name, nickname or log group")
	searchcmds.add_argument("pattern",nargs="?",default="none",help="Search pattern")

	client = subparsers.add_parser("client",help="Become client")
	client.add_argument("-w","--wait",default=DefaultConnectionWait,help="Time for client to wait for server on first connection (in seconds)")
	client.add_argument("server",help="Provide server fqdn or IP to become a search cluster client")

	return Parser

# Load Metas (A LogMeta, Meta Loader)
def LoadMetas():
	"""Load Metas"""

	global LogSources, LogMetas

	success = False

	if os.path.exists(LogSources):
		try:
			LogMetas = LogMeta.LoadMetas(LogSources)
		except Exception as err:
			Msg(f"An error occurred trying to load LogMetas from {LogSources}")

			breakpoint()
		else:
			success = True

	return success

# Load and Process Config File
def LoadConfig(configfile = None):
	"""Load And Process Config File"""

	global AppConfig, ConfigFile
	global TempSpace, LogSources, LogLocations, Mounts, LogMetas

	success = False

	# Even if we can't load the config, we want this to not be None
	# It may overwrite an existing one... that is ok, the goal here
	# is to ensure calls to AppConfig.get()'s will set defaults... so SET YOUR DEFAULTS
	AppConfig = configparser.ConfigParser()

	# May be redundant here, but it' a low cycle expense
	if configfile != None: ConfigFile = configfile

	if ConfigFile != None and os.path.exists(ConfigFile):
		try:
			AppConfig.read(ConfigFile)
			# Set Config items here, so that they CAN be overridden by cmdline args

			silent = AppConfig.getboolean("settings","silent",fallback=False)
			silent = False if silent else True # Jux Value
			CmdLineMode(silent)

			debugmode = AppConfig.getboolean("settings","debug",fallback=False)
			DebugMode(debugmode)

			TempSpace = AppConfig.get("settings","temp_space",fallback="/tmp")
			TRACEStatefile = AppConfig.get("settings","tracefile",fallback="/tmp/trace_ex.txt")
			LogSources = AppConfig.get("settings","logsources")

			LoadMetas()

			LogLocations = list()
			for name,value in AppConfig.items("logfolders"):
				LogLocations.append(value)

			Mounts = list()
			for name,value in AppConfig.items("mounts"):
				m = Mounter(value)

				m.Tag = name

				Mounts.append(m)

		except Exception as err:
			ErrMsg(err,f"An error occurred trying to load the specified config file - {ConfigFile}")
		else:
			success = True

	return success

# Parse Arguments Helper
def ParseArgs(arguments=None):
	"""Parse Arguments"""

	global Parser, Args, AppConfig, ConfigFile, Mounts, TRACERStatefile
	global TempSpace, LogLocations, LogSources, searchManager, tracer, app
	global LogMount

	if arguments != None:
		Args,unknowns = Parser.parse_known_args(arguments)
	else:
		Args,unknowns = Parser.parse_known_args()

	args = Args

	if args.config != None:
		LoadConfig(args.config)

	# Check for debug mode flag
	if args.debug:
		DebugMode(True)
		DbgMsg("Debug mode enabled by cmdline")

	# Check for Trace Flag
	if args.trace:
		tracer.Enable()
		tracer.LoadStates(TRACEStatefile)

		DbgMsg("Tracing messages turned on")

	# Check for Silent Flag (silent = messages sent to log, not console)
	if args.silent:
		DbgMsg("Silent mode enabled by cmdline")
		CmdLineMode(False)

	# Set Default Temp Space (Deprected 3/3/2022 by new subparser stuff, must be parsed by
	# search handler now
	#if args.local:
	#	TempSpace="/tmp"

	# If Temp space specified, use it (overrides --local flag)
	if args.tmp:
		TempSpace=args.tmp

	# Change In Log Source Location(s)
	if args.logsrc != None:
		LogLocations = args.logsrc.split(",")

	# Check for, and potentially load, new log metas
	if args.sources != None:
		LogSources = args.sources
		LoadMetas()

	# Create Search Manager
	searchManager = SearchManager(LogLocations,LogMetas)

	# Run tests
	if args.test:
		Test(args=args)
		quit()

	return args

# Initialize App
def Initialize():
	"""Initialize App"""

	# Set Run Log
	ph.Logfile = "/tmp/psearch_run.log"
	#ph.TeeFile = "run.txt"

	global Parser, AppConfig, ConfigFile, tracer

	if Parser == None: BuildParser()

	# Init App Helper
	app = App()

	# Init Tracer
	tracer = Tracable()

	if AppConfig == None and ConfigFile != None:
		# If AppConfig Is not Initialized and ConfigFile is not None, attempt to load
		LoadConfig()

	LoadMetas()

# Run Plugin/Import Pattern
def run(**kwargs):
	"""Run Plugin/Import Pattern Stub"""

	global Mounts

	DbgMsg("Entering psearch::run")

	arguments = kwargs.get("arguments",None)

	DbgMsg("Initializing")

	Initialize()

	DbgMsg("Init Complete, Parsing Arguments")

	args = None

	if arguments != None:
		args = ParseArgs(arguments)
	else:
		args = ParseArgs()

	DbgMsg(f"Parsing Complete, Starting Command Sequence {args.command}")

	if args.mount:
		for m in Mounts:
			try:
				# If not mounted, it will attempt a mount, if mounted, it notes it
				# And carries on quietly
				m.Mount(sudome=True)
			except Exception as err:
				ErrMsg(err,f"Could not mount {mh.Path}")

	if args.command == "show":
		DbgMsg("Executing show")
		__ShowHandler__(args)
	elif args.command == "client":
		DbgMsg("Becoming Client")
		Client(args.server,args.wait)
	elif args.command == "search":
		DbgMsg("Beginning PSearch")
		Search(args)

	for m in Mounts:
		try:
			# If mounts were already mounted, this will quietly not unmount them
			if m.Mounted():
				m.Unmount(sudome=True)
		except Exception as err:
			ErrMsg(err,f"Could not unmount {m.Path}")

# Show Logs Handler
def __ShowHandler__(args):
	"""Show Logs Handler"""

	global ShowChoices, LogSources

	sample = 0
	patterns = False
	include = None
	counts = False

	if args.sample != None:
		sample = int(args.sample)
	elif args.dump:
		sample = -1

	if args.patterns:
		patterns = True

	if args.counts:
		counts = args.counts

	logspec = args.logspec

	if not args.list:
		ShowLogsInfo(patterns,logspec,args.parameter,counts,sample,args.headtail)
	elif args.list:
		ShowLogs(args.parameter,logspec)

# Search Client Entry Point
def Client(server,wait):
	"""Search Client Entry Point"""

	pass

#
# Test Harnesses/Stubs
#

# Main Test Stub
def Test(**kwargs):
	"""Main Test Stub"""

	args = kwargs.get("args",None)

	pass

# Inspect SearchManager
def Inspect(sm):
	reply = ""

	while reply != "q":
		print("1. SearchManager State")
		print("2. Client Connections")
		print("3. Remote Queue Info")
		print("4. ")
		print("5. ")
		print("e. to Eval")
		print("q. To Quit")

		reply = input("Choice : ")

		if reply == "1":
			sm.Print()
		elif reply == "2":
			if sm.Server:
				pass
			else:
				print("No connections")
		elif reply == "3":
			pass
		elif reply == "4":
			pass
		elif reply == "5":
			print(sm.Inspect("RemoteAssignments"))
		elif reply == "e":
			cmd = input("Statement : ")
			print(eval(cmd))

# Test Server
def TestServer():
	Initialize()

	args = ParseArgs(DEBUGRVARGS)

	Search(args)

# Test Client
def TestClient():
	Initialize()

	args = ParseArgs(DEBUGCLTARGS)

	Search(args)

# Test Aliases

def ts():
	TestServer()

def tc():
	TestClient()

#
# Pre Init Stuff
#

# Random Seed Init
random.seed()

#
# Main Loop
#
if __name__ == "__main__":
	CmdLineMode(True)

	Initialize()

	run()
