# Bin install
INSTALL = /usr/local/bin
EXENAME = psearch

# Meta Data
DATAINSTALL = /srv/storage/data
DATA = logsources.xml
XSLT1 = logsrcs2csv.xslt
XSLT2 = logsrcs2htm.xslt

install:
	@cp $(EXENAME).py $(INSTALL)/$(EXENAME)
	@chmod +x $(INSTALL)/$(EXENAME)
	@[ ! -f $(DATAINSTALL)/$(DATA) ] && cp $(DATA) $(XSLT1) $(XSLT2) $(DATAINSTALL)/ || return 0
	@[ ! -f $(DATAINSTALL)/$(DATA) ] && chmod +r $(DATAINSTALL)/$(DATA) $(DATAINSTALL)/$(XSLT1) $(DATAINSTALL)/$(XSLT2) || return 0

test:
	@./psearch.py --debug --latest wifi awjohnso

testserver:
	@./psearch.py --debug --server --latest wifi awjohnso

testquery:
	@./psearch.py --debug --latest --query users wifi

testquery2:
	@./psearch.py --debug --server --start 20210401 --query users wifi

testquery3:
	@./psearch.py --debug --server --latest --query users wifi

testquery4:
	@./psearch.py --trace --debug --server --start 20210521 --query users wifi

runquery:
	@./psearch.py --server --latest --query users wifi

testclient:
	@./psearch.py --trace --debug --client sol.infosec.stonybrook.edu

runclient:
	@./psearch.py --clientwait 120 --client sol.infosec.stonybrook.edu

clientrepeat:
	@./clientrepeat.sh

show:
	@./psearch.py --counts --showp --debug

editmeta:
	@nano /srv/storage/data/logsources.xml
cpmeta:
	@cp logsources.xml /srv/storage/data/

cleantmp:
	@rm /tmp/psearch* || true
	@rm /tmp/logsearch* || true
	@rm /srv/equallogic/fsm_logs/logsearch* || true
	@rm /srv/array2/fsm_logs/logsearch* || true

chklogs:
	@ls -al /tmp/psearch* || true
	@ls -al /tmp/logsearch* || true
	@ls -al /srv/equallogic/fsm_logs/logsearch* || true
	@ls -al /srv/array2/fsm_logs/logsearch* || true

who:
	@nslookup ceres.infosec.stonybrook.edu | grep -E -A 1 "^Name:"
	@nslookup soliton.infosec.stonybrook.edu | grep -E -A 1 "^Name:"
	@nslookup graviton.infosec.stonybrook.edu | grep -E -A 1 "^Name:"

actions:
	@printf "Actions in this Makefile\n"
	@printf "========================\n"
	@printf "test\t\tRun debug mode test search\n"
	@printf "testserver\tRun 'test' with server turned on\n"
	@printf "testquery\tRun a 'test' using a named query and --latest\n"
	@printf "testquery2\tRun a 'test' with server and named query and start date\n"
	@printf "testquery3\tRun a 'test' with server and named query and --latest\n"
	@printf "testquery4\tRun a 'test' with server and named query and start date\n"
	@printf "testclient\tRun a client in test mode with debug\n"
	@printf "clientrepeat\tRun a client test mode with debug and reconnect\n"
	@printf "show\t\tRun 'showp' test\n"
	@printf "editmeta\tCall nano to edit logsources.xml\n"
	@printf "cpmeta\tCopy local meta to logsources storage location\n"
	@printf "cleantmp\tClean up temp files in /tmp\n"
