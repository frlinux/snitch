#!/usr/bin/python
import os
import sys
import pyinotify
import smtplib

mailcontent = ''
frommail=""
tomail=""
smtphost=""
subjectmail="Snitch: file accessed!\n"

mode=sys.argv[1]

# mode 1 - OPENED
# mode 2 - ACCESSED
# mode 3 - CREATED
# mode 4 - ACCESSED and OPENED - verbose /!\
if mode == "1":
	pynotifymasks = pyinotify.IN_OPEN
if mode == "2":
	pynotifymasks = pyinotify.IN_ACCESS
if mode == "3":
	pynotifymasks = pyinotify.IN_CREATE
if mode == "4":
	pynotifymasks = pyinotify.IN_OPEN | pyinotify.IN_ACCESS

watchmgr = pyinotify.WatchManager()

class ProcessManager(pyinotify.ProcessEvent):
	def process_IN_ACCESS(self, event):
		s = smtplib.SMTP(smtphost)
		mailcontent = "Accessed: %s " % os.path.join(event.path, event.name)
		message = "From:" + frommail + "\nTo:" + tomail + "\nSubject:" + subjectmail + "\n" + mailcontent
		s.sendmail(frommail,tomail,message)
		s.quit()

notifier = pyinotify.Notifier(watchmgr, ProcessManager())

wdd = watchmgr.add_watch(sys.argv[2], pynotifymasks, rec=True)

while True:
	try:
		notifier.process_events()
		if notifier.check_events():
			notifier.read_events()
	except KeyboardInterrupt:
		notifier.stop()
		break

