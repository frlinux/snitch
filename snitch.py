#!/usr/bin/python
import os
import sys
import pyinotify
import smtplib

frommail=""
tomail=""
subjectmail="Snitch: file notification\n"
smtphost=""

mode=sys.argv[1]

# mode 1 - OPENED
# mode 2 - ACCESSED
# mode 3 - CREATED
if mode == "1":
	pynotifymasks = pyinotify.IN_OPEN
if mode == "2":
	pynotifymasks = pyinotify.IN_ACCESS
if mode == "3":
	pynotifymasks = pyinotify.IN_CREATE

watchmgr = pyinotify.WatchManager()

def sendmail(mailcontent):
	s = smtplib.SMTP(smtphost)
	message = "From:" + frommail + "\nTo:" + tomail + "\nSubject:" + subjectmail + "\n" + mailcontent
	s.sendmail(frommail,tomail,message)
	s.quit()

class ProcessManager(pyinotify.ProcessEvent):
	global mailcontent
	mailcontent = ''

	def process_IN_ACCESS(self, event):
		mailcontent = "Accessed: %s " % os.path.join(event.path, event.name)
		sendmail(mailcontent)
	def process_IN_CREATE(self, event):
		mailcontent = "Created: %s " % os.path.join(event.path, event.name)
		sendmail(mailcontent)
	def process_IN_OPEN(self, event):
		mailcontent = "Opened: %s " % os.path.join(event.path, event.name)
		sendmail(mailcontent)

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

