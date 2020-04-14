#coding:utf8
from config import *
from crawl import *
import tkinter as tk
#from gui import change
from vul_module import vul_module


def vulscan_P(target1,thread_num,depth,module,output,logfile,waf):
	global QUEUE
	global TOTAL_URL
	for target in target1:
		print("[+] start scan target " + target + '...' + '\n')
		logfile.write("[+] start scan target " + target + '...' + '\n')
		i = 1

		QUEUE.append([0,target])
		TOTAL_URL.add(target)
		SpiderThread(target, [0,target],logfile,module,output).start()
		quit_flag = 0
		while(quit_flag == 0):
			while True:
				try:
					deep_url = QUEUE.pop(0)
					break
				except Exception as e:
					if threading.activeCount() == 2:
						print("[-] All crawl finish..."+'\n')
						logfile.write("[-] All crawl finish..." + '\n')
						quit_flag = 1
						break
					else:
						# time.sleep(1)
						continue
			while True:
				if deep_url[0] == depth + 1:
					break
				try:
					if threading.activeCount() < thread_num:
						# i += 1
						# print i
						SpiderThread(target, deep_url, logfile, module,output).start()
						break
				except Exception as e:
					# self.logfile.write( '\tError:' + str(e) + '\n')
					# self.logfile.flush()
					time.sleep(1)
					pass



def vulscan(target,thread_num,depth,module,output,logfile,waf):
	global QUEUE
	global TOTAL_URL
	print("[+] start scan target " + target + '...' + '\n')
	logfile.write("[+] start scan target " + target + '...' + '\n')
	i = 0

	QUEUE.append([0,target])
	TOTAL_URL.add(target)
	SpiderThread(target, [0,target],logfile,module,output,waf).start()
	quit_flag = 0
	while(quit_flag == 0):
		while True:
			try:
				deep_url = QUEUE.pop(0)
				break
			except Exception as e:
				if threading.activeCount() == 2:
					print("[-] All crawl finish..."+'\n')
					logfile.write("[-] All crawl finish..." + '\n') 
					quit_flag = 1
					break
				else:
					# time.sleep(1)
					continue
		while True:
			if deep_url[0] == depth + 1:
				break
			try:
				if threading.activeCount() < thread_num:
					# i += 1
					# print i
					SpiderThread(target, deep_url, logfile, module,output,waf).start()
					break
			except Exception as e:
				# self.logfile.write(get_time() + '\tError:' + str(e) + '\n')
				# self.logfile.flush()
				time.sleep(1)
				pass
	return 1
	'''
	quit_flag = 0
	total_url_list = list(TOTAL_URL)
	while(quit_flag == 0):
		while True:
			try:
				url = total_url_list.pop(0)
				break
			except Exception,e:
				print e
				if threading.activeCount() == 1:
					print "All Scan Finish..."
					quit_flag = 1
					break
					#exit(0)
				time.sleep(1)
		
		while True:
			try:
				if threading.activeCount() < thread_num:
					vul_module(url,logfile).start()
					break
			except Exception,e:
				print e
				time.sleep(1)
				pass
	'''


	

