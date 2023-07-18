'''********************

requirements:

  o VT Intelligence Premium access (collections)
  o Python 3.6 or higher
  o sudo apt install python3-pip
  o pip install vt-py (to use vt module)

Prior to running script, assign a valid VirusTotal API key to the KEY variable.
  
********************'''

import argparse
import os
import requests
import vt
import datetime
from dateutil.relativedelta import *


KEY = ''  # add VirusTotal API key here
limit = 300

flimit = 1000  # max number of files to query for behavior info (modify based on VirusTotal account limits)
dc_files = {}  # dictionary that will store file hashes & attributes used for output


def main():
	
	timeframe = 12  # months to subtract from edate (enddate) for query start date
	global edate
	global sdate
	global search_term
	
	parser = argparse.ArgumentParser(
		description='Query VirusTotal for TTPs on a specific malware family or threat actor.')
		
	parser.add_argument('-e', '--enddate',
		type=check_date,
		required=False,
		help=f'Specify end date of search timeframe using format YYYY-MM-DD. ' \
			f'If no end date (-e), start date (-s), or month count (-m) ' \
			f'is specified, the timeframe for the query will ' \
			f'automatically cover the last {timeframe} months through ' \
			f'today\'s date. ' \
			f'Use end date (-e) and/or start date (-s) '\
			f'to choose a specific timeframe to search. Options for ' \
			f'specifying search timeframe:' \
			f'\tSTART DATE (-s) + END DATE (-e) - If both start and end ' \
			f'dates are specified, the search will be conducted between ' \
			f'the two dates specified.' \
			f'\tEND DATE ONLY - If end date is specified with no other ' \
			f'search date options, this tool will automatically start ' \
			f'the search {timeframe} months prior to the specified end ' \
			f'date.' \
			f'\tMONTH (-m) ONLY - If -m <int> option alone is specified, ' \
			f'the integer value entered for -m will be subtracted from ' \
			f'today\'s date to determine the start date of the search ' \
			f'timeframe.'
			f'\tEND DATE (-e) + MONTHS (-m) If the end date is specified ' \
			f'with the month option, the start date will be m months ' \
			f'prior to the specified start date.')

	parser.add_argument('-l', '--limit',
		type=int,
		required=False,
		default=10,
		help=f'Specify integer value as limit to the max number of items ' \
			f'returned for each VirusTotal query; the default is {str(limit)}')
	
	parser.add_argument('-m', '--months',
		type=int,
		required=False,
		help=f'Used to specify timeframe (in number of months) that the ' \
			f'query will cover. If no end date (-e), start date (-s), ' \
			f'or month count (-m) is specified, the timeframe for the ' \
			f'query will automatically cover the last {timeframe} ' \
			f'months through today\'s date. The month count (-m) option ' \
			f'cannot be used with the start date (-s) option. ')

	parser.add_argument('-n', '--name',
		type=str,
		required=True,
		help='Specify the name of the threat actor or malware family to search. ' \
			'Enter only one term per search; if searching a threat actor ' \
			'group, other aliases or alternative names for that group ' \
			'will automatically be searched based on alternative names ' \
			'documented in VirusTotal\'s threat actor aliases.')

	parser.add_argument('-s', '--startdate',
		type=check_date,
		required=False,
		help=f'Specify start date of search timeframe using format YYYY-MM-DD. ' \
			f'If no end date (-e), start date (-s), or month count (-m) ' \
			f'is specified, the timeframe for the query will ' \
			f'automatically cover the last {timeframe} months through ' \
			f'today\'s date.' \
			f'Options for specifying search timeframe using -m option:\n' \
			f'\tMONTH (-m) ONLY - If -m <int> option alone is specified, ' \
			f'the integer value entered for -m will be subtracted from ' \
			f'today\'s date to determine the start date of the search ' \
			f'timeframe.'
			f'\tEND DATE (-e) + MONTHS (-m) If the end date is specified ' \
			f'with the month option, the start date will be m months ' \
			f'prior to the specified start date.' \
			f'See start date (-s) and end date (-e) options for further ' \
			f'details on modifying search time frames.')

		
	args = parser.parse_args()
	
	search_term = args.name

	if args.startdate is not None and args.months is not None:
		print('The --months (-m) and --startdate (-s) options cannot be ' \
			'used at the same time. Please re-enter a valid query that ' \
			'does not use both of these options.')
		exit(0)

	if args.months is not None:
		timeframe = args.months
	
	if args.enddate is None:
		edate = datetime.datetime.now()
	else:
		edate = args.enddate
		sdate = edate + relativedelta(months=-timeframe)
	
	if edate > datetime.datetime.now():
		print('End date entered occurs later than today. Please check ' \
			'the end date and ensure it occurs on or before today.')
		exit(0)
	
	if args.startdate is None:
		sdate = edate + relativedelta(months=-timeframe)
	else:
		sdate = args.startdate
	
	if edate < sdate:
		print('Error: End date cannot come before start date. Please ' \
			'check dates and try again.')
		exit(0)

	print('sdate\t' + sdate.strftime('%Y-%m-%d %H:%M:%S') + \
		'\nedate\t' + edate.strftime('%Y-%m-%d %H:%M:%S'))

	query(search_term)


def check_date(date):
	try:
		return datetime.datetime.strptime(date, "%Y-%m-%d")
	except ValueError:
		msg = f'The date you entered (\'{date}\') is in an invalid format. ' \
			f'Please enter a date using the format \'YYYY-MM-DD.\''
		raise argparse.ArgumentTypeError(msg)


def query(search_term):
	
	''' ****************************************************************
	Gathers files from individual file searches for the
	specified threat actor group or malware, then gets file attributes 
	and ATT&CK technique ids based on files returned
	*****************************************************************'''

	
	if len(dc_files) < flimit:
		with vt.Client(KEY) as client:
		
			''' get all alt names for given threat group (if available);
			use all names found to search for matching files '''
			try:
				threat_actor = client.get_object('/threat_actors/' + \
					search_term)
				
				for alias in threat_actor.aliases:
					files = client.iterator('/intelligence/search',
						params={'query': get_query_string(alias)},
						limit=limit)
				

					for each in files:
						try:
							fid = each.id
							print(fid)
						except:
							fid = 'NULL'
							print('fid not found')
							
						try:
							fdate = each.first_submission_date
						except:
							fdate = 'NULL'
							print('fdate not found')
						
						if fid != 'NULL' and fdate != 'NULL':
							if (len(dc_files) < flimit) and (fid not in dc_files):
								strfdate = fdate.strftime('%Y-%m-%d %H:%M:%S')
								dc_fileobj = get_file_data(fid, strfdate)
								dc_files[fid] = dc_fileobj
								dc_files[fid]['collection_ids'] = 'NULL'
								dc_files[fid]['collection_names'] = 'NULL'
								print(f'Files found: {str(len(dc_files))} - {fid}\t{fdate}')
			
			except:
				print('No alternative search terms found for ' + search_term)
				files = client.iterator('/intelligence/search',
					params={'query': get_query_string(search_term)},
					limit=limit)
				
				for each in files:
					try:
						fid = each.id
					except:
						fid = 'NULL'
						
					try:
						fdate = each.first_submission_date
					except:
						fdate = 'NULL'
					
					if fid != 'NULL' and fdate != 'NULL':
						if (len(dc_files) < flimit) and (fid not in dc_files):
								strfdate = fdate.strftime('%Y-%m-%d %H:%M:%S')
								dc_files[fid] = get_file_data(fid, strfdate)
								dc_files[fid]['collection_ids'] = 'NULL'
								dc_files[fid]['collection_names'] = 'NULL'
								print(f'Files found: {str(len(dc_files))} - {fid}\t{fdate}')
	output_data()


def collections_query(search_term):
	
	''' ****************************************************************
	Gathers files from collections and individual file searches for the
	specified threat actor group or malware, then gets file attributes 
	and ATT&CK technique ids based on files returned
	*****************************************************************'''

	
	'''
	search for collections, and if any are found, gather relevant files 
	for each; stop adding files if max file limit (flimit) is reached
	'''
	print('Searching collections for files...')
	
	ls_collections = get_collections(search_term)
	
	if len(ls_collections) > 0:
		
		with vt.Client(KEY) as client:

			for collid in ls_collections:
				
				if len(dc_files) < flimit:
				
					collection = client.get_object(f'/collections/{collid}')
					collname = collection.name
					
					print(f'collection filecount for {collid}: {str(collection.files_count)}')
					
					if collection.files_count > 0 and collection.files_count < 1000:
						flist = client.iterator(f'/collections/{collid}/files')
						
						for fileobj in flist:
							
							try:
								fid = fileobj.id
							except:
								fid = 'NULL'
							
							try:
								fdate = fileobj.first_submission_date
							except:
								fdate = 'NULL'
								
							try:
								fsubmit = fileobj.times_submitted
							except:
								fsubmit = 'NULL'
							

							if (fid != 'NULL' and fdate != 'NULL' and fsubmit != 'NULL'):
								if len(dc_files) < flimit:
									if (fdate >= sdate and fdate <= edate and fsubmit > 1):
										ls_collids = []
										ls_collnames = []
										
										if fid not in dc_files:
											strfdate = fdate.strftime('%Y-%m-%d %H:%M:%S')
											dc_fileobj = get_file_data(fid, strfdate)
											
											dc_files[fid] = dc_fileobj
											dc_files[fid]['collection_ids'] = ls_collids
											dc_files[fid]['collection_names'] = ls_collnames
											dc_files[fid]['collection_ids'].append(collid)
											dc_files[fid]['collection_names'].append(collname)
											print(f'Files found: {str(len(dc_files))} - {fid}\t{fdate}')
											
										else:
											dc_files[fid]['collection_ids'].append(collid)
											dc_files[fid]['collection_names'].append(collname)

								else:
									print(f'flimit of {flimit} has been met')
									break

					if len(dc_files) == 0:
						print('No collection files found matching search ' \
							'criteria.')
				else:
					print(f'flimit of {flimit} has been met')
					break
	else:
		print('No collection files found matching search ' \
			'criteria.')

	
	# conduct VT intelligence search for individual files assoc w/ threat actor
	if len(dc_files) < flimit:
		print('SEARCHING INDIVIDUAL FILES...')
		with vt.Client(KEY) as client:
		
			''' get all alt names for given threat group (if available);
			use all names found to search for matching files '''
			try:
				threat_actor = client.get_object('/threat_actors/' + \
					search_term)
				
				for alias in threat_actor.aliases:
					files = client.iterator('/intelligence/search',
						params={'query': get_query_string(alias)},
						limit=limit)
				

					for each in files:
						try:
							fid = each.id
							print(fid)
						except:
							fid = 'NULL'
							print('fid not found')
							
						try:
							fdate = each.first_submission_date
						except:
							fdate = 'NULL'
							print('fdate not found')
						
						if fid != 'NULL' and fdate != 'NULL':
							if (len(dc_files) < flimit) and (fid not in dc_files):
								strfdate = fdate.strftime('%Y-%m-%d %H:%M:%S')
								dc_fileobj = get_file_data(fid, strfdate)
								dc_files[fid] = dc_fileobj
								dc_files[fid]['collection_ids'] = 'NULL'
								dc_files[fid]['collection_names'] = 'NULL'
								print(f'Files found: {str(len(dc_files))} - {fid}\t{fdate}')
			
			except:
				print('No alternative search terms found for ' + search_term)
				files = client.iterator('/intelligence/search',
					params={'query': get_query_string(search_term)},
					limit=limit)
				
				for each in files:
					try:
						fid = each.id
					except:
						fid = 'NULL'
						
					try:
						fdate = each.first_submission_date
					except:
						fdate = 'NULL'
					
					if fid != 'NULL' and fdate != 'NULL':
						if (len(dc_files) < flimit) and (fid not in dc_files):
								strfdate = fdate.strftime('%Y-%m-%d %H:%M:%S')
								dc_fileobj = get_file_data(fid, strfdate)
								dc_files[fid] = dc_fileobj
								dc_files[fid]['collection_ids'] = 'NULL'
								dc_files[fid]['collection_names'] = 'NULL'
								print(f'Files found: {str(len(dc_files))} - {fid}\t{fdate}')
	output_data()

def get_collections(search_term):
	'''******************************************************************
	Gathers all alternative names for the search term entered by user,
	searches for all collections based on those alternative names,
	and returns list of collection ids based on search.
	******************************************************************'''	
	ls_collids = []
	ls_aliases = []
	
	
	with vt.Client(KEY) as client:
		
		''' get all alt names for given threat group (if available);
		use all names to search for collections '''
		try:
			threat_actor = client.get_object('/threat_actors/' + \
				search_term)
			
			ls_aliases = threat_actor.aliases
						
		except:
			print('No threat actor aliases found. Continuing search ' \
				'with original search term by itself.')
		
		if len(ls_aliases) > 0:
			
			print(f'Found {str(len(ls_aliases))} alternative names to ' \
				'search. Searching for collections...')
			
			for alias in ls_aliases:
				collections = client.iterator('/intelligence/search',
					params={'query': 'entity:collection name:' + alias + \
						' last_modification_date:' + \
						sdate.strftime('%Y-%m-%d') + '+' \
						' files:1+ files:1000-'},
					limit=limit)
				
				for each in collections:
					try:
						coll_id = each.id
						print(f'Collection date: {each.last_modification_date}')
					except:
						coll_id = 'NULL'
					else:
						ls_collids.append(coll_id)
		else:
			
			collections = client.iterator('/intelligence/search',
				params={'query': 'entity:collection name:' + search_term + \
					' last_modification_date:' + \
					sdate.strftime('%Y-%m-%d') + '+' \
					' files:1+ files:1000-'},
				limit=limit)
			
			for each in collections:
				try:
					coll_id = each.id
				except:
					coll_id = 'NULL'
					
				else:
					ls_collids.append(coll_id)
	
	# dedupe list of collection ids found to avoid redundant queries
	ls_collids.sort()
	ls_collids = list(dict.fromkeys(ls_collids))
	
	counter = 1
	for collid in ls_collids:
		print(f'{counter} - {collid}')
		counter += 1
	
	print(f'Number of collections found to search: {str(len(ls_collids))}')
	return ls_collids


def get_file_data(fid, fdate):
	dc_fileobj = {}
	ls_sandboxes = []
	
	with vt.Client(KEY) as cl:
		fileobj = cl.get_object(f'/files/{fid}')
		
		try:
			ftype = fileobj.type_description
		except:
			ftype = 'not found'
			
		try:
			cdate = (fileobj.creation_date).strftime('%Y-%m-%d %H:%M:%S')
		except:
			cdate = 'not found'
		
		try:
			mdate = (fileobj.last_modification_date).strftime('%Y-%m-%d %H:%M:%S')
		except:
			mdate = 'not found'
		
		try:
			submissions = str(fileobj.times_submitted)
		except:
			submissions = 'not found'
		
		try:
			for verdict in (fileobj.sandbox_verdicts).values():
				ls_sandboxes.append(verdict.get('sandbox_name'))
		except:
			ls_sandboxes.append('not found')
			
	dc_attack = get_attackdata(fid)		
		
	dc_fileobj = {'sha256':fid,
		'first_submitted_to_vt':fdate,
		'file_type':ftype,
		'creation_date':cdate,
		'modification_date':mdate,
		'times_submitted':submissions,
		'attack_ids':dc_attack,
		'sandbox_info':ls_sandboxes}
	
	return dc_fileobj


def get_query_string(search_term):
	
	'''*****************************************************************
	builds and returns query string for VTI search based on search term
	provided
	*****************************************************************'''
	
	qstring = f'entity:file' \
		f' (min_engines_{search_term}:5' \
		f' OR (engines:{search_term} crowdsourced_yara_rule:{search_term})' \
		f' OR (engines:{search_term} crowdsourced_ids:{search_term})' \
		f' OR (engines:{search_term} suggested_threat_label:*{search_term}*)' \
		f' OR (crowdsourced_yara_rule:{search_term} crowdsourced_ids:{search_term})' \
		f' OR (crowdsourced_yara_rule:{search_term} suggested_threat_label:*{search_term}*)' \
		f' OR (crowdsourced_ids:{search_term} suggested_threat_label:*{search_term}*))' \
		' has:behavior' + \
		' fs:' + sdate.strftime('%Y-%m-%d') + '+' + \
		' fs:' + edate.strftime('%Y-%m-%d') + '-' + \
		' submissions:3+' + \
		' sources:3+' + \
		' p:5+'
	
	return qstring


def get_attackdata(fid):
	
	''' Fetch attack data associated with file based on id; store data '''
	
	dc_attackids = {}
	
	with vt.Client(KEY) as beh_cl:
		behaviors = beh_cl.iterator(f'/files/{fid}/behaviours')
		
		for each in behaviors:
			beh_id = each.id
			
			with vt.Client(KEY) as att_cl:
				attack_info = att_cl.iterator(f'/file_behaviours/{beh_id}/attack_techniques')

				for technique in attack_info:
					try:
						tid = technique.id
					except:
						tid = 'NULL'
						
					try:
						tname = technique.name
					except:
						tname = technique.name
					else:
						dc_attackids[tid] = tname
							
	return dc_attackids


def output_data():
	
	attdir = os.path.join(os.environ['HOME'], 'attack_data')
	outdate = sdate.strftime('%Y%m%d') + '_' + edate.strftime('%Y%m%d')
	filename = f'attack_{search_term}_{outdate}.txt'
	ls_ttps = []
	
	if not os.path.isdir(attdir):
		os.mkdir(attdir)
	
	ofile = open(os.path.join(attdir, filename), 'w')
	
	ls_headings = ['FUID',
		'File Type',
		'Creation Timestamp',
		'Last Modified Timestamp',
		'First Submitted to VT',
		'Times Submitted to VT',
		'Technique ID',
		'Technique Name',
		'Technique',
		'Sandbox Info',
		'Collection IDs',
		'Collection Names']
	
	for h in ls_headings:
		ofile.write(h + '\t')
	
	for data in dc_files.values():
		
		for tid, ttp in data['attack_ids'].items():
			ofile.write('\n' + data['sha256'] + '\t' + \
				data['file_type'] + '\t' + \
				data['creation_date'] + '\t' + \
				data['modification_date'] + '\t' + \
				data['first_submitted_to_vt'] + '\t' + \
				data['times_submitted'] + '\t' + \
				tid + '\t' + \
				ttp + '\t' + \
				tid + ': ' + ttp + '\t' + \
				str(data['sandbox_info']) + '\t' + \
				str(data['collection_ids']) + '\t' + \
				str(data['collection_names']))
			ls_ttps.append(ttp)
	
	ofile.close()
	
	if len(ls_ttps) > 0:
		print('The following file contains the output ATT&CK TTPs: ' + \
			attdir + filename)
	else:
		print('No ATT&CK TTPs were found for the files that met the ' + \
			'search criteria.')
	
	
if __name__ == '__main__':
	main()
