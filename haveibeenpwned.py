#!/usr/bin/env python
# Created: 08/30/2024
# Author: crysys
# Purpose: Retrieve breached domain from response in case of a breach
# TODO: You'll need to purchase an API key from https://haveibeenpwned.com/API/Key

import requests
import time
import argparse
import os
import json
import csv
import logging
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

# TODO: Add APIKEY
API_KEY = str("")

SERVER = "haveibeenpwned.com"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
RATE_LIMIT = 1.3
HEADERS = {
	"hibp-api-key": API_KEY,
	"User-Agent": USER_AGENT
}
SSL_VERIFY = True

# ANSI code colors
OKGREEN = '\033[92m'
WARNING = '\033[93m'
ERROR = '\033[91m'
ENDC = '\033[0m'

# Logging Configuration
logging.basicConfig(
	filename='hibp.log',
	filemode='a',
	format='%(asctime)s %(levelname)s: %(message)s',
	level=logging.INFO,
	datefmt='%Y-%m-%d %H:%M:%S'
)

# Arguments
parser = argparse.ArgumentParser(description="Verify if email address has been pwned through HaveIBeenPwned API")
parser.add_argument("email", nargs="?", help="Single or multiple email addresses, comma-separated")
parser.add_argument("-f", "--filename", help="File with one email address per line")
parser.add_argument("-t", "--test", action='store_true', help="Runs test to ensure script is working")
parser.add_argument("-c", "--console", action="store_true", help="Print logs to console")
parser.add_argument("-s", "--simple", action="store_true", help="Only print titles of breaches [Single mode only]")
parser.add_argument("-n", "--fieldname", help="Name of the column containing emails")
parser.add_argument("-o", "--output", dest="outputFile", help="Output file to write results to")
args = parser.parse_args()

def main():
	if args.console:
		console = logging.StreamHandler()
		console.setLevel(logging.INFO)
		formatter = logging.Formatter("%(message)s")
		console.setFormatter(formatter)
		logging.getLogger('').addHandler(console)

	emails_to_check = []

	if args.filename:
		emails_to_check = load_emails_from_file(args.filename)
	elif args.email:
		emails_to_check = [email.strip() for email in args.email.split(',')]
	if args.test:
		emails_to_check = ["account-exists@hibp-integration-tests.com", "account-doesnt-exist@hibp-integration-tests.com"]
	if not emails_to_check:
		logging.error("No emails provided for checking.")
		print(f"{ERROR}Error: No emails provided.{ENDC}")
		return
	if args.outputFile:
		with open(args.outputFile, 'w', newline='') as output_file:
			writer = csv.writer(output_file)
			writer.writerow(["Email", "Date", "Breach Status", "Title", "Breach Date", "Data Classes", "Verified", "Malware"])
			process_emails(emails_to_check, writer)
	else:
		process_emails(emails_to_check)

def load_emails_from_file(filename):
	_, file_extension = os.path.splitext(filename)
	if file_extension.lower() == ".txt":
		with open(filename) as file:
			return [line.strip() for line in file]
	elif file_extension.lower() == ".csv":
		with open(filename) as file:
			reader = csv.DictReader(file)
			return [row[args.fieldname] for row in reader]
	else:
		logging.error("Invalid file type. Please provide a .txt or .csv file.")
		print(f"{ERROR}Error: Invalid file type provided.{ENDC}")
		return []

def process_emails(emails, writer=None):
	for email in emails:
		check_breach_status(email, writer)

def check_breach_status(email, writer=None):
	response = requests.get(
		f"https://{SERVER}/api/v3/breachedaccount/{email}?truncateResponse=false&includeUnverified=true",
		headers=HEADERS,
		verify=SSL_VERIFY)
	if response.status_code == 404:
		logging.info(f"{email}: No breach found.")
		output = [[email, time.strftime("%Y-%m-%d"), "Not breached", "-", "-", "-", "-", "-"]]
	elif response.status_code == 200:
		breaches = response.json()
		output = format_breaches(email, breaches)
		logging.info(f"{email}: Breach found.")
	elif response.status_code == 401:  # Missing API Key
		print(ERROR + "[X]" + ENDC + WARNING + " API key is missing" + ERROR + " [X] HTTPS: " + OKGREEN + str(response.status_code) + ENDC)
		logging.critical(msg="[X] API Key is missing" + " [X] HTTPS:" + str(response.status_code))
		exit()
	elif response.status_code == 429:  # Rate limit triggered
		logging.warn(f"{WARNING}[!]{OKGREEN}Rate limit exceeded,{ENDC} retrying in {response.headers['Retry-After']} seconds!")
		sleep = float(response.headers['Retry-After'])
		time.sleep(sleep)
		check_breach_status(email)
	else:
		logging.error(f"Failed to check {email}: {response.status_code}")
		output = [email, time.strftime("%Y-%m-%d"), f"Error {response.status_code}", "-", "-", "-", "-", "-"]
	if writer:
		for entry in output:
			writer.writerow(entry)
	else:
		for entry in output:
			if args.simple:
				print(f"{WARNING}Breach Date:{ENDC} {str(entry[4])}\t{ERROR}Title:{ENDC} {str(entry[3])}")
			else:
				email_output = str(entry[0])
				date_output = str(entry[1])
				status_output = str(entry[2])
				title_output = str(entry[3])
				breach_date_output = str(entry[4])
				data_classes_output = str(entry[5])
				verified_output = str(entry[6])
				malware_output = str(entry[7])

				print(f"{ERROR}Email:\t\t\t{email_output}{ENDC}")
				print(f"{OKGREEN}Current Date:{ENDC}\t{date_output}")
				print(f"{OKGREEN}Breach Status:{ENDC}\t{status_output}")
				print(f"{OKGREEN}Title:{ENDC}\t\t\t{title_output}")
				print(f"{OKGREEN}Breach Date:{ENDC}\t{breach_date_output}")
				print(f"{OKGREEN}Data Classes:{ENDC}\t{data_classes_output}")
				print(f"{OKGREEN}Verified:{ENDC}\t\t{verified_output}")
				print(f"{OKGREEN}Malware:{ENDC}\t\t{malware_output}")
				print(f"\n")

def format_breaches(email, breaches):
	outputs = []
	for breach in breaches:
		outputs.append([
			email,
			time.strftime("%Y-%m-%d"),
			"Breached",
			breach['Title'],
			breach['BreachDate'],
			", ".join(breach['DataClasses']),
			breach['IsVerified'],
			breach['IsMalware']
		])
	return outputs

if __name__ == "__main__":
	main()
