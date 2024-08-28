# haveibeenpwned
This script allows you to interact with the HaveIBeenPwned (HIBP) API to check email addresses against known data breaches. It can be used anywhere with Python in a CLI or indirectly integrated into a SIEM like Splunk, Microsoft Sentinel, or AlienVault. Although there is a Splunk add-on available on Splunkbase, it may not function as required for all use cases. For me, it did not function at all. If the add-on meets your needs, I would recommend using it. [Add-On for HaveIBeenPwned](https://splunkbase.splunk.com/app/5050)

> [!WARNING]
> To use this script, you **must purchase an API key.**
> 
> Purchase from HaveIBeenPwned https://haveibeenpwned.com/API/Key. Add your API Key to line 19. 

## Use Cases
**1. Employee Email Monitoring:** Run employee email addresses through this script and output the results to a file. The resulting CSV file can be ingested into SIEM tools to enhance Risk-Based Analytics (RBA) by adding breach risk indicators.

**2. Breach Monitoring:** Regularly monitor for new breaches to keep your organization's security posture up-to-date.


## How to use

**Run Test Mode:** Use the -t or --test flag to run tests and verify script functionality.

`python3 haveibeenpwned.py --test`

**Simple Output Mode:** Use the -s flag for a simplified output that only includes breach titles and dates.

`python3 haveibeenpwned.py -s "a@aim.com"`

**Output Results to a File:** Use the -o or --output flag to write results to a specified file.

`python3 haveibeenpwned.py --output outputFile.txt`

**Console and File Output:** Use the -c or --console flag to display results in the console while simultaneously writing them to a file.

`python3 haveibeenpwned.py -c --output outputFile.csv`

**Specify Email Column in CSV:** Use the -n or --fieldname flag in conjunction with the -f or --filename flag to specify the column containing email addresses, or leave it blank if the emails are in the first column.

`python3 haveibeenpwned.py --filename emails.csv --fieldname "userPrincipalName"`

> [!NOTE]
> This python represents a pretty cool milestone for me as it is the first script I developed.
