#!/bin/python

# Enable verbose logging
enable_logging = True

# These keywords will be fuzzed so that look-alike domain matches are identified 
keywords = ['google', 'amazon', 'facebook']

# These keywords will NOT be fuzzed. Useful for searching for domains that contains specific words (i.e., 'prod', 'database', 'bucket', etc...) 
no_fuzz_keywords = ['userdata', 'admin', 'database']

# These keywords will be ingored.  If a domain contains any of these keywords, then it will not be included in the results
ignore_keywords = []

# Save all matched domains to a csv file.  CSV file has three columns (timestamp, matched_keyword, domain)
enable_csv_output = True
output_csv_file = "certpipe_matches.csv"

# Slack alerting configuration
enable_slack = False
slack_token = "<INSERT SLACK API TOKEN HERE>"
slack_channel = "<INSERT SLACK CHANNEL HERE>"

# Syslog configuration TODO
#enable_syslog = False
#syslog_server = "10.10.11.18"
#syslog_port = 514

# TODO
#scan_matches = False
#screenshot_matches = False
