#!/bin/bash
# Script must be placed in $SPLUNK_HOME/bin/scripts along with adding +x permissions (chmod +x)
#
# This script is intended to leverage the Alerting capabilities of Splunk to identify and globally mitigate offensive behaviour using SkyATP's Blacklist feature
# SkyATP Threat Intel API is here http://www.juniper.net/techpubs/en_US/release-independent/sky-atp/information-products/topic-collections/sky-atp-cloudfeed-open-apis.html
#
# Define SkyATP Application Token (Paste in your value between the "")
APPToken="Your_Application_Token_Here"
# Define the name of the feed you wish to create
FeedName="IPS_Blacklist"
#
# Search Filter being used within Splunk to generate the Alert:
# sourcetype="juniper_srx" RT_IDP source_zone_name="Outside" AND (threat_severity="CRITICAL" OR threat_severity="HIGH")
#
# $8 is a predefined variable by Splunk. This variable contains the full path to the gzip'd file with the log entry that triggered the alert

# Generate a unique folder to store our results in
time=`date +'%d%m%y_%H%M%S%N'`
TempDirectory=/var/tmp/$time
mkdir $TempDirectory

# Generate Temporary File to store results in
TempFile=$TempDirectory/bad_ip.txt

#Copy our log file to the new $TempDirectory
cp $8 $TempDirectory
cd $TempDirectory

# Extract the compressed file
gunzip -d *.gz

#Parse file for IP's, then select the 4th item (Source Address) from the log field. This is what we'll add to our blacklist

grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' tmp_0.csv | awk 'NR==4' > $TempFile

#  the output for the IP and add it to your desired BlackList

curl -k -XPATCH -H "Authorization: Bearer $APPToken" -F file=@${TempFile} https://threat-api.sky.junipersecurity.net/v1/cloudfeeds/blacklist/file/ip/${FeedName} 2>&1 | tee -a curl_output.txt

# Cleanup and Exit

cd ..

rm -rf $TempDirectory
