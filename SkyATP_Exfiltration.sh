#!/bin/bash
# Script must be placed in $SPLUNK_HOME/bin/scripts along with adding +x permissions (chmod +x)
#
# This script is intended to leverage the Alerting capabilities of Splunk to identify and prevent Data Exfiltration occuring as outlined in the blog post
# SkyATP Threat Intel API is here http://www.juniper.net/techpubs/en_US/release-independent/sky-atp/information-products/topic-collections/sky-atp-cloudfeed-open-apis.html
#
# Define SkyATP Application Token (Paste in your value between the "")
APPToken="Your_Application_Token_Here"
#
# Define the name of the feed you wish to leverage. 
FeedName="Splunk_Exfil"
#
# FeedName specified above must be created prior to deploying this alert. Example below using a feed named "Splunk_IPS_Blacklist"
# curl -k -v -XPOST -H "Authorization: Bearer Your_App_Token" -F file=@badip.txt https://threat-api.sky.junipersecurity.net/v1/cloudfeeds/blacklist/file/ip/Splunk_Exfil
#
# Search Filter being used within Splunk to generate the Alert (sourcetype should be modified to your own environment - you may have called it something else other than juniper:srx):
# sourcetype="juniper:srx" APPTRACK_SESSION AND source_zone_name="Inside" | where application="UNSPECIFIED_ENCRYPTED" OR application="OPENVPN" OR application="SSH" OR application="SSL"| where packets_from_server > 1000 AND ((bytes_from_server / bytes_from_client)*100) < 5 
#
# $8 is a predefined variable by Splunk. 
# This variable contains the full path to the gzip'd file with the log entry that triggered the alert

# Generate a unique string based on the exact time to name our directory with
time=`date +'%d%m%y_%H%M%S%N'`
# Declare and create a unique directory to store our results in named with $time
TempDirectory=/var/tmp/$time
mkdir $TempDirectory

# Generate Temporary File to store results in
TempFile=$TempDirectory/bad_ip.txt

#Copy Splunk's compressed alert to the new $TempDirectory
cp $8 $TempDirectory
cd $TempDirectory

# Extract the compressed alert
gunzip -d *.gz

#Parse file for IP's, then select the 5th item (Destination Address) from the log field. This is what we'll add to our blacklist

grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' tmp_0.csv | awk 'NR==5' > $TempFile

#  the output for the IP and add it to your desired BlackList

curl -v -k -XPATCH -H "Authorization: Bearer $APPToken" -F file=@${TempFile} https://threat-api.sky.junipersecurity.net/v1/cloudfeeds/blacklist/file/ip/${FeedName} 2>&1 | tee -a curl_output.txt

# Cleanup and Exit

cd ..

# For troubleshooting purposes, you can comment out the 'rm -rf' below and see the output from curl within curl_output.txt
rm -rf $TempDirectory
