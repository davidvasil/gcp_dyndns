# gcp_dyndns

<p align=center>
<img src=./images/DNS_logo.png alt="creative commons dns logo">
</p>
  
Update GCP DNS resource records with GCE instance ephemeral natIP.  Keep your external hostname up to date with your GCE instance natIP without paying for a static IP.  
  
* GCP DNS
* GCP Compute
  
Uses the googleapiclient to get the current A record for a resource record set in a managed zone, then compares that against the current natIP for a GCE instance specified in the config file.  Updates the GCP DNS resource record if necessary and logs the information in JSON format to either a file or stderr.

## Quickstart
Edit `gcp_dyndns.config-EXAMPLE` to include the service account credential file, GCP project ID, GCP DNS information, and GCE instance information.  Run the script by specifying the config location using the only available argument.  
  
```
python3 gcp_dyndns.py --config gcp_dyndns.config
```

## Service account permissions
The service account needs specific permissions in order to view/edit GCP DNS details and also view GCP compute instance information.  
  
The bare minimum permissions required are:  
* compute.instances.get
* dns.changes.create
* dns.managedZones.list
* dns.resourceRecordSets.list
* dns.resourceRecordSets.update

These can be assigned at the project level assuming your compute instance and dns zones are in the same project.

## Config file options
|Config Option|Notes|
|---|---|
|gcp_cred_file|Service Account Credential File in JSON format|
|project_id|Project Name|
|zone_name|Cloud DNS Zone Name as it appears in the Cloud DNS console (with - instead of . )|
|a_record|FQDN Cloud DNS zone record DNS name as it appears in the Cloud DNS console|
|gce_instance|GCE Instance name|
|gce_zone|The zone where the GCE instance resides|
|log_file|Full path to the log file you want to output results to|
