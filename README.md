# stigcli

# Disclaimer - This repository is not affiliated or has no ties to DISA or the Department of Defense. This an open source repository and is licensed under MIT. See the repo license for further detail. 

This tool was developed to help solve scaling challenges working with DoD STIG Checklist files and provides an alternative method to working with the DoD STIG Viewer. It provides security engineers and managers and with a CLI tool with the following features:

## Report

Traverses a directory searching for STIG .ckl and .cklb files and extracts the STIG Id, Severity, Status, Title, Comment, and FindingDetails into a CSV file.

`stigcli report directorypath`

Optionally include a path to a CCI file to include STIG CCI information. This is useful to correlate STIGs with CCI controls. Including this parameter will tell the stigcli to map the STIG with the CCI XML and include relevant CCI data in the report export.

`stigcli report directorypath --cci_xml_path ./U_CCI_List.xml`

## Modify

Bulk management of STIG Checklist modifications through a CSV spreadsheet, automatically updating STIGs using a simple rule language to modify to comments, status, or finding details.

`stigcli modify 'stig_updates.csv' './stig_checklist_directory`

The .csv file is used to tell the stigcli how it should search and modify items within a STIG checklist. The first three columns Id,Hostname,Status,Comment are search parameter used to search for STIG items within a checklist file. If one of the fields is defined within the row, the stigcli will use that as a search paramter. If the field is blank, it will not be used within the search. The fields FindingDetails, StatusUpdate, CommentUpdate tell the stigcli to update these fields with the data provide if there is a match.

For example, the following CSV file will 

- Find STIG V-222949, update its status to NotAFinding, and update the comment field with the reason why it is not a finding.
- Find STIG V-214274, update its status to NotAFinding, and update the comment field with the reason why it is not a finding.

| Id       | Hostname | Status | Comment | FindingDetails | StatusUpdate | CommentUpdate                                                                                                   | FindingDetailsUpdate |
|----------|----------|--------|---------|---------------|--------------|-----------------------------------------------------------------------------------------------------------------|----------------------|
| V-222949 |          |        |         |               | NotAFinding  | The generic tomcat user is not used for the application, therefor this finding could not be checked properly. The actual tomcat user used in the application has the correct UMASK applied.                          |                      |
| V-214274 |          |        |         |               | NotAFinding  | httpasswd files are used within the apache tomcat instance.                                                                                     |                      |

If you file in multiple fields on a row, it will further define the search criteria when scripting the update fields. For example, the following file will only update V-222949 if the checklist file hostname field is dev-tomcat1.

| Id       | Hostname | Status | Comment | FindingDetails | StatusUpdate | CommentUpdate                                                                                                   | FindingDetailsUpdate |
|----------|----------|--------|---------|---------------|--------------|-----------------------------------------------------------------------------------------------------------------|----------------------|
| V-222949 |  dev-tomcat1        |        |         |               | NotAFinding  | The generic tomcat user is not used for the application, therefor this finding could not be checked properly. The actual tomcat user used in the application has the correct UMASK applied.                          |                      |
| V-214274 |          |        |         |               | NotAFinding  | httpasswd files are used within the apache tomcat instance.   

The update process also supports searching for the absence of data by placing a dash `-` in the column. For example, the following CSV file will update any comment that are blank with new comment.

| Id       | Hostname | Status | Comment | FindingDetails | StatusUpdate | CommentUpdate                                                                                                   | FindingDetailsUpdate |
|----------|----------|--------|---------|---------------|--------------|-----------------------------------------------------------------------------------------------------------------|----------------------|
|  |         |        |    -     |               |  | A comment applied to all STIG comments if a comment doesnt exist                       |                      |

## Convert (Still in Development)

Bulk Automation of converting CKL files to CKLB files. Point the tool at a directory of CKL and get a directory output of updated CKLB files.

## Update (Still in Development)

Bulk automation of upgrading STIG Checklist when new versions come out. This command will traverse a directory of checklist files and search a directory of STIG XML Definition files, determining if there is an update present, and update the checklist to the new version -- adding, removing, and modifying checklist content.

`stigcli update ./stig_checklist_direcotry ./artifacts/stig_xml_definition_directory`

## Download

A common tool to download STIGs and CCI XML files directly from the DISA website.

The following command will download the latest U_SRG-STIG_Library release from the DISA website, extract the zip and obtain all STIG xml. This is useful for the update command to gather input for all the latest quarterly STIG releases.

`stigcli download stigs`

The following command will download the latest U_CCI_List.zip from the DISA website and extract the zip to obtain the U_CCI_List.xml. This is useful for the report command above.

`stigcli download cci`

## Known Limitations 
- STIG Update command is still in development and needs a few more modifications before it is feature completed
- Current version only supports one STIG per checklist file. Multiple STIG checklists per file is currently not supported, but on the backlog.



