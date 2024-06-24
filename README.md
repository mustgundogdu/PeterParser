# PeterParser

![](https://github.com/mustgundogdu/PeterParser/blob/main/logo.png)

## Explanation

The Peterparser tool is designed to parse event IDs and provide file output in CSV format, aiming to assist in detecting specific attacks.

![](https://img.shields.io/badge/Powershell-2CA5E0?style=for-the-badge&logo=powershell&logoColor=white)![](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
## Working Principle
Essentially, it sequentially exports the most commonly used event ID logs to CSV format for specific attacks. While doing this, it allows you to back up the files it generates by taking their unique hashes and compare the files generated within a certain period with the SHA hash information in the backup.

## Application area
Its primary use is to help system administrators parse event logs into CSV format using PowerShell, as well as to facilitate the detection of specific and well-known AD attacks.

## Requirements
### ! Note: A properly configured SMB share named 'dcLog' should be created by default with NTFS permissions set correctly (restricted to authorized users only). If specifying a local file path instead of creating an SMB share is preferred, the '$Folder' variable in the 'shareChecking.ps1' file can be set to the file path.


## Event IDs

#### 4769
This event id indicates that a client has requested a Kerberos service ticket to access a specific service.
## Important Areas:

- Target Server
- Service Name
- Ticket Options
- Ticket Encryption Type
- Client Address
- Client Port
### Kerberoasting Detection
When the 'TicketEncryptionType' log value is 0x3, 0x18, or 0x17 in the detection of a Kerberoasting attack, it is assumed that a Kerberoasting attack has been carried out. This is due to Kerberos tickets being signed with a encryption algorithm not supported by Microsoft.

### Detection Example
![](https://github.com/mustgundogdu/PeterParser/blob/main/ScreenShots/4769Detection.PNG)

#### 4624
This event indicates that a user or service account has successfully logged on to a system or network resource. When the logon process is successful, the user's authentication credentials are valid, allowing access to system resources within the permissions granted.

## Important Areas:
- Logon Type
- Logon ID
- Security ID
- Account Name
- Source Network Address
- Authentication Package

### Pass The Hash Detection
Pass the hash attack aims for an attacker to gain access or log into a system using a user's NTLM or Kerberos hash instead of their password. This attack allows the attacker to authenticate without needing the actual password, by directly using the hash value.

The event ID 4624 plays a critical role in detecting pass the hash attacks and serves as an important source for security event investigations and inquiries.

### Detection Example
![](https://github.com/mustgundogdu/PeterParser/blob/main/ScreenShots/P1.PNG)

![](https://github.com/mustgundogdu/PeterParser/blob/main/ScreenShots/P4.PNG)

![](https://github.com/mustgundogdu/PeterParser/blob/main/ScreenShots/P3.PNG)

![](https://github.com/mustgundogdu/PeterParser/blob/main/ScreenShots/P2.PNG)


### Pass The Ticket Detection
Pass the ticket attack aims to gain authorized access to a target system using a valid Kerberos service ticket. In this type of attack, the attacker typically authenticates to the target system using a previously obtained valid Kerberos ticket-granting ticket (TGT) or service ticket (TGS) from a previous session.

In the detection of Pass The Ticket attacks, it is identified by comparing the 'session id' and 'Account Name' information found in cached Kerberos TGT tickets with those from the current session.
#### Note: The cached 'session id' and 'Account Name' information obtained in pass the ticket detection is provided with local administrator privileges on the local machine.

### Detection Example

![](https://github.com/mustgundogdu/PeterParser/blob/main/ScreenShots/PttDetection.PNG)


### References
> https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624
> https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769
