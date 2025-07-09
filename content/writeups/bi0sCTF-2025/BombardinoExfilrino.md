+++
title = "Bombardino Exfilrino"
date = 2025-07-09
authors = ["Sarvesh"]
+++

_Once connected to a well-known drug business, some files were found in an abandoned outpost. It is thought to include private information related to a current probe into a possible cartel. Shortly after discovering anomalies in a clandestine operation, the primary investigator disappeared. You, Joe Mama being the best Forensic Investigator alive, is the last hope to close up the case._

`MD5 Hash: ba0b9f65ed70d9a7a3de753caa4418ad chall1.E01`

`MD5 Hash: 714410f62ad1bf89a3fdef40ae7cf5cc chall2.E01`

**Questions**
1.What tag and ID was given to the operation during the conversation? Format: SIGMA4BRUNO8-CHARLIE_44
2.What is the name of the 77th client in their client list? Format: As found in the list (Case sensitive)
3.What are the coordinates of the second drop-point for the mission? Format: XX.XX,X.XX
4.What is the Manifest ID of the cargo? Format: All uppercase
5.What is the Doc ID of the Final Mission Plan? Format: All uppercase
6.What is the md5 hash of the exfiltrated data? Format: All lowercase
7.What is the MITRE ATT&CK method id which enabled data exfiltration?

**1.** We are given two Encase Image File Format (.E01) files in chall folder, which are often used in digital forensics for Disk Imaging. Based on the file format, our first stp is to mount the .E01 files.

 It is common for .E01 files to be split into multiple chunks for easier handling, but they should follow the naming convention of .E01, .E02, .E03, ... etc.

Both files we received end with the .E01 extension, which is unusual.
![](https://vyanide.github.io/_astro/q1-1.v2lxRQtG_ZqPeCd.webp)
Formatting the drive wont help in recovering data from it

There could be two possibilities:

1. The  `.E01`  files are corrupted, and we would need to repair them before mounting.
2. The  `.E01`  files contain a kind of file system that Windows does not recognize.

Either way, we should examne the  `.E01`  files directly using an Hex Editor to get a better understanding of what we are dealing with.
Opening both  `.E01`  files and scrolling down a bit, we can see a word:  `Storage Pool`.
![ ](https://vyanide.github.io/_astro/q1-2.3iYTMiAe_Z1wJQ3x.webp)
Searching up what storage pool is tell uss,
![](file:///C:/Users/N%20S%20Sarvesh/OneDrive/Pictures/Screenshots/Screenshot%202025-07-08%20004208.png)

Essentially, we are dealing with a **RAID-like** configuration.

RAID (Redundant Array of Independent Disks) is a data storage virtualization technology that combines multiple physical disk drive components into one or more logical units for the purposes of data redundancy, performance improvement, or both.

To mount the `.E01` files, we can use an Image Mounter ( I used Arsenal Image Mounter), which can recover **most of the files**.

> Mounting Instructions
>
> 1. Mount first `.E01`
> 2. Select “Enable Store differencing data in host RAM only (not in a file)”  (so that only RAM is ussed to mount the EnCase files)
> 3. Repeat for second `.E01`

![](https://vyanide.github.io/_astro/q1-4.CeTLf4OT_mo11U.webp)

We can now extract `conv.mp3` from the disk and listen for the tag and ID.

**Flag 1: DELTA4CHARLIE7-SILVERHAWK_88**

### Question 2: What is the name of the 77th client in their client list? (Format: As found in the list (Case sensitive))

If we try to extract `clients.zip`, we will get an error saying that the file is corrupted.

Again, we are faced with two options:

1. Find a better disk recovery tool.
2. File craving.

While trying to repair the disk, we will notice that some recovery tools are able to identify the `clients.zip` file as `clients.csv`.

Based on this observation, we can try carving the `clients.csv`’s data using a Hex Editor.

After scrolling through the Hex Editor for a while, we will  find data which resembles a CSV file in `chall.E01`.

![](https://vyanide.github.io/_astro/q2-1.DopGQr7L_Z2jaXAp.webp)

![](https://vyanide.github.io/_astro/q2-2.y7lm9cv6_ZOv4wW.webp)

And we can clearly see that the 77th client in the list is `Felisaas`.

Solution (Flag 2)

**Flag 2: Felisaas**

### Question 3: What are the coordinates of the second drop-point for the mission? (Format: XX.XX,X.XX)

Reading the bytes of `sighted.bin`, we see some hex data mentioning longitude and latitude.

![](https://vyanide.github.io/_astro/q3-1.D1pzMn5B_Z1uWHGz.webp)

Searching for the labels seen in the bytes of `sighted.bin` leads us to [ArduPilot’s log messages documentation](https://ardupilot.org/plane/docs/logmessages.html) (simply from the fact that a pilot's log has to follow some universal standard protocaol to decipher info and all of the protocols used to date are documented in ArduPilot's documentation), and with a bit of searching we can find that ArduPilot supports the **MAVLink protocol**.

We can then dump the mission logs using [pymavlink](https://github.com/ArduPilot/pymavlink/tree/master) with `tools/mavmission.py`.

Terminal window

```
PS C:\Users\vow\Desktop\pymavlink-2.4.47> python .\mavmission.py .\sighted.bin --output dump.txt
```

To understand what the logs mean, referring to [MAVLink’s file format documentation](https://mavlink.io/en/file_formats/), shows the format of the log.

```
QGC WPL <VERSION><INDEX> <CURRENT WP> <COORD FRAME> <COMMAND> <PARAM1> <PARAM2> <PARAM3> <PARAM4> <PARAM5/X/LATITUDE> <PARAM6/Y/LONGITUDE> <PARAM7/Z/ALTITUDE> <AUTOCONTINUE>
```

dump.txt

```
QGC WPL 1100  0  0  16  0.000000  0.000000  0.000000  0.000000  44.728114  7.421710  267.529999  11  0  3  22  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  30.000000  12  0  3  21  0.000000  0.000000  0.000000  1.000000  44.734763  7.427600  0.000000  13  0  0  218  41.000000  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  14  0  0  93  30.000000  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  15  0  0  218  41.000000  2.000000  0.000000  0.000000  0.000000  0.000000  0.000000  16  0  3  22  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  30.000000  17  0  3  21  0.000000  0.000000  0.000000  1.000000  44.736415  7.433066  0.000000  18  0  0  218  41.000000  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  19  0  0  93  30.000000  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  110  0  0  218  41.000000  2.000000  0.000000  0.000000  0.000000  0.000000  0.000000  111  0  3  22  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  30.000000  112  0  3  21  0.000000  0.000000  0.000000  1.000000  44.727088  7.431419  0.000000  113  0  0  218  41.000000  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  114  0  0  93  30.000000  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  115  0  0  218  41.000000  2.000000  0.000000  0.000000  0.000000  0.000000  0.000000  116  0  3  22  0.000000  0.000000  0.000000  0.000000  0.000000  0.000000  30.000000  117  0  3  21  0.000000  0.000000  0.000000  1.000000  44.728122  7.421734  0.000000  1
```

Sorting our data based on `<COORD FRAME>` in `dump.txt`, we can see that the second drop-point is at `44.734763, 7.427600`.

Solution (Flag 3)

**Flag 3: 44.73,7.43**

### Question 4: What is the Manifest ID of the cargo? (Format: All uppercase)

The `sighted.bin` files does not seem to contain any information about the Manifest ID, nor do the previous files, so we will have to look for it in the `file.zip`, which contains a `file.log`.

`flie.log` contains **49,077** logs from [Zeek](https://docs.zeek.org/en/master/about.html), a passive, open-source network traffic analyzer.

Using `grep` for keywords like `manifest`, `cargo`, did not yield any useful results, and since Zeek does not have a parser, we will have to analyze and filter the logs manually.

#### Step 0: Filtering tool

Using Cyberchef’s filtering function to make the search musch easier, which not only allows us to filter logs based on keywords, but also supports inverse condition filtering, along with our own Python parser to help us extract certain information from the logs.

![](https://vyanide.github.io/_astro/q4-1.BIF9TU4C_Z1c99cu.webp)

![](https://vyanide.github.io/_astro/q4-2.HeJ3CjUP_Z1O1DbA.webp)

#### Step 1: `_path:"loaded_scripts"`

We can easily see that there are logs with different values in the `_path` field. Scrolling to the bottom of the file, we notice that the last logs all contain `_path:"loaded_scripts"`, which should just be script paths for Zeek, likely irrelevant to our search.

file.log

```
...{_path:"loaded_scripts",name:"/usr/local/zeek/share/zeek/site/local.zeek"}{_path:"loaded_scripts",name:"/usr/local/zeek/share/zeek/base/init-bare.zeek"}{_path:"loaded_scripts",name:"  /usr/local/zeek/share/zeek/base/utils/dir.zeek"}{_path:"loaded_scripts",name:"  /usr/local/zeek/share/zeek/base/utils/time.zeek"}{_path:"loaded_scripts",name:"  /usr/local/zeek/share/zeek/base/utils/urls.zeek"}{_path:"loaded_scripts",name:"/usr/local/zeek/share/zeek/base/init-default.zeek"}{_path:"loaded_scripts",name:"  /usr/local/zeek/share/zeek/base/utils/addrs.zeek"}...
```

We can filter out all the logs that contain `_path:"loaded_scripts"`.

Number of logs remaining: **48,564**

#### Step 2: `_path:"files"`

When we talk about cargo, we usually think of files, so let’s examine all the logs that contain `_path:"files"`.

However, Zeek’s `file.log` does not capture transmitted file data, only some metadata about the files, and there does not seem to be any suspicious files in the logs, so we can filter `_path:"files"` out as well.

Number of logs remaining: **45,485**

#### Step 3: `_path:"http"`

Perhaps the device user visited some website, which contains a path to the cargo file. f0rest wrote a parser which listed all hosts and the number of times they were visited.

http_parsed.txt

```
426 host:"httpbin.org",uri:"/delay/2",referrer398 host:"httpbin.org",uri:"/delay/1",referrer388 host:"httpbin.org",uri:"/delay/3",referrer306 host:"httpstat.us",uri:"/200",referrer290 host:"neverssl.com",uri:"/",referrer260 host:"detectportal.firefox.com",uri:"/",referrer250 host:"httpforever.com",uri:"/",referrer200 host:"www.wikipedia.org",uri:"/",referrer200 host:"speedtest.tele2.net",uri:"/1MB.zip",referrer100 host:"testmy.net",uri:"/",referrer100 host:"news.ycombinator.com",uri:"/",referrer7   host:"infinitumhub.com",uri:"/",referrer7   host:"icanhazip.com",uri:"/",referrer7   host:"httpbin.org",uri:"/",referrer6   host:"w3.org",uri:"/",referrer6   host:"deepmesh.org",uri:"/",referrer4   host:"neuronforge.io",uri:"/",referrer4   host:"info.cern.ch",uri:"/",referrer4   host:"1.1.1.1",uri:"/",referrer3   host:"zenithcore.com",uri:"/",referrer3   host:"cybernest.org",uri:"/",referrer3   host:"cipherloom.com",uri:"/",referrer3   host:"bluecircuit.net",uri:"/",referrer2   host:"syncrift.com",uri:"/",referrer2   host:"ifconfig.me",uri:"/",referrer1   host:"matrixlane.com",uri:"/",referrer1   host:"fusionglow.com",uri:"/",referrer1   host:"bytepulse.io",uri:"/",referrer
```

However, none of these sites seem to be malicious or contain any information related to the cargo. So, `_path:"http"` can join our exclusion list.

Number of logs remaining: **42,353**

#### Step 4: `_path:"conn"`

We could take a look at all the TCP, UDP, and ICMP connections made by the device, but none of them have any particular intersting information, so we can filter `_path:"conn"` out as well.

Number of logs remaining: **22,189**

#### Step 5: `_path:"dns"`

Another thing to look out for would be DNS exfiltration techniques, hence we wrote another parser to list out all unique DNS queries made by the device.

dns_query_parser.py

```
import re
dns_query_list = []pattern = r'query:"([^"]+)"'
with open("file.log") as file:  data = file.readlines()
for log in data:    matches = re.findall(pattern, log)    # Do not add empty matches    if len(matches) > 0:        dns_query_list.extend(matches)
# Trick to remove duplicatesdns_query_list = list(set(dns_query_list))
# Write results to a filewith open('dns_queries_parsed.txt', 'w') as f:    for line in dns_query_list:        f.write(f"{line}\n")
```

dns_queries_parsed.txt

```
...4ddf0120d4fd14904636203030303030206e200a30303030303133393036.203030303030206e200a30303030303134353237203030303030206e200a.30303030303134313932203030303030206e200a30303030303134313232.203030303030206e20.aerisxsecmercancia.comouzn6gfl.comcoreliant.netztfqfpm6.coma02e0120d41c6e904638fef9cfc4d758cb3589f1b401e545818171639e8d.80e2d0cb8ad2414adbe001ab8c7edcae7fc07a11088aa00a82f0b4fd37eb.79c59d278f2927b1f6caaa4ad68b244aed7dcafa9595eaf478bb15423ebc.f34f3553f7ac5c9e37.aerisxsecmercancia.comtheverge.comgialc1e3.comexample.org...
```

There seems to be some very long domains in the DNS queries, and they are all assoicated with the same domain: `aerisxsecmercancia.com`.

If we try decoding the hex data in the DNS queries, there seems to be some kind of data in them.

![](https://vyanide.github.io/_astro/q4-3.Cl1_QwYg_Z1bHdA2.webp)

It seems that we should put our focus on domains that contain `aerisxsecmercancia.com`.

Number of logs remaining: **1,066**

#### Step 6: `aerisxsecmercancia.com`

By decoding some of the hex (especially the longer ones) from the DNS queries which contains `aerisxsecmercancia.com`, we can find the following snippet of data:

`599a0120d49033ae0a6361742046696e616c5f706c616e2e7064660a.aerisxsecmercancia.com -> Y Ô3® cat Final_plan.pdf`

So, it seems like a `.pdf` file is being exfiltrated through DNS queries with the file name being `Final_plan.pdf`, then our next step would be recovering `Final_plan.pdf` with yet another parser.

Note

1. The hex data is actually padded with 9 starting bytes (or 18 hex characters), which we will need to remove.
2. The `.pdf` file data is only in the longer queries, so we can filter out the shorter ones.

dns_exfil_parser.py

```
import re
dns_hex_exfil_data = []pattern = r'query:"([^"]+)"'exfil_file_data = ""
with open("file.log") as file:  data = file.readlines()
for log in data:  # Only process logs that contain 'dns' in the path  if '_path:"dns"' and 'aerisxsecmercancia.com' in log:  # Again, get the hex data in DNS queries    temp_data = re.findall(pattern, log)    # We remove DNS queries that are shorter than a certain length (these usually contain commands instead of data)    if len(temp_data[0]) > 90:      # The hex data has padding, so we need to remove it (9 bytes, 18 hex characters)      dns_hex_exfil_data.append(temp_data[0][18:])
# Combine the hex exfiltrated data into a single string, with processingfor data in dns_hex_exfil_data:  parsed_data = data.replace('aerisxsecmercancia.com', '')  parsed_data = parsed_data.replace('.', '')  exfil_file_data += parsed_data
# Decode the hex and write to filefile_data = bytes.fromhex(exfil_file_data)
# Write results to a filewith open('final_plan.pdf', 'wb') as f:    f.write(file_data)
```

In the end, we get a`.pdf` file, which contains the following:

![](https://vyanide.github.io/_astro/q4-4.CUdv_gBe_Z1Xk162.webp)

Solution (Flag 4)

**Flag 4: AXZ-BL-571**

### Question 5: What is the Doc ID of the Final Mission Plan? (Format: All uppercase)

Solution (Flag 5)

**Flag 5: AEROX-MB-KRM-8251**

### Question 6: What is the md5 hash of the exfiltrated data? (Format: All uppercase)

If we calculate the md5 hash of our parsed `final_plan.pdf`, we will get `a1038793ad04230100d3e84dab54194f` as the md5 hash. But that is incorrect. Because if we compare the bytes in `final_plan.pdf` file with another random `.pdf` file, we will notice that at the end of the file, `final_plan.pdf` is missing a `0x0A` byte.

According to [ISO-32000-1](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf) and [ISO-32000-2](https://pdfa.org/resource/iso-32000-2/), it is stated in 7.5.1 that the tokens in a PDF file are arranged into lines. Each line shall be terminated by an end-of-line (EOL) marker, which may be a CARRIAGE RETURN (0x0D), a LINE FEED (0x0A), or both.

To obtain the correct hash, we have to apppend an extra `0x0A` byte to the end of the `final_plan.pdf` file.

Solution (Flag 6)

**Flag 6: 1560d718c94ea09f1860cd270933fc24**

### Question 7: What is the MITRE ATT&CK method id which enabled data exfiltration? (Format: All uppercase)

In Question 4, when we decoded one of the DNS queries, we got the following result.

`Y Ô3® cat Final_plan.pdf`

Note the word `cat` in the decoded data, this is a obviously a Unix command.

From this, we can determine that this is not just a data exfiltration technique, but potentially a **Command and Control (C2)** technique using DNS.

Definition (Command and Control)

Command and Control (C2) is a method used by attackers to maintain communication with compromised systems within a target network. It allows them to send commands, retrieve data, and control the compromised systems remotely while avoiding detection.

A quick lookup at the [MITRE ATT&CK](https://attack.mitre.org/techniques/T1071/004/) website and we can easily find the correct method id.

Solution (Flag 7)

**Flag 7: T1071.004**

### Final Flag

And of course, the final flag after powering through all the 7 questions is,

Solution (Flag)

Flag: bi0sctf{n07_4_g4m3_m0m_17s_f0r3ns1cs_92maj420}
