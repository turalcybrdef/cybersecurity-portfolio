# TryHackMe Lab: Hack Your First Website (Gobuster)

## Platform
TryHackMe (Legal, controlled lab environment)

## Lab Description
This lab simulates an ethical hacker’s first interaction with a web application by performing **web enumeration** to discover hidden directories and functionality.

All activities were performed legally within TryHackMe’s authorized environment.

---

## Objective
- Understand how attackers discover hidden web content
- Use Gobuster to enumerate directories
- Interpret HTTP response codes
- Identify potential attack surface without exploitation

---

## Tool Used
### Gobuster
Gobuster is a directory and file enumeration tool used to brute-force discover hidden web paths using a wordlist.

---

## Methodology (High-Level)
1. Identified the target web application provided by the lab
2. Used Gobuster with a common wordlist to enumerate directories
3. Analyzed HTTP response codes returned by the server
4. Identified accessible and redirected endpoints
5. Documented findings and security implications

---

## Example Command Used
```bash
gobuster dir -u http://target-ip -w common.txt

## Achievement & Verification

TryHackMe Room Completion:  
https://tryhackme.com/room/Offensive Security Intro room info

TryHackMe Profile:  
https://tryhackme.com/p/tural.aghabalayev
[0x1][NEOPHYTE]

