# HTB

    FALAFEL AND POPCORN
        • Challenges
            ○ Bypass File Upload Restrictions
        • Source code analysis requirments
            ○ Nope
    VAULT
        • Challenges
            ○ Enumeration
            ○ Port forwarding
            ○ File sharing with netcat
            ○ Use of PGP
        • Source code analysis requirments
            ○ Nope
    BLOCKY
        • Challenges
            ○ Use JD-GUI
            ○ Adapt CVEs Exploits
            ○ Vulnerability Chaining
            ○ Webshells
            ○ Use of PGP
        • Source code analysis requirments
            ○ Locate credentials within Jar file (1 file)
            ○ Decompile JAR files
        • 2 methods to gain root, the preferred for me is:
            ○ Use the creds to access phpmyadmin
            ○ change user and password
            ○ Access Wordpress and upload a crafted plugin
            ○ Escalate from www-data to root
    ARKHAM
        • Challenges
            ○ Use cryptsetup to dump/decrypt LUKS disks
            ○ Read Web Application’s Documentation
            ○ Know how to use crypto utility to encrypt a payload
            ○ Know how to use ysoserial to generate an RCE payload via insecure deserialsiation
        • Source code analysis requirments
            ○ Documentation reading

#### SUMMARY
Wrapping up the above info, I would say that only Arkham (up to user shell) and Blocky (also up to user shell) are worth for OSWE preparation. For anyone else, they are fairly funny machines (mostly vault and arkham).

# VulnHub

    PIPE
        • Challenges
            ○ Know how to exploit PHP insecure deserialisation to achieve RCE
        • Source code analysis requirements
            ○ Source Code Analysis of 3 PHP files (Boringly simple)
        • OSWE Style Walkthrough:
            ○ Pipe
    RAVEN2
        • Challenges
            ○ Detect missing input validation
            ○ Debug PHP app via code augmentation [big word, small task]
        • Source code analysis requirements
            ○ Source Code Analysis of PHPMailer (Important files: 2)
        • OSWE Style Walkthrough:
            ○ Raven
    HOMELESS
        • Challenges
            ○ Know a bit of hashing functions
        • Source code analysis requirements
            ○ Source Code Analysis of 3-4 PHP files
        • OSWE Style Walkthrough:
            ○ Homeless
    TED
        • Challenges
            ○ Know how to exploit PHP Local File Inclusion to achieve RCE
        • Source code analysis requirements
            ○ Source Code Analysis of a few PHP files
        • OSWE Style Walkthrough:
            ○ Ted
    FLICK2
        • Challenges
            ○ Understand how APIs work
            ○ Know how to decompile/recompile an APK
            ○ A bit of enumeration
        • Source code analysis requirements
            ○ Little APK decompiled code analysis
        • OSWE Style Walkthrough:
            ○ Flick2
            ○ Additional Exercise at the end
