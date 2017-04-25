LFI for Unitrends 9.0

URL: https://ip/api/restore/download
TYPE: POST (json)

Details:

The function downloadFile in api/includes/restore.php blindly accepts any filename passed as valid. This allows an attacker to read any file on the filesystem.

Headers required:

AuthToken (aka "token" cookie given at login, no quotes around b64 value)

Parameters:

filename - the file to read from disk.