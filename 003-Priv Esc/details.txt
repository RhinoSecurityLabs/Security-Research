Priv Escalation

Details:

Given user credentials for a unitrends application, an arbitrary user can escalate to administrator by 

1. Urldecode the "token" cookie
2. Base64 decode the "token" cookie
3. The cookis of the format:
    v0:session_key:UID:/path/to/log/file.log:log_level
4. Change the UID value to 1
5. Re-encode base64 and URL. Save, refresh.