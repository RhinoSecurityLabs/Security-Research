URL: https://url/api/users/#/?sid=#

Details: The above URL is vulnerable to forceable password changes. You can change the logged in user's password without knowing the current password. This is done by passing the JSON parameter "force" with your request, as seen in the api/includes/users.php file.