# Assuming the tool.exe is in the same directory as this script
$tool_exe_path = ".\tool.exe"

# Directory containing the .pub files
$keys_folder = ".\keys"

# The file to encode
$encode_file = "config.json"

# Loop through each .pub file in the keys folder
Get-ChildItem $keys_folder -Filter *.pub | ForEach-Object {
    $pub_key_file = $_.FullName
    Write-Host $pub_key_file
	Start-Sleep -Seconds 1
	
    # Execute the tool.exe command
    & $tool_exe_path -pub-key $pub_key_file $encode_file
}

Write-Host "All .pub files in the keys folder have been processed using tool.exe."
