# lmsstat
Dump current status for squeezelite player from LMS server

Prints the JSON result from the "status" query for current device.  Automatically finds the LMS server's IP address, and the local MAC address (wlan0).

Requires https://github.com/DaveGamble/cJSON

gcc -o lmsstat lmsstat.c cJSON.c
