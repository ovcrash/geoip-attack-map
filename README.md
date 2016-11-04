### Cyber Security GeoIP Attack Map Visualization
This geoip attack map visualizer was developed to display network attacks on your organization in real time. The data server follows a syslog file, and parses out source IP, destination IP, source port, and destination port. Protocols are determined via common ports, and the visualizations vary in color based on protocol type. [CLICK HERE](https://www.youtube.com/watch?v=raNp9uA7fvc) for a demo video. This project would not be possible if it weren't for Sam Cappella, who created a cyber defense competition network traffic visualizer for the 2015 Palmetto Cyber Defense Competition. I mainly used his code as a reference, but I did borrow a few functions while creating the display server, and visual aspects of the webapp. I would also like to give special thanks to [Dylan Madisetti](http://www.dylanmadisetti.com/) as well for giving me advice about certain aspects of my implementation.

### Modification
I have modified the script to ingest CEF format syslog message. You need:
```
1- Forward logs from ArcSight to rsyslog and into a file.
2- DataServer.py is used to read that file and parse the data and push it into a redis server.
3- I moved the webSocket server to nodejs, in the file webSocketServer.js i tought that would be faster.
```

### Important
This program relies entirely on syslog, and because all appliances format logs differently, you will need to customize the log parsing function(s). If your organization uses a security information and event management system (SIEM), it can probably normalize logs to save you a ton of time writing regex.
1. Send all syslog to SIEM.
2. Use SIEM to normalize logs.
3. Send normalized logs to the box (any Linux machine running syslog-ng will work) running this software so the data server can parse them.

### Installation
Run the following commands to install all required dependencies (tested on Ubuntu 14.04 x64)
```
# sudo apt-get install python3-pip redis-server
# sudo pip3 install tornado tornado-redis redis maxminddb
```

### Setup
1. Make sure in **/etc/redis/redis.conf** to change **bind 127.0.0.1** to **bind 0.0.0.0** if you plan on running the DataServer on a different machine than the AttackMapServer.
2. Make sure that the WebSocket address in **/AttackMapServer/index.html** points back to the IP address of the **AttackMapServer** so the browser knows the address of the WebSocket.
3. Download the MaxMind GeoLite2 database, and change the db_path variable in **DataServer.py** to the wherever you store the database.
    * ./db-dl.sh
4. Add headquarters latitude/longitude to hqLatLng variable in **index.html**
5. Use syslog-gen.sh to simulate dummy traffic "out of the box."
6. **IMPORTANT: Remember, this code will only run correctly in a production environment after personalizing the parsing functions. The default parsing function is only written to parse ./syslog-gen.sh traffic.**

### Bugs, Feedback, and Questions
If you find any errors or bugs, please let me know. Questions and feedback are also welcome, and can be sent to mcmay.web@gmail.com, or open an issue in this repository.
- Current bug that i need to fix, but since my coding skills are limited i'm having a hard time. The webSocketServer.js is always only eating up RAM on the server, until the thing breaks. Probably a memory leak in the code some where. So you are welcome to fix it! :o)
