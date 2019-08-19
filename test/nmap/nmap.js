'use strict'

var path = require('path');
var fs = require('fs');
var sdk = require('../../lib/index');

if(process.argv[2] == null || !process.argv[2].startsWith('http')) {
   console.log('Pass the webhook url as an argument');
   process.exit();
}

sdk.init(process.argv[2]);

function readJSON(file,cb) {
  if(file === null) file="/dev/stdin";
  fs.readFile(file, function(err, data) {
    if(err) return cb(err);
    return cb(null,JSON.parse(data));
  });
};


readJSON(null,function(err,data) {
  if(err) console.log("Error: ",err);
  else {
    sdk.submit({assets: data}, function(err,res) {
        if(err) return console.log('Error: ',err);
        return console.log('Result = ',res.statusCode);
    });
  }
});


/* awk filter
function clear() { if(current["ip"]) { print "{"; print "deviceId: \"" current["mac"] "\","; print "assetLabel: \"" names[current["mac"]] "\","; print "ipAddress: \"" current["ip"] "\","; if(current["device_type"]) { print "deviceType: \"" current["device_type"] "\","; } if(current["os"]) { print "operatingSystem: \"" current["os"] "\","; } if(current["device"]) { print "deviceName: \"" current["device"] "\","; } print "isActive: 16"; print "},"; } delete current; delete current[0]; }
BEGIN { delete current[0]; }
/^ethernet/ { mac=tolower($3); names[mac]=$2; };
/^Nmap scan report for [0-9+]+\.[0-9]+\.[0-9]+\.[0-9]+/ { clear(); current["ip"]=$5; }
/^Nmap scan report for .* \([0-9+]+\.[0-9]+\.[0-9]+\.[0-9]+\)/ { clear(); split($6,a,"("); split(a[2],b,")"); current["ip"]=b[1]; }
/^MAC Address: / { current["mac"]=tolower($3); }
/^OS details: / { split($0,a,": "); current["os"]=a[2]; }
/^Running: / { split($0,a,": "); current["running"]=a[2]; }
/^Device Type: / { split($0,a,": "); current["device_type"]=a[2]; }
/^Agressive OS guesses: / { split($0,a,": "); split(a[2],b," ("); current["os_guess"]=b[1]; }
/^Service Info: / { split($0,a,"cpe:/h:"); current["device"]=a[2]; }
END { clear(); }
*/
