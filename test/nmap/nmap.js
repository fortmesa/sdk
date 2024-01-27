'use strict'

/* awk filter if you dont use nmap xml format
function clear() { if(current["ip"]) { print "{"; print "deviceId: \"" current["mac"] "\","; print "assetLabel: \"" names[current["mac"]] "\","; print "ipAddress: \"" current["ip"] "\","; if(current["device_type"]) { print "deviceType: \"" current["device_type"] "\","; } if(current["os"]) { print "operatingSystem: \"" current["os"] "\","; } if(current["device"]) { print "deviceName: \"" current["device"] "\","; } print "isActive: 16"; print "},"; } delete current; delete current[0]; }
BEGIN { delete current[0]; }
/^ethernet/ { mac=tolower($3); names[mac]=$2; };
/^Nmap scan report for [0-9+]+\.[0-9]+\.[0-9]+\.[0-9]+/ { clear(); current["ip"]=$5; }
/^Nmap scan report for .* \([0-9+]+\.[0-9]+\.[0-9]+\.[0-9]+\)/ { clear(); split($6,a,"("); split(a[2],b,")"); current["ip"]=b[1]; }
/^MAC Address: / { current["mac"]=tolower($3); }
/^Running: / { split($0,a,": "); current["running"]=a[2]; }
/^Device Type: / { split($0,a,": "); current["device_type"]=a[2]; }
/^Service Info: / { split($0,a,"cpe:/h:"); current["device"]=a[2]; }
END { clear(); }
*/


const path = require('path');
const fs = require('fs');
const xml2js = require('xml2js');
const sdk = require('../../lib/index');

if(process.argv[2] == null || !process.argv[2].startsWith('http')) {
   console.log('Pass the webhook url as an argument');
   process.exit();
}


async function readFile(file) {
    if(file==null || file=='') {
        file=process.stdin.fd;
    }
    let data,json;
    try {
      data = fs.readFileSync(file, 'utf-8');
    } catch(err) {
      console.log('Error reading data (',file,'): ',err);
    }
    try {
      json=JSON.parse(data);
    } catch(err) {
      //console.log('JSON Error: ',err);
    }
    if(json) return json;

    const parser = new xml2js.Parser({
            explicitArray: false
    });
    try {   
      data=await parser.parseStringPromise(data);
      if(Array.isArray(data['nmaprun']['host']))
        data=data['nmaprun']['host'];
      else
        data=[data['nmaprun']['host']];
      if(data && data.length)
        json=[];
      for(let i in data) {
        let item=data[i];
        let obj={};
        
        if(item.address) {
          if(!Array.isArray(item.address))
            item.address=[item.address];
          for(let x in item.address) {
            if(item.address[x]['$'].addrtype==='ipv4') {
              obj.ipAddress=item.address[x]['$'].addr;
            } else if(item.address[x]['$'].addrtype==='ipv6') {
              obj.ip6Address=item.address[x]['$'].addr;
            } else if(item.address[x]['$'].addrtype==='mac') {
              obj.macAddress=item.address[x]['$'].addr;
            }
          }
        }
        if(item.os?.osmatch) {
            let osmatch=item.os.osmatch;
            if(Array.isArray(item.os.osmatch))
                osmatch=item.os.osmatch[0];
            let osclass=osmatch.osclass;
            if(Array.isArray(osmatch.osclass))
                osclass=osmatch.osclass[0];

            if(osmatch['$']?.name)
                obj.operatingSystem=osmatch['$'].name;
            if(osclass.cpe && osclass.cpe.startsWith('cpe:/o'))
                obj.cpe=osclass.cpe;
            if(osclass['$']?.type)
                obj.deviceType=osclass['$'].type;
        }
        if(item.hostnames?.hostname?.['$']?.name)
            obj.assetLabel=item.hostnames.hostname['$'].name;
        if(item['$']?.starttime)
            obj.systemInventoryScanDate=item['$'].starttime;
        if(item['$']?.endtime)
            obj.systemInventoryScanDate=item['$'].endtime;
        obj.isActive=16;
        
        if(!obj.assetLabel && obj.macAddress)
            obj.assetLabel=obj.macAddress;
        if(!obj.deviceId && obj.macAddress)
            obj.deviceId=obj.macAddress;
        if(!obj.assetLabel && obj.ipAddress)
            obj.assetLabel=obj.ipAddress;
        if(!obj.deviceId && obj.ipAddress)
            obj.deviceId=obj.ipAddress;
        if(!obj.assetLabel && obj.ip6Address)
            obj.assetLabel=obj.ip6Address;
        if(!obj.deviceId && obj.ip6Address)
            obj.deviceId=obj.ip6Address;
        if(!obj.deviceName)
            obj.deviceName=obj.assetLabel;
        
        obj.unstructuredAssetInfo=item;
        
        json.push(obj);
      }

    } catch(err) {
      //console.log('XML Error: ',err);
      console.log('Did not find valid JSON or XML input ',file);
    }
    return json;
};

if(process.argv.length<4) {
    process.argv.push('');
}

(async()=>{
  for( let arg=3; arg<process.argv.length; arg++) {
    let data = await readFile(process.argv[arg]);
    //return console.dir(data,{depth:8});
    await sdk.init({
        url: process.argv[2]
    });
    let ret = await sdk.submit({
        assets: data
    });
    console.log('Result(',process.argv[arg],') = ', ret.statusCode);
  }
})();

