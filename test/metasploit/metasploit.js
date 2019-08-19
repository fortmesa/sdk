'use strict'

var path = require('path');
var fs = require('fs');
var xml2js = require('xml2js');
var jsonMapper = require('json-mapper-json');
var sdk = require('../../lib/index');

if(process.argv[2] == null || !process.argv[2].startsWith('http')) {
   console.log('Pass the webhook url as an argument');
   process.exit();
}

sdk.init(process.argv[2]);

var hostsMapper = {
  deviceId: {
    path: 'mac',
    required: true
  },
  systemInventoryScanDate: 'updated_at',
  assetLabel: {
    path: 'mac',
    required: true
  },
  deviceName: 'name',
  deviceStatus: 'state',
  ipAddress: {
    path: 'address',
    formatting: (value) => { if(value instanceof Array) { return value[0]; } else { return value; }}
  },
  operatingSystem: 'os_name',
  operatingSystemVersion: 'os_sp',
  platformType: 'purpose'

};

function readMegasploit(file,cb) {
  var parser = new xml2js.Parser({explicitArray: false});
  fs.readFile(file, function(err, data) {
    if(err) return cb(err);
    parser.parseString(data, function (err, result) {
      if(err) return cb(err);
      return cb(null,result);
    });
  });
};


readMegasploit("./hosts.xml",function(err,data) {
  if(err) console.log("Error: ",err);
  else {
    switch(Object.keys(data)[0]) {
      case 'hosts':
        jsonMapper(data.hosts.entry,hostsMapper).then( (result) => {
          sdk.submit({assets: result}, function(err,res) {
            if(err) return console.log('Error: ',err);
            return console.log('Result = ',res.statusCode);
          });
        });
        break;
      default:
        break;
    }
  }
});
