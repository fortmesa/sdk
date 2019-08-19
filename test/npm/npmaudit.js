'use strict'

var path = require('path');
var fs = require('fs');
var jsonMapper = require('json-mapper-json');
var sdk = require('../../lib/index');

if(process.argv[2] == null || !process.argv[2].startsWith('http')) {
   console.log('Pass the webhook url as an argument');
   process.exit();
}

if(process.argv[3] == null) {
    console.log('Pass the deviceId as the second argument.');
    process.exit();
}

var my_deviceId=process.argv[3];
var my_time=new Date();

sdk.init(process.argv[2]);

var resultMapper = {
  deviceId: {
    path: 'title',
    required: true,
    formatting: (value) => { return my_deviceId; }
  },
  lastScanDate: {
    path: 'title',
    formatting: (value) => { return my_time; }
  },
  findingId: {
    path: 'name',
    required: true
  },
  title: 'title',
  description: 'overview',
  service: 'module_name',
  recommendation: 'recommendation',
  severity: 'severity',
  numericSeverity: {
    path: 'severity',
    required: true,
    formatting: (value) => { if(value=='info') return 0; if(value=='low') return 3; if(value=='moderate') return 5; if(value=='high') return 7; if(value=='critical') return 10; return 10; }
  }
};

function readnpmaudit(cb) {
  var stdin = process.stdin;
  var inputJSON='';
  
  stdin.setEncoding('utf8');
  stdin.on('data', function(chunk) { inputJSON+=chunk; });
  stdin.on('end', function() {
    let result=JSON.parse(inputJSON);
    return cb(null,result);
  });
};


readnpmaudit(function(err,data) {
  if(err) console.log("Error: ",err);
  else {
    var data2 = Object.keys(data.advisories).map(function(k) { var record=data.advisories[k]; record.name=data.advisories[k].id + ' ' + data.advisories[k].title; return record; });
//    console.dir(data2,{depth:null});
    jsonMapper(data2,resultMapper).then( (result) => {
       console.dir(result,{depth:null});
      sdk.submit({vulnerabilities: result}, function(err,res) {
        if(err) return console.log('Error: ',err);
        return console.log('Result = ',res.statusCode);
      });
    });
  }
});
