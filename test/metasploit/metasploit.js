'use strict'

const path = require('path');
const fs = require('fs');
const xml2js = require('xml2js');
const jsonMapper = require('json-mapper-json');
const sdk = require('../../lib/index');

if(process.argv[2] == null || !process.argv[2].startsWith('http')) {
   console.log('Pass the webhook url as an argument');
   process.exit();
}

const hostsMapper = {
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

async function readFile(file) {
  const parser = new xml2js.Parser({explicitArray: false});
  if(file==null || file=='') {
      file=process.stdin.fd;
  }
  let data = fs.readFileSync(file, 'utf-8');
  return parser.parseStringPromise(data);
}

if(process.argv.length<4) {
    process.argv.push('hosts.xml');
}

(async()=>{
  for( let arg=3; arg<process.argv.length; arg++) {
    let data = await readFile(process.argv[arg]);
    if(data) {
      switch(Object.keys(data)[0]) {
        case 'hosts':
          let result =await jsonMapper(data.hosts.entry.hostsMapper);
          //return console.dir(result,{depth:8});
          await sdk.init({
            url: process.argv[2]
          });
          let ret = await sdk.submit({
            assets: result
          });
          console.log('Result(',process.argv[arg],') = ', ret.statusCode);
          break;
        default:
          break;
      }
    }
  }
})();
