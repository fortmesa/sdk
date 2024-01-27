'use strict'

const path = require('path');
const fs = require('fs');
const dns = require('dns');
const xml2js = require('xml2js');
const jsonMapper = require('json-mapper-json');
const sdk = require('../../lib/index');

var macList = {};

const resultMapper = {
    deviceId: {
        path: 'host._',
        required: true,
        formatting: (value) => {
            if (macList[value])
                return macList[value];
            else
                return value;
        }
    },
    lastScanDate: 'modification_time',
    findingId: {
        path: 'nvt.cve',
        required: false,
        formatting: (value) => {
            if( value === "NOCVE" )
                return null;
            else
                return value;
        }
    },
    title: 'name',
    description: 'description',
    severityOtherScore: {
        path: 'severity',
        required: true,
//        formatting: (value) => {
//            let res = value.split(".", 1);
//            return res[0];
//        }
    },
    severityCVSS2Score: {
        path: 'nvt.cvss_base',
        required: false,
//        formatting: (value) => {
//            let res = value.split(".", 1);
//            return res[0];
//        }
    },
    severity: 'threat',
    confidence: 'qod.value',
};

if (process.argv[2] == null || !process.argv[2].startsWith('http')) {
    console.log('Pass the webhook url as an argument');
    process.exit();
}

async function readFile(file) {
    const parser = new xml2js.Parser({
            explicitArray: false
        });
    if(file==null || file=='') {
        file=process.stdin.fd;
    }
    const data = fs.readFileSync(file, 'utf-8');
    return parser.parseStringPromise(data);
}

const timeout = (delay, message) => new Promise((_, reject) => setTimeout(reject, delay, message));

async function nslookupReverse(asset) {
    try {
      const domains = await Promise.race([dns.promises.reverse(asset.ipAddress), timeout(7000, null)]);
      if(typeof domains === 'object' && domains.length>0 && typeof domains[0] === 'string' && domains[0].length > 4)
        return domains[0];
    } catch(e) {
      return;
    }
};

/*
{
"deviceId": "a8:86:dd:aa:80:1b",
"assetLabel": "a8:86:dd:aa:80:1b",
"ipAddress": "192.168.86.21",
"operatingSystem": "Apple Mac OS X 10.7.0 (Lion) - 10.12 (Sierra) or iOS 4.1 - 9.3.3 (Darwin 10.0.0 - 16.4.0)",
"systemInventoryScanDate": 1556906520,
"isActive": 16
},
*/

(async()=>{
  for( let arg=3; arg<process.argv.length; arg++) {
    let data = await readFile(process.argv[arg]);
            let assets = [];
            let scanDate = new Date();
            for (let i = 0, l = data.report.report.host.length; i < l; i++) {
                let host = data.report.report.host[i];
                if (host.ip) {
                    let asset = {
                        ipAddress: host.ip,
                        isActive: 16,
                        systemInventoryScanDate: host.start,
                        deviceId: host.ip,
                        assetLabel: host.ip,
                        unstructuredAssetInfo: JSON.parse(JSON.stringify(host).replace(/"\$":/g,'"key":'))
                    };
                    if (host.detail) {
                        for (let i2 = 0, l2 = host.detail.length; i2 < l2; i2++) {
                            switch (host.detail[i2].name) {
                            case 'MAC':
                                let mac = host.detail[i2].value.toLowerCase();
                                //asset.deviceId=mac;
                                //asset.assetLabel=mac;
                                //macList[host.ip]=mac;
                                break;
                            case 'best_os_txt':
                                asset.operatingSystem = host.detail[i2].value;
                                break;
                            default:
                                break;
                            }
                        }
                    }
                    let ptr = await nslookupReverse(asset);
                    if (typeof ptr === 'string')
                        asset.assetLabel = ptr;
                    if (typeof asset === 'object' && asset.deviceId)
                        assets.push(asset);
                    if (asset.systemInventoryScanDate)
                        scanDate=asset.systemInventoryScanDate;
                }
            }
    let result = await jsonMapper(data.report.report.results.result, resultMapper);
    for (let i = 0, l = result.length; i < l; i++) {
      result[i].attributes=JSON.parse(JSON.stringify(data.report.report.results.result[i]).replace(/"\$":/g,'"key":'));
    }
    //return process.stdout.write(JSON.stringify({assets:assets,vulnerabilities: result}));
    await sdk.init({
      url: process.argv[2],
      scanDate: scanDate
    });
    let res = await sdk.submit({
      assets: assets,
      vulnerabilities: result
    });
    console.log('Result (',process.argv[arg],') = ', res.statusCode);
  }
})();