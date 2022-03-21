'use strict'

var path = require('path');
var fs = require('fs');
var dns = require('dns');
var xml2js = require('xml2js');
var jsonMapper = require('json-mapper-json');
var sdk = require('../../lib/index');

var macList = {};

var resultMapper = {
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
//            var res = value.split(".", 1);
//            return res[0];
//        }
    },
    severityCVSS2Score: {
        path: 'nvt.cvss_base',
        required: false,
//        formatting: (value) => {
//            var res = value.split(".", 1);
//            return res[0];
//        }
    },
    severity: 'threat',
    confidence: 'qod.value'
};

if (process.argv[2] == null || !process.argv[2].startsWith('http')) {
    console.log('Pass the webhook url as an argument');
    process.exit();
}

function readOpenVAS(file, cb) {
    var parser = new xml2js.Parser({
            explicitArray: false
        });
    if (file === null)
        file = "/dev/stdin";
    fs.readFile(file, function (err, data) {
        if (err)
            return cb(err);
        parser.parseString(data, function (err, result) {
            if (err)
                return cb(err);
            return cb(null, result);
        });
    });
};

function nslookupReverse(asset, callback) {
    var called = false;
    var doCallback = function(err, domains) {
        if (called) return;
        called = true;
        if(typeof domains === 'object' && domains.length>0 && typeof domains[0] === 'string' && domains[0].length > 4)
            return callback(null,asset,domains[0]);
        else
            return callback(null,asset,null);
    };
    setTimeout(function() { doCallback(new Error("Timeout exceeded"), null); }, 7000);
    
    dns.reverse(asset.ipAddress, doCallback);
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

sdk.init({
    url: process.argv[2]
}, function (err) {
    readOpenVAS(null, function (err, data) {
        if (err)
            console.log("Error: ", err);
        else {
            var assets = [];
            for (var i = 0, l = data.report.report.host.length; i < l; i++) {
                var host = data.report.report.host[i];
                if (host.ip) {
                    var asset = {
                        ipAddress: host.ip,
                        isActive: 16,
                        systemInventoryScanDate: host.start,
                        deviceId: host.ip,
                        assetLabel: host.ip
                    };
                    if (host.detail) {
                        for (var i2 = 0, l2 = host.detail.length; i2 < l2; i2++) {
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
                    nslookupReverse(asset, function (err, finalAsset, ptr) {
                        if (typeof ptr === 'string')
                            finalAsset.assetLabel = ptr;
                        if (typeof finalAsset === 'object' && finalAsset.deviceId)
                            assets.push(finalAsset);
                    });
                }
            }
            setTimeout(function () {
                jsonMapper(data.report.report.results.result, resultMapper).then((result) => {
                    //return console.dir(result,{depth:5});
                    sdk.submit({
                        assets: assets,
                        vulnerabilities: result
                    }, function (err, res) {
                        if (err)
                            return console.log('Error: ', err);
                        return console.log('Result = ', res.statusCode);
                    });
                });
            }, 10000);
        }
    });
});