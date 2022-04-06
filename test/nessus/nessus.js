'use strict'

var path = require('path');
var fs = require('fs');
var dns = require('dns');
var xml2js = require('xml2js');
var jsonMapper = require('json-mapper-json');
var sdk = require('../../lib/index');

var ignoreIDs = {
    '19506': true,
    '10287': true,
};


if (process.argv[2] == null || !process.argv[2].startsWith('http')) {
    console.log('Pass the webhook url as an argument');
    process.exit();
}

function readNessus(file, cb) {
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

    readNessus(null, function (err, data) {
        if (err)
            console.log("Error: ", err);
        else {
            let assets = [];
            let vulns = [];
            let scanDate;
            for (let i = 0, l = data.NessusClientData_v2.Report.ReportHost.length; i < l; i++) {
                let host = data.NessusClientData_v2.Report.ReportHost[i];
                if (host['$'].name) {
                    let asset = {
                        isActive: 16,
                        unstructuredAssetInfo: JSON.parse(JSON.stringify(host.HostProperties).replace(/"\$":/g,'"key":')),
                        deviceId: host['$'].name.toLowerCase(),
                        assetLabel: host['$'].name.toLowerCase(),
                        
                    };
                    if (host.HostProperties && host.HostProperties.tag) {
                        for (let i2 = host.HostProperties.tag.length; i2>0; i2--) {
                            let value=host.HostProperties.tag[i2-1]['_'];
                            switch (host.HostProperties.tag[i2-1]['$'].name) {
                            case 'cpe':
                                asset.cpe = value;
                                break;
                            case 'host-ip':
                                asset.ipAddress = value.toLowerCase();
                                break;
                            case 'os':
                                if(!asset.operatingSystem)
                                    asset.operatingSystem = value;
                                break;
                            case 'operating-system':
                                asset.operatingSystem = value;
                                break;
                            case 'mac-address':
                                asset.macAddress = value;
                                break;
                            case 'HOST_END_TIMESTAMP':
                                if(!asset.systemInventoryScanDate)
                                    asset.systemInventoryScanDate = new Date(value*1000);
                                break;
                            case 'HOST_START_TIMESTAMP':
                                asset.systemInventoryScanDate = new Date(value*1000);
                                if(!scanDate)
                                    scanDate = asset.systemInventoryScanDate;
                                break;
                            default:
                                break;
                            }
                        }
                    }
                    if (typeof asset === 'object' && asset.deviceId)
                        assets.push(asset);
                    if (host.ReportItem && host.ReportItem.length > 0) {
                        for (let i2 = host.ReportItem.length; i2>0; i2--) {
                            let pluginId;
                            let item=host.ReportItem[i2-1];
                            let vuln = {
                                deviceId: asset.deviceId,
                                attributes: JSON.parse(JSON.stringify(item).replace(/"\$":/g,'"key":')),
                                lastScanDate: asset.systemInventoryScanDate
                            };
                            if(item.cvss3_base_score)
                                vuln.severityCVSS3Score=item.cvss3_base_score;
                            if(item.cvss3_vector)
                                vuln.severityCVSS3Vector=item.cvss3_vector;
                            if(item.cvss_base_score)
                                vuln.severityCVSS2Score=item.cvss_base_score;
                            if(item.cvss_vector)
                                vuln.severityCVSS2Vector=item.cvss_vector;
                            if(item['$'].severity && !vuln.severityCVSS2Score && !vuln.severityCVSS3Score) {
                                switch(item['$'].severity) {
                                default:
                                case '0':
                                    vuln.severityOtherScore=0;
                                    break;
                                case '1':
                                    vuln.severityOtherScore=2;
                                    break;
                                case '2':
                                    vuln.severityOtherScore=5;
                                    break;
                                case '3':
                                    vuln.severityOtherScore=7;
                                    break;
                                case '4':
                                    vuln.severityOtherScore=9;
                                    break;
                                }
                            }
                            if(item.description)
                                vuln.description=item.description;
                            if(item.solution)
                                vuln.recommendation=item.solution;
                            if(item['$'].pluginName)
                                vuln.title=item['$'].pluginName;
                            if(item.plugin_name)
                                vuln.title=item.plugin_name;
                            if(item['$'].pluginID)
                                pluginId=item['$'].pluginID;

                            if(item.cve)
                                vuln.findingId=item.cve;
                            
                            if(!ignoreIDs[pluginId])
                                vulns.push(vuln);
                        }
                    }
                }
            }
            //return process.stdout.write(JSON.stringify({assets:assets,vulnerabilities: vulns}));
            sdk.init({
                url: process.argv[2],
                scanDate: scanDate
            }, function (err) {
                sdk.submit({
                    assets: assets,
                    vulnerabilities: vulns
                }, function (err, res) {
                    if (err)
                        return console.log('Error: ', err);
                    return console.log('Result = ', res.statusCode);
                });
            });
        }
    });
