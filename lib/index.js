'use strict'

var request = require("request");

var _FMwebhookUrl = '';
var _FMuserAgent = 'FMWEB Sample Webhook 0.1';
var _FMmaxTTL = null;
var _FMscanDate = new Date();

function dateParse(date) {
    var newDate;

    newDate = new Date(Number(date));
    if (newDate instanceof Date && newDate.getFullYear() > 1980) return newDate;
    newDate = new Date(Number(date) * 1000);
    if (newDate instanceof Date && newDate.getFullYear() > 1980) return newDate;
    newDate = new Date(date);
    if (newDate instanceof Date && newDate.getFullYear() > 1980) return newDate;
    return new Date();
}

module.exports.init = function (options,cb) {
  if(options) {
    if(options.url) _FMwebhookUrl=options.url;
    if(options.maxTTL!=null) _FMmaxTTL=options.maxTTL;
    if(options.ua!=null) _FMuserAgent=options.ua;
    if(options.scanDate!=null) _FMscanDate=dateParse(options.scanDate);
  }
  if(cb!=null) return cb(null);
  return null;
}

function submitWebhook(payloadData,cb) {

  var payload = JSON.stringify(payloadData);

  var options = {
    method: 'POST',
    url: _FMwebhookUrl,
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': _FMuserAgent,
      'Timestamp': _FMscanDate
    },
    body: payload
  };
  request(options, function (err, res, body) {
    return cb(err,res,body);
  });
};


/*
  Valid fields with types for Assets

  "deviceId":           string          Unique ID for this asset
  "deviceName":         string          Name of this asset
  "deviceType":         string          Type of asset
  "deviceStatus":       string          Status of asset
  "instanceStatus":     string
  "operatingSystem":    string          Name of OS
  "operatingSystemVersion": string      Version of OS
  "computerName":       string          OS machine name
  "ipAddress":          string          IP Address
  "platformName":       string
  "platformType":       string
  "platformVersion":    string
  "cpuCores":           integer         CPU cores
  "cpuHyperThreadEnabled": boolean      Threading enabled
  "cpuModel":           string          CPU Model
  "cpuSockets":         integer         CPU Sockets
  "cpuSpeedMhz":        integer         CPU Mhz
  "cpuS":               integer
  "osServicePack":      string          OS Serivce Pack
  "instanceType":       string
  "instanceArchitecture": string
  "availabilityZone":   string
  "isActive":           integer         0=pending, 16=running, 32=shutting-down, 48=terminated, 64=stopping, 80=stopped (from aws sdk)
  "instanceLaunchDate": datetime        Date last started
  "systemInventoryScanDate": datetime   Date last scanned
  "unstructuredAssetInfo": any          Anything
  "assetLabel":         string          Asset Name to be displayed in web interface
  "isArchived":         boolean         Archive asset database entry
*/

/*
  Valid fields with types for Vulnerabilities

  "deviceId":           string          deviceId of asset this vulnerability applies to
  "service":            string
  "assetType":          string
  "findingId":          string          Unique finding identifier for asset, if empty filled with title value
  "title":              string          Vulnerability Title
  "description":        string          Vulnerability Description
  "recommendation":     string          Recommended solution
  "confidence":         string          How sure we are this is accurately found issue
  "indicatorOfCompromise":  string
  "attributes":         object          any extra info
  "failedItems":        string
  "lastScanDate":       datetime        When was this scanned/found
  "userAttributes":     object		any extra info
  "severityCVSS3Score": (string)	from 0 to 10 float for CVSS3 score
  "severityCVSS2Score": (string)	from 0 to 10 float for CVSS2 score
  "severityOtherScore": (string)	from 0 to 10 float for Other score
  "severityCVSS3Vector":string		CVSS3 Vector string
  "severityCVSS2Vector":string		CVSS2 Vector string
  "numericSeverity":    (string)        from 0 to 10, written to severityOtherScore
  "severity":           string          Human readable severity, used if numericSeverity is empty
*/
                    
function assetVerification(asset) {
  if(asset.deviceId==null) return new Error('deviceId not defined, needs to be a unique id per asset');
  if(typeof asset.deviceId !== 'string' || asset.deviceId.length<8) return new Error('deviceId needs to be a unique string id per asset');
  if(asset.assetLabel==null) return new Error('assetLabel needs to be defined');
  if(typeof asset.assetLabel !== 'string' || asset.assetLabel.length<2) return new Error('assetLabel string too short');
  return null;
}


function vulnerabilityVerification(vuln) {
  if(vuln.deviceId==null) return new Error('deviceId not defined, needs to be set to an existing asset deviceId');
  if(typeof vuln.deviceId !== 'string' || vuln.deviceId.length<8) return new Error('deviceId needs to be an existing asset deviceId');
  if(vuln.findingId==null && vuln.title==null) return new Error('findingId needs to be defined');
  if((typeof vuln.findingId !== 'string' || vuln.findingId.length<2) && (typeof vuln.title !== 'string' || vuln.title.length <2 )) return new Error('findingId string too short: ' + vuln.findingId);
  return null;
}

module.exports.submit = function (payload,cb) {
  if(_FMwebhookUrl.length<20 || !_FMwebhookUrl.startsWith('http')) return cb(new Error('webhookUrl not configured'));
  let assets=(payload.assets!=null && typeof payload.assets==='object' && payload.assets instanceof Array);
  let vulns =(payload.vulnerabilities!=null && typeof payload.vulnerabilities==='object' && payload.vulnerabilities instanceof Array);
  if(!assets && !vulns) return cb(new Error('No assets or vulnerabilities'));
  if(assets) {
    for(var i=0,l=payload.assets.length; i<l; i++) {
      var err=assetVerification(payload.assets[i]);
      if(err != null) return cb(err);
    }
  }
  if(vulns) {
    for(var i=0,l=payload.vulnerabilities.length; i<l; i++) {
      var err=vulnerabilityVerification(payload.vulnerabilities[i]);
      if(err != null) return cb(err);
    }
  }
  return submitWebhook(payload,cb);
}
