'use strict'

const path = require('path');
const fs = require('fs');
const xml2js = require('xml2js');
const htmlEntities = require('html-entities');
const sdk = require('../../lib/index');

var scanDate;

var vulnDB={};

if(process.argv[2] == null || !process.argv[2].startsWith('http')) {
   console.log('Pass the webhook url as an argument');
   process.exit();
}


async function readFile(file) {
    if(file==null || file=='') {
        file=process.stdin.fd;
    }
    let data,assets,vulns;
    try {
      data = fs.readFileSync(file, 'utf-8');
    } catch(err) {
      console.log('Error reading data (',file,'): ',err);
    }
    const parser = new xml2js.Parser({
            explicitArray: false
    });
    try {   
      data=await parser.parseStringPromise(data);
      //console.dir(data,{depth:8});
      if(data.ASSET_DATA_REPORT?.HEADER?.GENERATION_DATETIME)
          scanDate = data.ASSET_DATA_REPORT.HEADER.GENERATION_DATETIME;
      if(data.ASSET_DATA_REPORT?.GLOSSARY?.VULN_DETAILS_LIST?.VULN_DETAILS) {
        //console.dir(data.ASSET_DATA_REPORT.GLOSSARY.VULN_DETAILS_LIST,{depth:8});
        let vulnDetails;
        if(Array.isArray(data.ASSET_DATA_REPORT.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS))
          vulnDetails=data.ASSET_DATA_REPORT.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS;
        else
          vulnDetails=[data.ASSET_DATA_REPORT.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS];
        for(let i in vulnDetails) {
          let item=vulnDetails[i];
          let obj={};
          if(item.TITLE)
            obj.title=htmlEntities.decode(item.TITLE);
          if(item.SEVERITY)
            obj.severityOtherScore=item.SEVERITY;
          if(item.SOLUTION)
            obj.recommendation=htmlEntities.decode(item.SOLUTION);
          if(item.THREAT && item.IMPACT)
            obj.description=htmlEntities.decode(item.THREAT + "\n\n" + item.IMPACT);
          if(!obj.description && item.THREAT)
            obj.description=htmlEntities.decode(item.THREAT);
            
          if(Array.isArray(item.CVE_ID_LIST?.CVE_ID)) {
            obj.cve=[];
            for(let c in item.CVE_ID_LIST.CVE_ID) {
              if(item.CVE_ID_LIST.CVE_ID[c].ID)
                obj.cve.push(item.CVE_ID_LIST.CVE_ID[c].ID);
            }
            if(!obj.cve.length)
              delete obj.cve;
          } else if(item.CVE_ID_LIST?.CVE_ID?.ID) {
            obj.cve=[];
            obj.cve.push(item.CVE_ID_LIST.CVE_ID.ID);
          }

          if(item.QID?.['_'])
            vulnDB[item.QID['_']]=obj;
        }
      }
      //console.log(vulnDB);
      if(Array.isArray(data.ASSET_DATA_REPORT?.HOST_LIST.HOST))
        data=data.ASSET_DATA_REPORT.HOST_LIST.HOST;
      else
        data=[dataASSET_DATA_REPORT.HOST_LIST.HOST];
      if(data && data.length) {
        assets=[];
        vulns=[];
      }
      for(let i in data) {
        let item=data[i];
        let obj={};
        let vulnList=[];
        if(Array.isArray(item.VULN_INFO_LIST?.VULN_INFO))
          vulnList=item.VULN_INFO_LIST.VULN_INFO
        else if(item.VULN_INFO_LIST?.VULN_INFO)
          vulnList=[item.VULN_INFO_LIST.VULN_INFO];
        delete item.VULN_INFO_LIST;
        //console.dir(vulnList,{depth:8});

        if(item.IP?.['_'])
          obj.ipAddress=item.IP['_'];
        if(item.IPV6?.['_'])
          obj.ip6Address=item.IPV6['_'];

        if(item.OS)
          obj.operatingSystem=item.OS;
        if(item.OPERATING_SYSTEM)
          obj.operatingSystem=item.OPERATING_SYSTEM;

        if(item.DNS)
            obj.assetLabel=item.DNS;
        
        obj.isActive=16;
        
        if(!obj.deviceId && item.QG_HOSTID)
            obj.deviceId=item.QG_HOSTID;
        if(!obj.deviceId && item.HOST_ID)
            obj.deviceId=item.HOST_ID;

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
        
        // problem with $ elements
        //obj.unstructuredAssetInfo=item;
        
        assets.push({...obj});
        
        for(let i in vulnList) {
          item=vulnList[i];
          let vuln={
            deviceId: obj.deviceId,
          };

          if(item.VULN_STATUS==='Active' && item.TYPE==='Vuln') {
            if(item.LAST_FOUND)
              vuln.lastScanDate=item.LAST_FOUND;
            if(item.TITLE)
              vuln.title=htmlEntities.decode(item.TITLE);
            if(typeof(item.RESULT)==='string')
              vuln.description=htmlEntities.decode(item.RESULT);
            if(item.RESULT?.['_'])
              vuln.description=htmlEntities.decode(item.RESULT['_']);
            if(item.QID?.['_']) {
              if(!vuln.userAttributes)
                vuln.userAttributes={};
              vuln.userAttributes.qualysQID=item.QID['_'];
            }
            if(item.TICKET_NUMBER && item.TICKET_STATE==='OPEN') {
              if(!vuln.userAttributes)
                vuln.userAttributes={};
              vuln.userAttributes.ticket=item.TICKET_NUMBER;
            }
            
            if(!vuln.title && item.PROTOCOL && item.PORT && vuln.userAttributes?.qid)
              vuln.title='qid_'+vuln.userAttributes.qid+' '+item.PROTOCOL+'/'+item.PORT+' '+htmlEntities.decode(item.SERVICE);;
            if(!vuln.title && item.PROTOCOL && item.PORT)
              vuln.title=item.PROTOCOL+'/'+item.PORT+' '+htmlEntities.decode(item.SERVICE);;
            if(!vuln.title && vuln.description)
              vuln.title=vuln.description.slice("\n", vuln.description.indexOf("\n"));
            
            if(!vuln.findingId && vuln.title)
              vuln.findingId=vuln.title;

            if(vuln.userAttributes?.qualysQID) {
              if(vulnDB[vuln.userAttributes.qualysQID]) {
                vuln = { ...vuln, ...vulnDB[vuln.userAttributes.qualysQID] };
              }
              //console.dir(vuln);
              let cve=vuln.cve;
              if(vuln.cve)
                delete vuln.cve;
              if(Array.isArray(cve)) {
                delete vuln.findingId;
                for(let c in cve) {
                  let cv = {...vuln};
                  cv.findingId=cve[c];
                  //console.log(cv);
                  vulns.push({...cv});
                }
              }
            }
            
          }
          
          if(vuln.findingId && vuln.deviceId)
            vulns.push({...vuln});
        }
      }

    } catch(err) {
      console.log('XML Error: ',err);
      console.log('Did not find valid JSON or XML input ',file);
    }
    return {assets: assets,vulnerabilities: vulns};
};

if(process.argv.length<4) {
    process.argv.push('');
}

(async()=>{
  for( let arg=3; arg<process.argv.length; arg++) {
    scanDate=null;
    let data = await readFile(process.argv[arg]);
    //return console.dir(data,{depth:8});
    await sdk.init({
        url: process.argv[2],
        scanDate: scanDate
    });
    let ret = await sdk.submit(data);
    console.log('Result(',process.argv[arg],') = ', ret.status,ret.data);
  }
})();

