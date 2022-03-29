# Webhook SDK

Using this lib you can submit your requests using: submit(payload, callback)

You will need to call, init({ url: webhool_url }, callback), first to initialize:
  url: full url for the webhook
  maxTTL: optional max seconds to wait for a response
  ua: optional useragent string to use

The payload object will be checked for basic reasonable values and submitted using the webhook POST.

## Payload

The payload object will be formatted such as a json object:
```
{
  assets: [
    {
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
    }
  ],
  vaulnerabilities: [
    {
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
      "userAttributes":     object          any extra info
      "severityCVSS3Score": (string)        from 0 to 10 float for CVSS3 score
      "severityCVSS2Score": (string)        from 0 to 10 float for CVSS2 score
      "severityOtherScore": (string)        from 0 to 10 float for Other score
      "severityCVSS3Vector":string          CVSS3 Vector string
      "severityCVSS2Vector":string          CVSS2 Vector string
      "numericSeverity":    (string)        from 0 to 10, written to severityOtherScore
      "severity":           string          Human readable severity, used if numericSeverity is empty
    }
  }
}
```
