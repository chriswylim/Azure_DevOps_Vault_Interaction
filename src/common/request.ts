import tl = require('azure-pipelines-task-lib/task');
const url = require('url');
const http = require('http');
const https = require("https");
const Stream = require('stream').Transform;

export function requestVault(requestedUrl: string, ignoreCertificateChecks: boolean, strRequestTimeout: string, token: string, methode: string, body: string): Promise<string> {
    return new Promise((resolve, reject) => {

        // Setup options for requests
        var protocol;
        var options = url.parse(requestedUrl);

        // Set protocol and port in needed
        switch(options.protocol){
            case "https:":
                protocol = https;
                if(!options.port){
                    options.port = 443;
                }
                if(ignoreCertificateChecks){
                    console.log("[INFO] Ignore certificate checks : 'True'");
                    options.rejectUnhauthorized = false;
                    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
                }
                else{
                    console.log("[INFO] Ignore certificate checks : 'False'");
                }
                break;
            case "http:":
                protocol = http;
                if(!options.port){
                    options.port = 80;
                }
                break;
            default:
                reject("Protocol not supported. HTTP or HTTPS are supported.");
        }

        // Set token in headers
        if(body){
            options.headers  = {
                'Content-Type': 'application/json',
                'Content-Length': body.length,
                "X-Vault-Token": token
            }
        }
        else{
            options.headers  = {
                "X-Vault-Token": token
            }
        }

        // Set timeout
        if(strRequestTimeout){
            options.timeout = Number(strRequestTimeout);
        }

        // Set methode
        switch(methode){
            case "post":
            case "POST":
                options.method = "POST";
                break;
            case "list":
            case "LIST":
                    options.method = "LIST";
                    break;
            default:
            case "get":
            case "GET":
                options.method = "GET";
                break;
        }

        var req = protocol.request(options, (res) => {

            var binaryData = new Stream();
            
            var statusCode = res.statusCode;
            
            res.on('data', function (d) {
                binaryData.push(d);
            });
            
            res.on('end', function (e) {

                try{
                    var content = JSON.stringify(JSON.parse(binaryData.read()));
                } catch (err) {
                    reject("Error when converting JSON return. " + err);
                }
                

                if(parseInt(statusCode) < 200 || parseInt(statusCode) > 299){
                    reject("Error when requesting Vault [" + statusCode + "] : \n" + content);
                }

                resolve(content);
                
            });
            
        }).on('error', function catchError(error) {
            reject("Error when requesting Vault '" + requestedUrl + "' : " + error);
        });
        
        if(body){
            req.write(body);
        }
        req.end();
    });
}

export function getToken(strRequestTimeout): Promise<string> {
    return new Promise((resolve, reject) => {
        var strUrl = tl.getInput('strUrl', true);
		var strAuthType = tl.getInput('strAuthType', true);
		var ignoreCertificateChecks = tl.getBoolInput('ignoreCertificateChecks', true);

        var authUrl = null;
        var bodyData = null;

        switch(strAuthType){			
			case "approle":
                console.log("[INFO] Authentication Method : 'AppRole'");

                var strAuthPath = tl.getInput('strAuthPath', false);
                var apiURL = "/v1/auth/approle/login";
                if(strAuthPath){
                    apiURL = "/v1/auth/" + strAuthPath + "/login";
                }

                var strRoleID = tl.getInput('strRoleID', true);
                var strSecretID = tl.getInput('strSecretID', true);

				authUrl = url.resolve(strUrl,apiURL);
				bodyData = JSON.stringify({
					role_id: strRoleID,
					secret_id: strSecretID
				});		
                break;
            case "azure":
                console.log("[INFO] Authentication Method : 'Azure'");

                var strAuthPath = tl.getInput('strAuthPath', false);
                var apiURL = "/v1/auth/azure/login";
                if(strAuthPath){
                    apiURL = "/v1/auth/" + strAuthPath + "/login";
                }

                var strRole = tl.getInput('strRole', true);
                var strJWT = tl.getInput('strJWT', true);

                var strSubscriptionID = tl.getInput('strSubscriptionID', false);
                strSubscriptionID = strSubscriptionID ? strSubscriptionID : "";

                var strResourceGroupName  = tl.getInput('strResourceGroupName', false);
                strResourceGroupName = strResourceGroupName ? strResourceGroupName : "";

                var strVmName  = tl.getInput('strVmName', false);
                strVmName = strVmName ? strVmName : "";

                var strVmssName = tl.getInput('strVmssName', false);
                strVmssName = strVmssName ? strVmssName : "";
                
				authUrl = url.resolve(strUrl,apiURL);
				bodyData = JSON.stringify({
					role: strRole,
					jwt: strJWT,
					subscription_id: strSubscriptionID,
					resource_group_name: strResourceGroupName,
					vm_name: strVmName,
					vmss_name: strVmssName
				});		
                break;
            case "clientToken":
                console.log("[INFO] Authentication Method : 'Client Token'");
                var strToken = tl.getInput('strToken', true);
                resolve(strToken);
                break;
            case "ldap":
                console.log("[INFO] Authentication Method : 'LDAP'");
                var strAuthPath = tl.getInput('strAuthPath', false);
                var apiURL = "/v1/auth/ldap/login/";
                if(strAuthPath){
                    apiURL = "/v1/auth/" + strAuthPath + "/login/";
                }
                var strUsername = tl.getInput('strUsername', true);
		        var strPassword = tl.getInput('strPassword', true);
				authUrl = url.resolve(strUrl,apiURL + strUsername);
				bodyData = JSON.stringify({
					password: strPassword
				});				
                break;
            case "radius":
                console.log("[INFO] Authentication Method : 'Radius'");
                var strAuthPath = tl.getInput('strAuthPath', false);
                var apiURL = "/v1/auth/radius/login/";
                if(strAuthPath){
                    apiURL = "/v1/auth/" + strAuthPath + "/login/";
                }
                var strUsername = tl.getInput('strUsername', true);
		        var strPassword = tl.getInput('strPassword', true);
				authUrl = url.resolve(strUrl,apiURL + strUsername);
				bodyData = JSON.stringify({
					password: strPassword
				});				
                break;
            case "userpass":
                console.log("[INFO] Authentication Method : 'Username & Password'");
                var strAuthPath = tl.getInput('strAuthPath', false);
                var apiURL = "/v1/auth/userpass/login/";
                if(strAuthPath){
                    apiURL = "/v1/auth/" + strAuthPath + "/login/";
                }
                var strUsername = tl.getInput('strUsername', true);
		        var strPassword = tl.getInput('strPassword', true);
				authUrl = url.resolve(strUrl,apiURL + strUsername);
				bodyData = JSON.stringify({
					password: strPassword
				});		
                break;
            case "azuremsi":
                break;
            // AWS
            case "aws":
                break;
			default:
                reject("Authentication method not supported.");
		}
        
        if (strAuthType != "clientToken"){
            console.log("[INFO] Authentication URL : '" + authUrl + "'");
            console.log("[INFO] Starting requesting client token ...");
        }

        if (strAuthType == 'azuremsi') {
            console.log("[INFO] Authentication Method : 'Azure MSI'");
            var strResourceUri = tl.getInput('strResourceURI', true);
            requestAzureJwt(strResourceUri)
                .then(result => {
                    var strAuthPath = tl.getInput('strAuthPath', false);
                    var apiURL = "/v1/auth/azure/login";
                    if(strAuthPath){
                        apiURL = "/v1/auth/" + strAuthPath + "/login";
                    }
                    var strRole = tl.getInput('strRole', true);
                    authUrl = url.resolve(strUrl,apiURL);
                    bodyData = JSON.stringify({
                        role: strRole,
                        jwt: result.jwt,
                        subscription_id: result.subscriptionId,
                        resource_group_name: result.rgName,
                        vm_name: result.vmName,
                        vmss_name: result.vmsName
                    });		
                    requestVault(authUrl, ignoreCertificateChecks, strRequestTimeout, null, "POST", bodyData).then(async function(result) {
                        var resultJSON = JSON.parse(result);
                        var token = resultJSON.auth.client_token;
                        var lease_duration = resultJSON.lease_duration || resultJSON.auth.lease_duration;
                        console.log("[INFO] Token received");
                        console.log("[INFO] Token lease duration : '" + lease_duration + "'");
                        resolve(token);
                    }).catch(function(err) {
                        reject(err);
                    });
                })
                .catch(error => {
                    console.log(error);
                    reject(error);
                });
if (strAuthType == 'azuremsi') {
            console.log("[INFO] Authentication Method : 'Azure MSI'");
            var strResourceUri = tl.getInput('strResourceURI', true);
            requestAzureJwt(strResourceUri)
                .then(result => {
                    var strAuthPath = tl.getInput('strAuthPath', false);
                    var apiURL = "/v1/auth/azure/login";
                    if(strAuthPath){
                        apiURL = "/v1/auth/" + strAuthPath + "/login";
                    }
                    var strRole = tl.getInput('strRole', true);
                    authUrl = url.resolve(strUrl,apiURL);
                    bodyData = JSON.stringify({
                        role: strRole,
                        jwt: result.jwt,
                        subscription_id: result.subscriptionId,
                        resource_group_name: result.rgName,
                        vm_name: result.vmName,
                        vmss_name: result.vmsName
                    });		
                    requestVault(authUrl, ignoreCertificateChecks, strRequestTimeout, null, "POST", bodyData).then(async function(result) {
                        var resultJSON = JSON.parse(result);
                        var token = resultJSON.auth.client_token;
                        var lease_duration = resultJSON.lease_duration || resultJSON.auth.lease_duration;
                        console.log("[INFO] Token received");
                        console.log("[INFO] Token lease duration : '" + lease_duration + "'");
                        resolve(token);
                    }).catch(function(err) {
                        reject(err);
                    });
                })
                .catch(error => {
                    console.log(error);
                    reject(error);
                });
if (strAuthType == 'azuremsi') {
            console.log("[INFO] Authentication Method : 'Azure MSI'");
            var strResourceUri = tl.getInput('strResourceURI', true);
            requestAzureJwt(strResourceUri)
                .then(result => {
                    var strAuthPath = tl.getInput('strAuthPath', false);
                    var apiURL = "/v1/auth/azure/login";
                    if(strAuthPath){
                        apiURL = "/v1/auth/" + strAuthPath + "/login";
                    }
                    var strRole = tl.getInput('strRole', true);
                    authUrl = url.resolve(strUrl,apiURL);
                    bodyData = JSON.stringify({
                        role: strRole,
                        jwt: result.jwt,
                        subscription_id: result.subscriptionId,
                        resource_group_name: result.rgName,
                        vm_name: result.vmName,
                        vmss_name: result.vmsName
                    });		
                    requestVault(authUrl, ignoreCertificateChecks, strRequestTimeout, null, "POST", bodyData).then(async function(result) {
                        var resultJSON = JSON.parse(result);
                        var token = resultJSON.auth.client_token;
                        var lease_duration = resultJSON.lease_duration || resultJSON.auth.lease_duration;
                        console.log("[INFO] Token received");
                        console.log("[INFO] Token lease duration : '" + lease_duration + "'");
                        resolve(token);
                    }).catch(function(err) {
                        reject(err);
                    });
                })
                .catch(error => {
                    console.log(error);
                    reject(error);
                });
if (strAuthType == 'aws') {
    console.log("[INFO] Authentication Method : 'AWS'");
    var strResourceUri = tl.getInput('strResourceURI', true);
    // function - extract jwt here
    requestAzureJwt(strResourceUri)
        .then(result => {
            var strAuthPath = tl.getInput('strAuthPath', false);
            var apiURL = "/v1/auth/azure/login";
            if(strAuthPath){
                apiURL = "/v1/auth/" + strAuthPath + "/login";
            }
            var strRole = tl.getInput('strRole', true);
            authUrl = url.resolve(strUrl,apiURL);
            bodyData = JSON.stringify({
                role: strRole,
                jwt: result.jwt,
                subscription_id: result.subscriptionId,
                resource_group_name: result.rgName,
                vm_name: result.vmName,
                vmss_name: result.vmsName
            });		
            requestVault(authUrl, ignoreCertificateChecks, strRequestTimeout, null, "POST", bodyData).then(async function(result) {
                var resultJSON = JSON.parse(result);
                var token = resultJSON.auth.client_token;
                var lease_duration = resultJSON.lease_duration || resultJSON.auth.lease_duration;
                console.log("[INFO] Token received");
                console.log("[INFO] Token lease duration : '" + lease_duration + "'");
                resolve(token);
            }).catch(function(err) {
                reject(err);
            });
        })
        .catch(error => {
            console.log(error);
            reject(error);
        });
        } else {
            requestVault(authUrl, ignoreCertificateChecks, strRequestTimeout, null, "POST", bodyData).then(async function(result) {
                var resultJSON = JSON.parse(result);
                var token = resultJSON.auth.client_token;
                var lease_duration = resultJSON.lease_duration || resultJSON.auth.lease_duration;
                console.log("[INFO] Token received");
                console.log("[INFO] Token lease duration : '" + lease_duration + "'");
                resolve(token);
            }).catch(function(err) {
                reject(err);
            });
        }
    });
}

export function requestAzureJwt(resourceId : string) : Promise<any> {
    var hostname = 'http://169.254.169.254';
    return new Promise<any>((resolve, reject) => {
        try {
            var tokenUrl = hostname + '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' + encodeURIComponent(resourceId);
            var options = url.parse(tokenUrl);
            options.port = 80;
            options.headers = {
                'Metadata': 'true'
            };
            options.method = 'GET';
            var tokenReq = http.request(options, res => {
                var data = new Stream();
                var statusCode = parseInt(res.statusCode);
                res.on('data', d => data.push(d));
                res.on('end', () => {
                    if (statusCode < 200 || statusCode > 299) {
                        reject('Error requesting MSI token.');
                        return;
                    }
                    var token = JSON.parse(data.read());
                    resolve(token);
                });
            }).on('error', error => reject('Error requesting token: ' + error));
            tokenReq.end();
        } catch(error) {
            reject(error);
        }
    }).then(token => {
        return new Promise((resolve, reject) => {
            try {
                var instanceUrl = hostname + '/metadata/instance?api-version=2017-08-01';
                var options = url.parse(instanceUrl);
                options.port = 80;
                options.headers = {
                    'Metadata': 'true'
                };
                var instanceReq = http.request(options, res => {
                    var data = new Stream();
                    var statusCode = parseInt(res.statusCode);
                    res.on('data', d => data.push(d));
                    res.on('end', () => {
                        if (statusCode < 200 || statusCode > 299) {
                            reject('Error requesting instance details.');
                            return;
                        }
                        var instance = JSON.parse(data.read());
                        var result = {
                            jwt: token.access_token,
                            subscriptionId: instance.compute.subscriptionId,
                            rgName: instance.compute.resourceGroupName,
                            vmName: instance.compute.name
                        };
                        resolve(result);
                    });
                }).on('error', error => reject('Error request instance: ' + error));
                instanceReq.end();
            } catch(error) {
                reject(error);
            }
        });
    });
}