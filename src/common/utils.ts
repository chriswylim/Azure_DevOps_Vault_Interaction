import tl = require('azure-pipelines-task-lib/task');
import fs = require('fs');
import iconv = require('iconv-lite');

export function exportJSONValues(obj: any, prefix: string, replaceCR: boolean, strCRPrefix: string, strFilePath: string, strTargetFiles: any): Promise<boolean> {
    // Source https://raw.githubusercontent.com/geeklearningio/gl-vsts-tasks-variables/master/Common/Node/expandJObject.ts
    return new Promise(async (resolve, reject) => {
        try {
            var typeArray: string[] =["string", "number", "boolean"];
            if (obj instanceof Array) {
                if(prefix != ""){
                    prefix = prefix + "_";
                }
                else{
                    prefix = "";
                }
                for (var i = 0; i < obj.length; i++) {
                    var element = obj[i];
                    await exportJSONValues(element, prefix + i.toString(), replaceCR, strCRPrefix, strFilePath, strTargetFiles);
                }
            }
            else if (typeArray.indexOf(typeof obj) > -1){
                var objValue = typeArray.indexOf(typeof obj)>0 ? obj.toString() : obj;
                if(replaceCR){
                    objValue = objValue.replace(/(?:\\[rn]|[\r\n])/g,strCRPrefix);
                }
                strTargetFiles.forEach((targetFile : string) => {
                    if (targetFile) {
                        console.log('[INFO] Finding match between ' + strFilePath + ' with ' + targetFile)
                        tl.findMatch(strFilePath, targetFile).forEach(filePath => {
                            if (tl.stats(filePath).isDirectory())
                                return;
                            if (!tl.exist(filePath)) {
                                console.log('File ' + filePath + ' not found.');
                                return;
                            }
                            console.log('Replacing token in ' + filePath);
                            let content: string = iconv.decode(fs.readFileSync(filePath), 'UTF-8');
                            content = content.replace(prefix, objValue);
                            fs.writeFileSync(filePath, iconv.encode(content, 'UTF-8'));
                        });
                    }
                });
                tl.setVariable(prefix, objValue, true);
            }
            else{
                if(prefix != ""){
                    prefix = prefix + "_";
                }
                else{
                    prefix = "";
                }
                for (var key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        var element = obj[key];
                        await exportJSONValues(element, prefix + key, replaceCR, strCRPrefix, strFilePath, strTargetFiles);
                    }
                }
            }

            resolve(true);

        } catch (err) {
		    reject("Error when exporting values. " + err);
	    }

    });
}