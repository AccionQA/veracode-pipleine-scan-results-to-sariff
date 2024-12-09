"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Converter = void 0;
const utils_1 = require("./utils");
class Converter {
    constructor(conversionConfig, msgFunc) {
        this.config = conversionConfig;
        this.msgFunc = msgFunc;
    }
    convertPipelineScanResults(pipelineScanResult) {
        this.msgFunc('Pipeline Scan results file found and parsed - validated JSON file');
        //"scan_status": "SUCCESS"
        if (pipelineScanResult.scan_status !== "SUCCESS") {
            throw Error("Unsuccessful scan status found");
        }
        this.msgFunc('Issues count: ' + pipelineScanResult.findings.length);
        let rules = pipelineScanResult.findings
            .reduce((acc, val) => {
            // dedupe by cwe_id
            if (!acc.map(value => value.cwe_id).includes(val.cwe_id)) {
                acc.push(val);
            }
            return acc;
        }, [])
            .map(issue => this.issueToRule(issue));
        // convert to SARIF json
        let sarifResults = pipelineScanResult.findings
            .map(issue => this.issueToResult(issue));
        // construct the full SARIF content
        return {
            $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: [
                {
                    tool: {
                        driver: {
                            name: "Veracode Static Analysis Pipeline Scan",
                            rules: rules
                        }
                    },
                    results: sarifResults
                }
            ]
        };
    }
    issueToRule(issue) {
        return {
            id: issue.cwe_id,
            name: issue.issue_type,
            shortDescription: {
                text: "CWE-" + issue.cwe_id + ": " + issue.issue_type
            },
            helpUri: "https://cwe.mitre.org/data/definitions/" + issue.cwe_id + ".html",
            properties: {
                "security-severity": (0, utils_1.mapVeracodeSeverityToCVSS)(issue.severity),
                category: issue.issue_type_id,
                tags: [issue.issue_type_id]
            },
            //            defaultConfiguration: {
            //                level: issue.severity
            //            }
        };
    }
    issueToResult(issue) {
        let sourceFile = issue.files.source_file;
        // construct flaw location
        let location = {
            physicalLocation: {
                artifactLocation: {
                    uri: (0, utils_1.getFilePath)(sourceFile.file, this.config.replacers)
                },
                region: {
                    startLine: sourceFile.line
                }
            },
            logicalLocations: [
                {
                    name: sourceFile.function_name,
                    fullyQualifiedName: sourceFile.qualified_function_name,
                    kind: "function",
                },
                {
                    fullyQualifiedName: issue.title,
                    kind: "member",
                    parentIndex: 0
                }
            ]
        };
        var flawMatch;
        if (issue.flaw_match === undefined) {
            var flawMatch = {
                flaw_hash: "",
                flaw_hash_count: 0,
                flaw_hash_ordinal: 0,
                cause_hash: "",
                cause_hash_count: 0,
                cause_hash_ordinal: 0,
                procedure_hash: "",
                prototype_hash: "",
            };
        }
        else {
            var flawMatch = issue.flaw_match;
        }
        let fingerprints = {
            flawHash: flawMatch.flaw_hash,
            flawHashCount: flawMatch.flaw_hash_count.toString(),
            flawHashOrdinal: flawMatch.flaw_hash_ordinal.toString(),
            causeHash: flawMatch.cause_hash,
            causeHashCount: flawMatch.cause_hash_count.toString(),
            causeHashOrdinal: flawMatch.cause_hash_ordinal.toString(),
            procedureHash: flawMatch.procedure_hash,
            prototypeHash: flawMatch.prototype_hash,
        };
        // construct the issue
        let ghrank = +(0, utils_1.mapVeracodeSeverityToCVSS)(issue.severity);
        return {
            // get the severity number to name
            level: this.config.reportLevels.get(issue.severity),
            rank: ghrank,
            message: {
                text: issue.display_text,
            },
            locations: [location],
            ruleId: issue.cwe_id,
            partialFingerprints: fingerprints
        };
    }
    convertSarifLog(sarifLog) {
        let issues = sarifLog.runs
            // flatmap results
            .map(run => run.results)
            .reduce((acc, val) => acc.concat(val), [])
            // flatmap results to each location
            .map(val => val.locations.map(location => [val, location]))
            .reduce((acc, val) => acc.concat(val), [])
            // get member which is nested within function
            .map(pair => {
            let possibleCallees = pair[1].logicalLocations
                .filter(logicalLocation => logicalLocation.kind === "member" &&
                logicalLocation.parentIndex !== undefined &&
                pair[1].logicalLocations[logicalLocation.parentIndex].kind === "function");
            if (possibleCallees.length > 0) {
                return [pair[0], pair[1], possibleCallees[0]];
            }
            else {
                return undefined;
            }
        })
            .filter(triple => triple !== undefined)
            .map(triple => {
            let result = triple[0];
            let location = triple[1];
            let memberCallLogicalLocations = triple[2];
            let functionLogicalLocations = location.logicalLocations[memberCallLogicalLocations.parentIndex];
            return {
                title: memberCallLogicalLocations.fullyQualifiedName,
                cwe_id: result.ruleId,
                severity: result.rank,
                display_text: result.message.text,
                files: {
                    source_file: {
                        file: location.physicalLocation.artifactLocation.uri,
                        line: location.physicalLocation.region.startLine,
                        function_name: functionLogicalLocations.name,
                        qualified_function_name: functionLogicalLocations.fullyQualifiedName
                    }
                },
                flaw_match: this.fingerprintsToFlawMatch(result.fingerprints, result.partialFingerprints)
            };
        });
        return {
            findings: issues,
        };
    }
    fingerprintsToFlawMatch(fingerprints, partialFingerpirnts) {
        if (partialFingerpirnts &&
            ["procedureHash", "prototypeHash",
                "flawHash", "flawHashCount", "flawHashOrdinal",
                "causeHash", "causeHashCount", "causeHashOrdinal"]
                .every(propertyName => propertyName in partialFingerpirnts && partialFingerpirnts[propertyName])) {
            // we do this because the values of fingerprints is string type
            // but FLawMatch have number typed properties
            this.msgFunc("Using partial fingerprint keys");
            return {
                procedure_hash: partialFingerpirnts["procedureHash"].toString(),
                cause_hash: partialFingerpirnts["causeHash"].toString(),
                cause_hash_count: parseInt(partialFingerpirnts["causeHashCount"]),
                cause_hash_ordinal: parseInt(partialFingerpirnts["causeHashOrdinal"]),
                flaw_hash: partialFingerpirnts["flawHash"].toString(),
                flaw_hash_count: parseInt(partialFingerpirnts["flawHashCount"]),
                flaw_hash_ordinal: parseInt(partialFingerpirnts["flawHashOrdinal"]),
                prototype_hash: partialFingerpirnts["prototypeHash"].toString(),
            };
        }
        let fingerprintKeys = Object.keys(fingerprints);
        let versionRegExp = new RegExp(/\/v(\d+)$/);
        if (fingerprintKeys.length > 0) {
            let highestKey = fingerprintKeys.reduce((current, nextValue) => {
                let currentVersionMatch = current.match(versionRegExp);
                let currentVersion = currentVersionMatch === null ? 0 : parseInt(currentVersionMatch[1]);
                let nextVersionMatch = nextValue.match(versionRegExp);
                let nextVersion = nextVersionMatch === null ? 0 : parseInt(nextVersionMatch[1]);
                if (currentVersion > nextVersion) {
                    return current;
                }
                else {
                    return nextValue;
                }
            }, fingerprintKeys[0]);
            this.msgFunc("Using " + highestKey + " as main fingerprint");
            return {
                sarif_fingerprint: fingerprints[highestKey]
            };
        }
        throw Error("Flaw fingerprints not set or error parsing SARIF fingerprints");
    }
    convertPolicyScanResults(policyScanResult) {
        this.msgFunc('Policy Scan results file found and parsed - validated JSON file');
        this.msgFunc('Issues count: ' + policyScanResult._embedded.findings.length);
        let rules = policyScanResult._embedded.findings
            .reduce((acc, val) => {
            // dedupe by cwe_id
            console.log('acc', acc);
            console.log('val', val);
            if (!acc.map(value => value.finding_details.cwe.id).includes(val.finding_details.cwe.id)) {
                acc.push(val);
            }
            return acc;
        }, [])
            .map(issue => this.findingToRule(issue));
        // convert to SARIF json
        let sarifResults = policyScanResult._embedded.findings
            .map(findings => this.findingToResult(findings));
        // construct the full SARIF content
        return {
            $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: [
                {
                    tool: {
                        driver: {
                            name: "Veracode Static Analysis Policy Scan",
                            rules: rules
                        }
                    },
                    results: sarifResults
                }
            ]
        };
    }
    findingToRule(finding) {
        var _a, _b, _c, _d, _e;
        /*
         {
                  "id": "no-unused-vars",
                  "shortDescription": {
                    "text": "disallow unused variables"
                  },
                  "helpUri": "https://eslint.org/docs/rules/no-unused-vars",
                  "properties": {
                    "category": "Variables"
                  }
                }
        */
        return {
            id: (_a = finding.finding_details.cwe) === null || _a === void 0 ? void 0 : _a.id.toString(),
            name: (_b = finding.finding_details.cwe) === null || _b === void 0 ? void 0 : _b.name,
            shortDescription: {
                text: "CWE-" + ((_c = finding.finding_details.cwe) === null || _c === void 0 ? void 0 : _c.id.toString()) + ": " + ((_d = finding.finding_details.cwe) === null || _d === void 0 ? void 0 : _d.name)
            },
            helpUri: "https://cwe.mitre.org/data/definitions/" + ((_e = finding.finding_details.cwe) === null || _e === void 0 ? void 0 : _e.id.toString()) + ".html",
            properties: {
                "security-severity": (0, utils_1.mapVeracodeSeverityToCVSS)(finding.finding_details.severity),
                category: finding.scan_type,
                tags: [finding.scan_type]
            },
            // defaultConfiguration: {
            //     level: this.config.reportLevels.get(finding.finding_details.severity)
            // }
        };
    }
    findingToResult(finding) {
        var _a;
        let finding_details = finding.finding_details;
        // construct flaw location
        let location = {
            physicalLocation: {
                artifactLocation: {
                    uri: (0, utils_1.removeLeadingSlash)((0, utils_1.getFilePath)(finding_details.file_path, this.config.replacers))
                },
                region: {
                    startLine: finding_details.file_line_number
                }
            },
            logicalLocations: [
                {
                    name: finding_details.file_name,
                    fullyQualifiedName: finding_details.procedure,
                    kind: "function",
                },
                {
                    fullyQualifiedName: finding_details.attack_vector,
                    kind: "member",
                    parentIndex: 0
                }
            ]
        };
        var flawMatch;
        if (finding.flaw_match === undefined) {
            var flawMatch = {
                context_guid: "",
                file_path: "",
                procedure: "",
            };
        }
        else {
            var flawMatch = finding.flaw_match;
        }
        let fingerprints = {
            context_guid: flawMatch.context_guid,
            file_path: flawMatch.file_path,
            procedure: flawMatch.procedure
        };
        // construct the issue
        let ghrank = +(0, utils_1.mapVeracodeSeverityToCVSS)(finding_details.severity);
        return {
            // get the severity number to name
            level: this.config.reportLevels.get(finding_details.severity),
            rank: ghrank,
            message: {
                text: finding.description,
            },
            locations: [location],
            ruleId: (_a = finding_details.cwe) === null || _a === void 0 ? void 0 : _a.id.toString(),
            partialFingerprints: fingerprints
        };
    }
    policyResultConvertSarifLog(sarifLog) {
        let issues = sarifLog.runs
            // flatmap results
            .map(run => run.results)
            .reduce((acc, val) => acc.concat(val), [])
            // flatmap results to each location
            .map(val => val.locations.map(location => [val, location]))
            .reduce((acc, val) => acc.concat(val), [])
            // get member which is nested within function
            .map(pair => {
            let possibleCallees = pair[1].logicalLocations
                .filter(logicalLocation => logicalLocation.kind === "member" &&
                logicalLocation.parentIndex !== undefined &&
                pair[1].logicalLocations[logicalLocation.parentIndex].kind === "function");
            if (possibleCallees.length > 0) {
                return [pair[0], pair[1], possibleCallees[0]];
            }
            else {
                return undefined;
            }
        })
            .filter(triple => triple !== undefined)
            .map(triple => {
            let result = triple[0];
            let location = triple[1];
            let memberCallLogicalLocations = triple[2];
            let functionLogicalLocations = location.logicalLocations[memberCallLogicalLocations.parentIndex];
            return {
                // title: memberCallLogicalLocations.fullyQualifiedName,
                description: result.message.text,
                finding_details: {
                    cwe: {
                        id: result.ruleId ? parseInt(result.ruleId) : null
                    },
                    severity: result.rank,
                    file_path: location.physicalLocation.artifactLocation.uri,
                    file_line_number: location.physicalLocation.region.startLine,
                    file_name: functionLogicalLocations.name,
                    attack_vector: functionLogicalLocations.fullyQualifiedName
                },
                flaw_match: this.fingerprintsToPolicyFlawMatch(result.partialFingerprints)
            };
        });
        return {
            _embedded: {
                findings: issues
            }
        };
    }
    fingerprintsToPolicyFlawMatch(partialFingerpirnts) {
        if (partialFingerpirnts &&
            ["context_guid", "file_path", "procedure"]
                .every(propertyName => propertyName in partialFingerpirnts && partialFingerpirnts[propertyName])) {
            // we do this because the values of fingerprints is string type
            // but FLawMatch have number typed properties
            this.msgFunc("Using partial fingerprint keys");
            return {
                context_guid: partialFingerpirnts["procedureHash"].toString(),
                file_path: partialFingerpirnts["file_path"].toString(),
                procedure: partialFingerpirnts["procedure"].toString(),
            };
        }
        let fingerprintKeys = Object.keys(partialFingerpirnts);
        let versionRegExp = new RegExp(/\/v(\d+)$/);
        if (fingerprintKeys.length > 0) {
            let highestKey = fingerprintKeys.reduce((current, nextValue) => {
                let currentVersionMatch = current.match(versionRegExp);
                let currentVersion = currentVersionMatch === null ? 0 : parseInt(currentVersionMatch[1]);
                let nextVersionMatch = nextValue.match(versionRegExp);
                let nextVersion = nextVersionMatch === null ? 0 : parseInt(nextVersionMatch[1]);
                if (currentVersion > nextVersion) {
                    return current;
                }
                else {
                    return nextValue;
                }
            }, fingerprintKeys[0]);
            this.msgFunc("Using " + highestKey + " as main fingerprint");
            return {
                sarif_fingerprint: partialFingerpirnts[highestKey]
            };
        }
        throw Error("Flaw fingerprints not set or error parsing SARIF fingerprints");
    }
}
exports.Converter = Converter;
