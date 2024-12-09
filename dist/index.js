"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = run;
const fs_1 = __importDefault(require("fs"));
const Converter_1 = require("./Converter");
const utils_1 = require("./utils");
const core = __importStar(require("@actions/core"));
const core_1 = require("@octokit/core");
const zlib_1 = require("zlib");
function run(opt, msgFunc) {
    const scanType = opt.scanType;
    const inputFilename = opt.scanType == 'pipeline' ? opt.inputFilename : opt.resultsJson;
    const outputFilename = opt.outputFilename;
    const ruleLevel = opt.ruleLevel;
    const pathReplacers = opt.pathReplacers;
    if (ruleLevel !== undefined && ruleLevel.length > 0) {
        core.info("##################");
        core.info("WARNING");
        core.info("##################");
        core.info("The 'finding-rule-level' input is deprecated and will be removed in a future release.");
        core.info("It will be overwritten with with 4:3:0");
        core.info("This setting is not needed anymore as GitHub as introduced granular control over the severity of findings");
        core.info("Please find more information here: https://github.blog/changelog/2021-07-19-codeql-code-scanning-new-severity-levels-for-security-alerts/#about-security-severity-levels");
        core.info("##################");
    }
    let rawData = fs_1.default.readFileSync(inputFilename);
    let converter = new Converter_1.Converter({
        replacers: (0, utils_1.setupSourceReplacement)(...pathReplacers.split(";")),
        reportLevels: (0, utils_1.sliceReportLevels)(ruleLevel)
    }, msgFunc);
    let output;
    try {
        let results = JSON.parse(rawData.toString());
        if (scanType === 'policy') {
            try {
                output = converter.convertPolicyScanResults(results);
            }
            catch (error) {
                core.info(`Failed to convert policy result to sarif : ${error}`);
                output = converter.policyResultConvertSarifLog(results);
            }
        }
        else {
            try {
                output = converter.convertPipelineScanResults(results);
            }
            catch (error) {
                core.info(`Failed to convert pipeline result to sarif : ${error}`);
                output = converter.convertSarifLog(results);
            }
        }
    }
    catch (error) {
        throw Error('Failed to parse input file ' + inputFilename);
    }
    fs_1.default.writeFileSync(outputFilename, JSON.stringify(output));
    msgFunc('file created: ' + outputFilename);
    uploadSARIF(outputFilename, opt);
}
//upload SARIF
function uploadSARIF(outputFilename, opt) {
    return __awaiter(this, void 0, void 0, function* () {
        if (opt.noupload === 'true') {
            console.log('Skipping upload to GitHub');
            return;
        }
        else {
            //gzip compress and base64 encode the SARIF file
            function createGzipBase64(outputFilename) {
                return __awaiter(this, void 0, void 0, function* () {
                    try {
                        // Read the entire file into memory
                        const fileData = fs_1.default.readFileSync(outputFilename);
                        console.log('File data: ' + fileData);
                        // Compress the file data
                        const compressedData = (0, zlib_1.gzipSync)(fileData);
                        // Encode the compressed data to base64
                        const base64Data = compressedData.toString('base64');
                        return base64Data;
                    }
                    catch (error) {
                        throw error;
                    }
                });
            }
            const octokit = new core_1.Octokit({
                auth: opt.githubToken
            });
            const base64Data = yield createGzipBase64(outputFilename);
            console.log('Base64 data: ' + base64Data);
            yield octokit.request('POST /repos/' + opt.repo_owner + '/' + opt.repo_name + '/code-scanning/sarifs', {
                //        headers: {
                //            authorization: opt.githubToken
                //        },
                //        owner: opt.repo_owner,
                //       repo: opt.repo_name,
                ref: opt.ref,
                commit_sha: opt.commitSHA,
                sarif: base64Data
            });
        }
    });
}
