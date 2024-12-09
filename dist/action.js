#!/usr/bin/env node
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
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
const index_1 = require("./index");
try {
    let owner;
    let repo;
    if (core.getInput('repo_owner') && core.getInput('repo_name')) {
        owner = core.getInput('repo_owner');
        console.log('Owner: ' + core.getInput('repo_owner'));
        repo = core.getInput('repo_name');
        console.log('Repo: ' + core.getInput('repo_name'));
    }
    else {
        owner = github.context.repo.owner;
        repo = github.context.repo.repo;
    }
    (0, index_1.run)({
        scanType: core.getInput('scan-type', { required: true }),
        resultsJson: core.getInput('results-json', { required: true }),
        inputFilename: core.getInput('pipeline-results-json', { required: true }),
        outputFilename: core.getInput('output-results-sarif', { required: true }),
        githubToken: core.getInput('githubToken', { required: true }),
        commitSHA: core.getInput('commitSHA', { required: true }),
        ref: core.getInput('ref', { required: true }),
        ruleLevel: core.getInput('finding-rule-level'),
        repo_owner: owner,
        repo_name: repo,
        noupload: core.getInput('noupload'),
        pathReplacers: [
            core.getInput('source-base-path-1'),
            core.getInput('source-base-path-2'),
            core.getInput('source-base-path-3')
        ].join(";")
    }, msg => core.info(msg));
}
catch (error) {
    core.setFailed(error.message);
}
