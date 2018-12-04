#!/usr/bin/env node

// Copyright 2019,2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


'use strict';

const inspect_backup = require('./cmd/analyze');
const logger = require('./logger');
const {ProcessError} = require('./errors');
const create_excel_file = require('./excel-writer');
const argv = require('yargs')
    .command('analyze', 'Analyze Datapower backup',
        (yargs) => {
            return yargs
                .option('b', {
                    alias: 'backup-file',
                    describe: 'DataPower backup file',
                    required: true
                })
                .option('o', {
                    alias: 'output-file',
                    describe: 'Excel output file',
                    default: 'out.xlsx',
                })
                .option('h', {
                    alias: 'help'
                })
                .version(false)
                .help(true)
        },
        async ({
                   "backup-file": backup_file,
                   "output-file": outout_file
               }) => {
            try {
                let backup_info = await inspect_backup(backup_file);
                await create_excel_file(outout_file, backup_info);
            } catch (ex) {
                if (ex instanceof ProcessError) {
                    logger.error(ex.message);
                } else {
                    logger.error(ex.message);
                    logger.error(ex.stack);
                }
            }
        })
    .option('h', {
        alias: 'help'
    })
    .version(false)
    .help(true)
    .demandCommand()
    .argv;
