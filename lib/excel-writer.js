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
const { promisify } = require('util');
const fs = require('fs');
const logger = require('./logger');
const path = require('path');
const {ProcessError} = require('./errors');
const _ = require('lodash');
const categories = require('./categories');
const YAML = require('json-to-pretty-yaml');

const Excel = require('exceljs');


function cell(worksheet, row, col) {
    return worksheet.getRow(row).getCell(col)._address;
}


async function group_actions_by_category(backup_info) {

    let actions_by_category = {};

    for (let domain_name in backup_info.domains) {
        let domain_info = backup_info.domains[domain_name];

        for (let mpg_name in domain_info.mpgs) {
            let mpg_info = domain_info.mpgs[mpg_name];

            for (let policy_name in mpg_info.policy) {
                let policy = mpg_info.policy[policy_name];

                for (let rule_name in policy.rules) {
                    let rule = policy.rules[rule_name];
                    for (let action of rule.actions) {
                        let action_type = Object.keys(action)[0];
                        let action_info = action[action_type];

                        let category = categories.by_action_type[action_type];
                        if (!category) {
                            logger.warn(`Unknown action of type ${action_type}`);
                            category = categories.names.OTH;
                        }

                        if (!actions_by_category[category]) {
                            actions_by_category[category] = {};
                        }

                        let action_key = `${policy_name}/${action_info.name}`;
                        if (!actions_by_category[category][action_key]) {
                            actions_by_category[category][action_key] = {
                                direction: rule.direction,
                                info: action_info,
                                mpgs: [],
                            }
                        }

                        actions_by_category[category][action_key].mpgs.push({name: mpg_name, domain: domain_name});
                    }
                }
            }
        }
    

    
            for (let wsp_name in domain_info.wsps) {
                let wsp_info = domain_info.wsps[wsp_name];
    
                for (let policy_name in wsp_info.policies) {
                    let policy = wsp_info.policies[policy_name];
    
                    for (let rule_name in policy.rules) {
                        let rule = policy.rules[rule_name];
                        for (let action of rule.actions) {
                            let action_type = Object.keys(action)[0];
                            let action_info = action[action_type];
    
                            let category = categories.by_action_type[action_type];
                            if (!category) {
                                logger.warn(`Unknown action of type ${action_type}`);
                                category = categories.names.OTH;
                            }
    
                            if (!actions_by_category[category]) {
                                actions_by_category[category] = {};
                            }
    
                            let action_key = `${policy_name}/${action_info.name}`;
                            if (!actions_by_category[category][action_key]) {
                                actions_by_category[category][action_key] = {
                                    direction: rule.direction,
                                    info: action_info,
                                    wsps: [],
                                }
                            }
    
                            actions_by_category[category][action_key].wsps.push({name: wsp_name, domain: domain_name});
                        }
                    }
                }
            }
        

    

        


    }

    return actions_by_category;

}

function format_header_cell(ws, value, row, col, options) {
    options = _.merge({
        value: value,
        font: {
            bold: true,
            name: 'Arial',
            color: {
                argb: 'FFFFFFFF'
            },
            size: options.font_size || 10
        },
        fill: {
            type: 'pattern',
            pattern:'solid',
            fgColor:{
                argb: 'FF666666'
            }
        },
        alignment: {
            vertical:  'middle',
            horizontal: 'center'
        },
        border : {
            top: {style:'thin'},
            left: {style:'thin'},
            bottom: {style:'thin'},
            right: {style:'thin'}
        }
    }, options || {});

    let c_cell = ws.getCell(`${cell(ws,row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}


function format_generic_cell(ws, value, row, col, options) {
    options = _.merge({
        value: value,
        font: {
            bold: true,
            name: 'Arial',
            color: {
                argb: 'FFFFFFFF'
            },
            size: options.font_size || 10
        },
        fill: {
            type: 'pattern',
            pattern: 'solid'
        },
        alignment: {
            vertical:  'middle',
            horizontal: 'center'
        },
    }, options || {});

    let c_cell = ws.getCell(`${cell(ws,row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}



function format_left_header_cell(ws, value, row, col, options) {

   options = _.merge({
        value: value,
        font: {
            bold: false,
            name: 'Arial',
            color: {
                argb:  'FF000000'
            },
            size: 10
        },
        fill: {
            type: 'pattern',
            pattern:'solid',
            fgColor:{
                argb: 'FFEFEFEF'
            }
        },
        alignment: {
            vertical: 'middle',
            horizontal: 'right'
        },
        border : {
            right: {style:'thin'}
        }
    }, options ||   {});


    let c_cell = ws.getCell(`${cell(ws,row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}


function format_policy_header_cell(ws, value, row, col, options) {

    options = _.merge({
        value: value,
        font: {
            bold: true,
            name: 'Arial',
            color: {
                argb: 'FFFFFFFF'
            },
            size: 10
        },
        fill: {
            type: 'pattern',
            pattern: 'solid',
            fgColor: {
                argb: 'FF666666'
            }
        },
        alignment: {
            vertical: 'middle',
            horizontal: 'center'
        },
        border : {
            top: {style:'thin'},
            left: {style:'thin'},
            bottom: {style:'thin'},
            right: {style:'thin'}
        }
    }, options || {});

    let c_cell = ws.getCell(`${cell(ws, row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}


function format_policy_action_cell(ws, value, row, col, options) {

    options = _.merge({
        value: value,
        font: {
            bold: false,
            name: 'Courier New',
            color: {
                argb: 'FF000000'
            },
            size: 8
        },
        fill: {
            type: 'pattern',
            pattern: 'solid',
            fgColor: {
                argb: 'FFFFFFFF'
            }
        },
        alignment: {
            vertical: 'middle',
            horizontal: 'left'
        },
        border : {
            top: {style:'thin'},
            left: {style:'thin'},
            bottom: {style:'thin'},
            right: {style:'thin'}
        }
    }, options || {});

    let c_cell = ws.getCell(`${cell(ws, row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}



function format_domain_row_cell(ws, value, row, col, options) {
    options = _.merge({
        value: value,
        font: {
            bold: false,
            name: 'Arial',
            color: {
                argb: 'FF000000'
            },
            size: 8
        },
        alignment: {
            vertical: 'middle',
            horizontal: 'left'
        }
    }, options || {});

    let c_cell = ws.getCell(`${cell(ws, row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}



function format_selected_cell(ws, value, row, col, options) {
    options = _.merge({
        value: value,
        font: {
            bold: false,
            name: 'Arial',
            color: {
                argb: 'FF000000'
            },
            size: 10
        },
        alignment: {
            vertical: 'middle',
            horizontal: 'center'
        }
    }, options || {});

    let c_cell = ws.getCell(`${cell(ws, row, col)}`);
    Object.assign(c_cell, options);

    if (options.col_width) {
        ws.getColumn(col).width = options.col_width;
    }

    if (options.row_height) {
        ws.getRow(row).height = options.row_height;
    }
}

module.exports = async function create_excel_file(file_name, backup_info) {

    var workbook = new Excel.Workbook();


    var ws = workbook.addWorksheet('Policies');


    format_header_cell(ws, "Policy Rule Actions", 1, 4, {row_height: 25});
    format_header_cell(ws, "Proxy", 7, 1, {col_width: 45});
    format_header_cell(ws, "Type", 7, 2, {col_width: 25});
    format_header_cell(ws, "Domain", 7, 3, {col_width: 45});

    format_left_header_cell(ws, "category", 2, 3);
    format_left_header_cell(ws, "alias", 3, 3);
    format_left_header_cell(ws, "direction", 4, 3);
    format_left_header_cell(ws, "definition", 5, 3);


    let actions_by_cat = await group_actions_by_category(backup_info);

    // add categories to spreadsheet

    let actions_by_mpg = {};
    let actions_by_wsp = {};


    let start_col = 4;
    let end_col = start_col;
    for (let category_name in actions_by_cat) {
        let actions_in_cat = actions_by_cat[category_name];
        let actions_count = Object.keys(actions_in_cat).length;
        let new_end_col = end_col + actions_count;
        ws.mergeCells(`${cell(ws, 2, end_col)}:${cell(ws, 2, new_end_col)}`);

        let alias_row = 3;
        let dir_row = 4;
        let def_row = 5;

        format_policy_header_cell(ws, category_name, 2, end_col, {fill:{fgColor:{argb:categories.colors[category_name]}}});


        let thin = {style: 'thin'};
        let none = {style: 'none'};
        let border_top = {border: {left: thin, right: thin, bottom: none, top: thin}};
        let border_mid = {border: {left: thin, right: thin,  bottom: none, top: none}};
        let border_bot = {border: {left: thin, right: thin, bottom: thin, top: none}};


        let action_col = end_col;
        let index = 1;
        for (let action_full_name  in actions_in_cat) {
            let action_data = actions_in_cat[action_full_name];
            let action_info = action_data.info;
            let abbr = categories.abbr[category_name];
            let action_alias = `${abbr}-${index}`;

            format_header_cell(ws, action_alias, alias_row, action_col, _.merge({col_width: 45, fill:{fgColor:{argb:categories.colors[category_name]}}}, border_top));
            format_policy_action_cell(ws, action_data.direction, dir_row, action_col, _.merge({col_width: 30,  fill:{fgColor:{argb:'ffd9d9d9'}}}, border_mid));
            format_policy_action_cell(ws, YAML.stringify(action_info), def_row, action_col, _.merge({col_width: 30,  fill:{fgColor:{argb:'ffd9d9d9'}}}, border_bot));

            if (action_data.hasOwnProperty("mpgs"))
            {
            for (let mpg_info of action_data.mpgs) {
                let key = `${mpg_info.domain}:${mpg_info.name}`;
                if (!actions_by_mpg[key]) {
                    actions_by_mpg[key] = {
                        mpg_name: mpg_info.name,
                        domain_name: mpg_info.domain,
                        'actions': {}
                    };
                }

                actions_by_mpg[key]['actions'][action_full_name] = {column: action_col, data: action_data};
            }

            index += 1;
            action_col += 1;
        }

            if (action_data.hasOwnProperty("wsps"))
           {
            for (let wsp_info of action_data.wsps) {
                let key = `${wsp_info.domain}:${wsp_info.name}`;
                if (!actions_by_wsp[key]) {
                    actions_by_wsp[key] = {
                        wsp_name: wsp_info.name,
                        domain_name: wsp_info.domain,
                        'actions': {}
                    };
                }

                actions_by_wsp[key]['actions'][action_full_name] = {column: action_col, data: action_data};
            }

            index += 1;
            action_col += 1;
        }

        }

        let bypass_color = 'ff6aa84f';
        format_header_cell(ws, 'Bypass', alias_row, action_col, _.merge({col_width: 25, fill:{fgColor:{argb: bypass_color}}}, border_top));
        format_header_cell(ws, ' ', dir_row, action_col, _.merge({col_width: 25, fill:{fgColor:{argb: bypass_color}}}, border_mid));
        format_header_cell(ws, ' ', def_row, action_col, _.merge({col_width: 25, fill:{fgColor:{argb: bypass_color}}}, border_bot));

        end_col = new_end_col + 1;
    }


    ws.mergeCells(`${cell(ws,1,start_col)}:${cell(ws,1,end_col - 1)}`);

    let cur_row = 8;
    for (let key in actions_by_mpg) {
        let data = actions_by_mpg[key];
        let mpg_name = data.mpg_name;
        let domain_name = data.domain_name;
        let actions = data.actions;

        for (let col = 1; col < end_col; col++) {
            if (cur_row % 2 === 0) {
                format_generic_cell(ws, null, cur_row, col, {fill: {fgColor: {argb: 'ffd9d9d9'}}});
            }
        }

        format_domain_row_cell(ws, mpg_name, cur_row, 1);
        format_domain_row_cell(ws, 'MultiProtocolGateway', cur_row, 2);
        format_domain_row_cell(ws, domain_name, cur_row, 3);
        for (let action_key in actions) {
            let action_info = actions[action_key];
            format_selected_cell(ws, "✓", cur_row, action_info.column);
        }

        cur_row += 1;
    }

    for (let key in actions_by_wsp) {
        let data = actions_by_wsp[key];
        let wsp_name = data.wsp_name;
        let domain_name = data.domain_name;
        let actions = data.actions;

        for (let col = 1; col < end_col; col++) {
            if (cur_row % 2 === 0) {
                format_generic_cell(ws, null, cur_row, col, {fill: {fgColor: {argb: 'ffd9d9d9'}}});
            }
        }

        format_domain_row_cell(ws, wsp_name, cur_row, 1);
        format_domain_row_cell(ws, 'WebServiceProxy', cur_row, 2);
        format_domain_row_cell(ws, domain_name, cur_row, 3);
        for (let action_key in actions) {
            let action_info = actions[action_key];
            format_selected_cell(ws, "✓", cur_row, action_info.column);
        }

        cur_row += 1;
    }

    /*
     ws.views = [
        {state: 'frozen', xSplit: 3, ySplit: 7, topLeftCell: 'D8', activeCell: 'A1'}
    ];
    */

    let res = await workbook.xlsx.writeFile(file_name);
};
