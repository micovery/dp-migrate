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

let categories = module.exports.names = {
    SEC: 'Security',
    ROU: 'Routing',
    XFM: 'Transformation',
    VAL: 'Validation',
    LOG: 'Logging',
    OTH: 'Other',
};

let colors = module.exports.colors = {};

colors[categories.SEC] = 'ffe06666';
colors[categories.ROU] = 'ff3c78d8';
colors[categories.XFM] = 'ffb45f06';
colors[categories.VAL] = 'ff9fc5e8';
colors[categories.LOG] = 'ff783f04';
colors[categories.OTH] = 'ffd9d9d9';

let abbr = module.exports.abbr = {};

abbr[categories.SEC] = 'sec';
abbr[categories.ROU] = 'route';
abbr[categories.XFM] = 'xform';
abbr[categories.VAL] = 'val';
abbr[categories.LOG] = 'log';
abbr[categories.OTH] = 'other';


module.exports.by_action_type = {
    'convert-http': categories.XFM,
    'slm': categories.ROU,
    'call': categories.OTH,
    'setvar': categories.ROU,
    'gatewayscript': categories.XFM,
    'method-rewrite': categories.XFM,
    'fetch': categories.XFM,
    'aaa' : categories.SEC,
    'route-action': categories.ROU,
    'route-set': categories.ROU,
    'xformbin': categories.XFM,
    'xformng': categories.XFM,
    'xformpi': categories.XFM,
    'xform': categories.XFM,
    'jose-decrypt': categories.SEC,
    'decrypt': categories.SEC,
    'jose-encrypt': categories.SEC,
    'encrypt': categories.SEC,
    'jose-verify': categories.VAL,
    'jose-sign': categories.VAL,
    'sign': categories.VAL,
    'verify': categories.VAL,
    'filter': categories.XFM,
    'validate': categories.VAL,
    'antivirus': categories.SEC,
    'log': categories.LOG,
    'on-error': categories.ROU,
    'extract': categories.XFM,
    'results': categories.ROU,
    'results_output': categories.ROU
};



