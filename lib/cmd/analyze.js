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
const decompress = require('decompress');
const { promisify } = require('util');
const fs = require('fs');
const logger = require('../logger');
const path = require('path');
const {ProcessError} = require('../errors');
const _ = require('lodash');
const XPath = require('xpath');
const XMLDom = require('xmldom');
const DOMParser = XMLDom.DOMParser;
const YAML = require('json-to-pretty-yaml');
const fs_access_async = promisify(fs.access);

async function get_policy_rule_match_name(policy_map) {
    let match_name = XPath.select('./Match', policy_map)[0].textContent;
    return match_name;
}

async function get_matching_operator(matching) {
    let combine_with_or = XPath.select('./CombineWithOr', matching)[0].textContent;

    if (combine_with_or === 'on') {
        return 'or';
    }

    return 'and'
}

async function inspect_policy_matching_rule(matching_rule) {
    let matching_rule_info = {};

    let childNodes = XPath.select('./*', matching_rule);
    for (let child_node of childNodes) {
        let node_name = child_node.nodeName.toLocaleLowerCase();
        let node_value = child_node.textContent;

        if (node_value === '') {
            continue;
        }

        matching_rule_info[node_name] = node_value;
    }

    return matching_rule_info;
}

async function inspect_policy_matching_rules(matching) {
    let matching_rules = XPath.select('./MatchRules', matching);

    let matching_rules_info = [];
    for (let matching_rule of matching_rules) {
        let matching_rule_info = await inspect_policy_matching_rule(matching_rule);
        matching_rules_info.push(matching_rule_info);
    }

    return matching_rules_info;
}

async function inspect_policy_rule_match(policy_map) {

    let match_name = await get_policy_rule_match_name(policy_map);

    let matching = _.find(XPath.select('/datapower-configuration/configuration/Matching', policy_map), (e) => {
        return e.getAttribute('name') == match_name;
    });


    let matching_info = {
        operator: await get_matching_operator(matching),
        rules: await inspect_policy_matching_rules(matching)
    };


    return matching_info;
}


async function get_policy_rule_action_name(style_policy_rule_action) {
    return style_policy_rule_action.textContent;
}

async function get_elem_text(xpath, domObject) {
    let elem = XPath.select(xpath, domObject);
    if (!elem || elem.length === 0) {
        return null;
    }

    return elem[0].textContent;
}

async function get_elem_attr(xpath, attr, domObject) {
    let elem = XPath.select(xpath, domObject);
    if (!elem || elem.length === 0) {
        return null;
    }

    return elem[0].getAttribute(attr);
}

async function get_stylesheet_params(domObj) {
    let stylesheet_params = XPath.select('./StylesheetParameters', domObj);

    let params = [];
    for (let stylesheet_param of stylesheet_params) {
       let name = await get_elem_text('./ParameterName', stylesheet_param);
       let value =  await get_elem_text('./ParameterValue', stylesheet_param);
       params.push({name, value});
    }

    return params;
}

async function add_params_field(action, policy_rule_action) {
    let params = await get_stylesheet_params(policy_rule_action);
    if (params.length === 0) {
        return;
    }

    action.params = params;
}

async function add_ssl_cred_field(action, policy_rule_action) {
    let ssl_client_type = await get_elem_text('./SSLClientConfigType', policy_rule_action);
    let ssl_credential = await get_elem_text('./SSLCred', policy_rule_action);
    let ssl_client_credential =  await get_elem_text('./SSLClientCred', policy_rule_action);

    if (ssl_client_type && ssl_credential) {
        action[`ssl_${ssl_client_type}_profile`] =  ssl_credential;
    } else if (ssl_client_type && ssl_client_credential) {
        action[`ssl_${ssl_client_type}_profile`] =  ssl_client_credential;
    }
}

async function get_rule_action_type_alias(policy_rule_name, policy_rule_action_name) {
    let alias = policy_rule_action_name.replace(new RegExp(`^${policy_rule_name}_`), '');
    alias = alias.replace(new RegExp('_\\d+$'),'');
    return alias;
}

async function add_xform_fields(action, policy_rule_action) {
    let xslt =  await get_elem_text('./Transform', policy_rule_action);
    if (xslt) {
        Object.assign(action, { xslt } );
    }

    let transform_lang = await get_elem_text('./TransformLanguage', policy_rule_action);

    if (transform_lang && !(transform_lang === 'none' || transform_lang === 'default')) {
        Object.assign(action, { transform_lang });
    }
}

async function inspect_antivirus_action(action, policy_rule_action) {
    add_xform_fields(action, policy_rule_action);
    return [action];
}

async function inspect_log_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './LogType', 'log_type');
    await add_child(action, policy_rule_action, './LogLevel', 'log_level');
    await add_child(action, policy_rule_action, './Destination', 'destination');
    await add_child(action, policy_rule_action, './MethodType', 'method');

    return [action];
}

async function inspect_on_error_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './ErrorMode', 'error_mode');
    await add_child(action, policy_rule_action, './Rule', 'rule');

    return [action];
}

async function add_child(action, policy, xpath, name) {
    let value = await get_elem_text(xpath, policy);
    if (value) {
        action[name] = value;
    }
}

async function inspect_extract_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './XPath', 'xpath');
    await add_child(action, policy_rule_action, './Variable', 'var');

    return [action];
}

async function inspect_validate_action(action, policy_rule_action) {
    let xsd = await get_elem_text('./SchemaURL', policy_rule_action);
    let wsdl = await get_elem_text('./WsdlURL', policy_rule_action);
    let json = await get_elem_text('./JSONSchemaURL', policy_rule_action);
    let url_rewrite_policy = await get_elem_text('./Policy', policy_rule_action);
    let dynamic_xsd = await get_elem_text('./DynamicSchema', policy_rule_action);

    if (xsd) {
        action = {...action, xsd};
    } else if (wsdl) {
        action = {...action, wsdl};
    } else if (json) {
        action = {...action, json};
    } else if (url_rewrite_policy) {
        action = {...action, url_rewrite_policy};
    } else if (dynamic_xsd) {
        let clazz = await get_elem_attr('./DynamicSchema', 'class', policy_rule_action);
        action = {...action, dynamic_xsd};
    } else {
        action = {...action, with_schema_attribute: true};
    }

    return [action];
}

async function inspect_xform_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);
    await add_child(action, policy_rule_action, './Policy', 'url_rewrite_policy');

    return [action];
}

async function inspect_xformbin_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    await add_child(action, policy_rule_action, './TxMap', 'itx_map_file');
    await add_child(action, policy_rule_action, './TxMode', 'itx_map_mode');
    await add_child(action, policy_rule_action, './TxTopLevelMap', 'itx_top_level_map');
    await add_child(action, policy_rule_action, './PoTxAuditLoglicy', 'itx_audit_log');
    await add_child(action, policy_rule_action, './Policy', 'url_rewrite_policy');

    return [action];
}

async function inspect_xformpi_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);
    await add_child(action, policy_rule_action, './Policy', 'url_rewrite_policy');

    return [action];
}

async function inspect_xformng_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './InputLanguage', 'input_lang');
    await add_child(action, policy_rule_action, './InputDescriptor', 'input_descriptor');

    let output_lang = await get_elem_text('./OutputLanguage', policy_rule_action);
    if (output_lang && output_lang !== 'default') {
        action = {...action, output_lang};
    }

    let transform_lang = await get_elem_text('./TransformLanguage', policy_rule_action);
    if (transform_lang === 'xquery') {
        await add_child(action, policy_rule_action, './Transform', 'xquery');
    }

    await add_child(action, policy_rule_action, './Policy', 'url_rewrite_policy');

    return [action];
}

async function inspect_encrypt_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    let dynamic_xslt = await get_elem_text('./DynamicStylesheet', policy_rule_action);

    if (dynamic_xslt) {
        let clazz = await get_elem_attr('./DynamicStylesheet', 'class', policy_rule_action);
        action = {...action, dynamic_xslt};
    }

    return [action];
}

async function inspect_decrypt_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    let dynamic_xslt = await get_elem_text('./DynamicStylesheet', policy_rule_action);

    if (dynamic_xslt) {
        let clazz = await get_elem_attr('./DynamicStylesheet', 'class', policy_rule_action);
        action = {...action, dynamic_xslt};
    }

    return [action];
}

async function inspect_sign_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    return [action];
}

async function inspect_verify_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    return [action];
}

async function inspect_filter_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    return [action];
}

async function inspect_aaa_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './AAA', 'policy');

    return [action];
}

async function inspect_jose_sign_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './GatewayScriptLocation', 'script');
    await add_child(action, policy_rule_action, './JOSESerializationType', 'serialization');
    await add_child(action, policy_rule_action, './JWSSignatureObject', 'signature');

    return [action];
}

async function inspect_route_action_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);

    let dynamic_xslt = await get_elem_text('./DynamicStylesheet', policy_rule_action);

    if (dynamic_xslt) {
        let clazz = await get_elem_attr('./DynamicStylesheet', 'class', policy_rule_action);

        action = {...action, dynamic_xslt};
    }

    return [action];
}

async function inspect_route_set_action(action, policy_rule_action) {
    await add_xform_fields(action, policy_rule_action);
    await add_child(action, policy_rule_action, './Destination', 'destination');

    return [action];
}

async function inspect_jose_verify_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './GatewayScriptLocation', 'script');
    await add_child(action, policy_rule_action, './SignatureIdentifier', 'signature_identifier');
    await add_child(action, policy_rule_action, './SingleCertificate', 'single_certificate');
    await add_child(action, policy_rule_action, './SingleSSKey', 'single_sskey');
    await add_child(action, policy_rule_action, './JWSVerifyStripSignature', 'strip_signature');

    return [action];
}

async function inspect_results_output_action(action, policy_rule_action) {
    return [];
}

async function inspect_jose_encrypt_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './GatewayScriptLocation', 'script');
    await add_child(action, policy_rule_action, './JOSESerializationType', 'serialization');
    await add_child(action, policy_rule_action, './JWEEncAlgorithm', 'algorithm');
    await add_child(action, policy_rule_action, './JWEHeaderObject', 'jwe_header');

    return [action];
}

async function inspect_jose_decrypt_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './GatewayScriptLocation', 'script');
    await add_child(action, policy_rule_action, './SingleSSKey', 'sskey');
    await add_child(action, policy_rule_action, './SingleKey', 'single_key');
    await add_child(action, policy_rule_action, './RecipientIdentifier', 'recipient_identifier');
    await add_child(action, policy_rule_action, './JWEDirectKeyObject', 'direct_key');

    return [action];
}

async function inspect_fetch_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './Destination', 'source');
    await add_child(action, policy_rule_action, './MethodRewriteType', 'method');

    return [action];
}

async function inspect_setvar_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './Variable', 'var');
    await add_child(action, policy_rule_action, './Value', 'val');

    return [action];
}

async function inspect_results_action(action, policy_rule_action) {
    //no-op
    return [];
}

async function inspect_gatewayscript_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './GatewayScriptLocation', 'gatewayscript');
    await add_child(action, policy_rule_action, './ActionDebug', 'debug');

    return [action];
}

async function inspect_conditional_action(action, policy_rule_action) {
    let conditions = XPath.select('./Condition', policy_rule_action);

    let sub_actions = [];
    for (let condition of conditions) {
       let condition_action = conditions = XPath.select('./ConditionAction', condition);
       let condition_action_name = condition_action[0].textContent;
       let actions = await inspect_policy_rule_action(policy_rule_action.ownerDocument, condition_action_name, "");
       if (!actions || actions.length === 0) {
           continue;
       }
       sub_actions = sub_actions.concat(actions);
    }

    return sub_actions;
}

async function inspect_slm_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './SLMPolicy', 'slm');

    return [action];
}

async function inspect_call_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './Rule', 'rule');

    return [action];
}

async function inspect_method_rewrite_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './MethodRewriteType', 'method');

    return [action];
}

async function inspect_convert_http_action(action, policy_rule_action) {
    await add_child(action, policy_rule_action, './InputConversion', 'input-conversion');

    return [action];
}

function action2fn(action_type) {
    action_type = action_type.replace(new RegExp("-", 'g'), "_");

    try {
        return eval(`(inspect_${action_type}_action)`);
    } catch(ex) {
        return null;
    }
}

async function inspect_policy_rule_action(xdoc, policy_rule_action_name, policy_rule_name) {
    let policy_rule_action = _.find(XPath.select('/datapower-configuration/configuration/StylePolicyAction', xdoc), (e) => {
        return e.getAttribute('name') == policy_rule_action_name;
    });

    let action_type = (await get_rule_action_type_alias(policy_rule_name, policy_rule_action_name)).toLocaleString();

    let action_subtype = await get_elem_text('./Type', policy_rule_action) || '';
    action_subtype = action_subtype.toLowerCase();

    let action = {
        name: policy_rule_action_name
    };

    let func = action2fn(action_type);

    if (!func && action_type !== action_subtype) {
        //if we fail to look it up by the main type, try the subtype
        action_type = action_subtype;
        func = action2fn(action_type);
    }

    let actions = [];
    if (typeof func  === 'function')  {
        action.type = action_type;
        actions = await func.call(this, action, policy_rule_action);
    } else {
        logger.warn(`Unknown policy rule action of type: ${action_type}`);
    }

    if (!actions || actions.length === 0 ) {
        return [];
    }

    let results = [];
    for (let sub_action of actions) {
        await add_ssl_cred_field(sub_action, policy_rule_action);
        await add_params_field(sub_action, policy_rule_action);

        let result = {};

        if (sub_action.type) {
            result[sub_action.type] = sub_action;
            delete sub_action.type;
        } else {
            result = sub_action;
        }

        results.push(result);
    }

    return results;
}

async function inspect_policy_rule_action_wsp(xdoc, policy_rule_action_name, policy_rule_name) {
    let policy_rule_action = _.find(XPath.select('/datapower-configuration/configuration/StylePolicyAction', xdoc), (e) => {
        return e.getAttribute('name') == policy_rule_action_name;
    });

    let action_type = (await get_rule_action_type_alias(policy_rule_name, policy_rule_action_name)).toLocaleString();

    let action_subtype = await get_elem_text('./Type', policy_rule_action) || '';
    action_subtype = action_subtype.toLowerCase();

    let action = {
        name: policy_rule_action_name
    };

    let func = action2fn(action_type);

    if (!func && action_type !== action_subtype) {
        //if we fail to look it up by the main type, try the subtype
        action_type = action_subtype;
        func = action2fn(action_type);
    }

    let actions = [];
    if (typeof func  === 'function')  {
        action.type = action_type;
        actions = await func.call(this, action, policy_rule_action);
    } else {
        logger.warn(`Unknown policy rule action of type: ${action_type}`);
    }

    if (!actions || actions.length === 0 ) {
        return [];
    }

    let results = [];
    for (let sub_action of actions) {
        await add_ssl_cred_field(sub_action, policy_rule_action);
        await add_params_field(sub_action, policy_rule_action);

        let result = {};

        if (sub_action.type) {
            result[sub_action.type] = sub_action;
            delete sub_action.type;
        } else {
            result = sub_action;
        }

        results.push(result);
    }

    return results;
}

async function inspect_policy_rule_actions(style_policy_rule) {
    let policy_rule_name = style_policy_rule.getAttribute('name');
    let policy_rule_actions_info = [];

    let style_policy_rule_actions = XPath.select('./Actions', style_policy_rule);

    for (let action of style_policy_rule_actions) {

        let policy_rule_action_name = await get_policy_rule_action_name(action);

        let policy_actions = await inspect_policy_rule_action(style_policy_rule.ownerDocument, policy_rule_action_name, policy_rule_name);
        if (!policy_actions || policy_actions.length === 0 ) {
            continue;
        }

        for (let policy_action of policy_actions) {
            policy_rule_actions_info.push(policy_action);
        }
    }

    return policy_rule_actions_info;
}

async function inspect_policy_rule_actions_wsp(style_policy_rule) {
    let policy_rule_name = style_policy_rule.getAttribute('name');
    let policy_rule_actions_info = [];

    let style_policy_rule_actions = XPath.select('./Actions', style_policy_rule);

    for (let action of style_policy_rule_actions) {

        let policy_rule_action_name = await get_policy_rule_action_name(action);

        let policy_actions = await inspect_policy_rule_action_wsp(style_policy_rule.ownerDocument, policy_rule_action_name, policy_rule_name);
        if (!policy_actions || policy_actions.length === 0 ) {
            continue;
        }

        for (let policy_action of policy_actions) {
            policy_rule_actions_info.push(policy_action);
        }
    }

    return policy_rule_actions_info;
}


async function inspect_mpg_style_policy_rule(policy_map, policy_rule_name) {
    let policy_rule_info = {
        direction: null,
        condition: {},
        actions: {}
    };

    let condition_name =  await get_policy_rule_match_name(policy_map);
    let condition_info = await inspect_policy_rule_match(policy_map);

    let style_policy_rule = _.find(XPath.select('/datapower-configuration/configuration/StylePolicyRule', policy_map), (e) => {
        return e.getAttribute('name') == policy_rule_name;
    });

    let direction = await get_elem_text('./Direction', style_policy_rule);

    policy_rule_info.direction = direction;
    policy_rule_info.condition[condition_name] = condition_info;
    policy_rule_info.actions = await inspect_policy_rule_actions(style_policy_rule);

    return policy_rule_info;
}

async function inspect_wsp_style_policy_rule(policy_map, policy_rule_name) {
    let policy_rule_info = {
        direction: null,
        condition: {},
        actions: {}
    };

    let condition_name =  await get_policy_rule_match_name(policy_map);
    let condition_info = await inspect_policy_rule_match(policy_map);

    let style_policy_rule = _.find(XPath.select('/datapower-configuration/configuration/WSStylePolicyRule', policy_map), (e) => {
        return e.getAttribute('name') == policy_rule_name;
    });

    let direction = await get_elem_text('./Direction', style_policy_rule);

    policy_rule_info.direction = direction;
    policy_rule_info.condition[condition_name] = condition_info;
    policy_rule_info.actions = await inspect_policy_rule_actions_wsp(style_policy_rule);

    return policy_rule_info;
}

async function get_policy_rule_name(policy_map) {
    let rule_name = XPath.select('./Rule', policy_map)[0].textContent;
    return rule_name;
}

async function inspect_mpg_style_policy_rules(style_policy) {
    let policy_maps = XPath.select('./PolicyMaps', style_policy);

    let policy_rules_info = {};
    for (let policy_map of policy_maps) {

        let policy_rule_name = await get_policy_rule_name(policy_map);
        let policy_rule_info = await inspect_mpg_style_policy_rule(policy_map, policy_rule_name);
        if (!policy_rule_info.actions || policy_rule_info.actions.length === 0) {
            continue;
        }
        policy_rules_info[policy_rule_name] = policy_rule_info;
    }

    return policy_rules_info;
}

async function inspect_wsp_style_policy_rules(style_policy) {
    let policy_maps = XPath.select('./PolicyMaps', style_policy);

    let policy_rules_info = {};
    for (let policy_map of policy_maps) {

        let policy_rule_name = await get_policy_rule_name(policy_map);
        let policy_rule_info = await inspect_wsp_style_policy_rule(policy_map, policy_rule_name);
        if (!policy_rule_info.actions || policy_rule_info.actions.length === 0) {
            continue;
        }
        policy_rules_info[policy_rule_name] = policy_rule_info;
    }

    return policy_rules_info;
}

async function inspect_mpg_style_policy(mpg) {
    let style_policies = XPath.select('./StylePolicy', mpg);

    if (!style_policies || style_policies.length == 0) {
        return {};
    }

    let policy_name =  style_policies[0].textContent;

    let style_policy = _.find(XPath.select('/datapower-configuration/configuration/StylePolicy', mpg), (e) => {
        return e.getAttribute('name') == policy_name
    });

    let policy_info = {};
    policy_info[policy_name] =  {
        rules: await inspect_mpg_style_policy_rules(style_policy)
    };

    return policy_info;
}

async function inspect_wsp_style_policy(wsp) {
    let style_policies = XPath.select('./StylePolicy', wsp);

    if (!style_policies || style_policies.length == 0) {
        return {};
    }

    let policy_name =  style_policies[0].textContent;

    let style_policy = _.find(XPath.select('/datapower-configuration/configuration/WSStylePolicy', wsp), (e) => {
        return e.getAttribute('name') == policy_name
    });

    let policy_info = {};
    policy_info[policy_name] =  {
        rules: await inspect_wsp_style_policy_rules(style_policy)
    };

    return policy_info;
}


async function inspect_mpg(mpg) {
    let type = XPath.select('./Type', mpg)[0].textContent;

    let policy = await inspect_mpg_style_policy(mpg);

    return {
        type,
        policy
    };
}

async function inspect_wsp(wsp) {
    let type = XPath.select('./Type', wsp)[0].textContent;

    let policies = await inspect_wsp_style_policy(wsp);

    return {
        type,
        policies
    };
}

async function inspect_domain(domain_name, domain_zip_buffer) {
    let unzipped = await decompress(domain_zip_buffer);
    let files = _.groupBy(unzipped, 'path');
    let top_export = new DOMParser().parseFromString(files['export.xml'][0].data.toString('utf8'));
    let mpgs = XPath.select('/datapower-configuration/configuration/MultiProtocolGateway', top_export);
    let wsps = XPath.select('/datapower-configuration/configuration/WSGateway', top_export);

    let domain_info = { mpgs: {},wsps: {}};

    for (let mpg of mpgs) {
        let mpg_name = mpg.getAttribute('name');
        let mpg_info = await inspect_mpg(mpg);
        domain_info.mpgs[mpg_name] = mpg_info;
    }
   if (wsps.length > 0)
   {
    for (let wsp of wsps) {
        let wsp_name = wsp.getAttribute('name');
        let wsp_info = await inspect_wsp(wsp);
        domain_info.wsps[wsp_name] = wsp_info;
    }
    
}
return domain_info;
}

module.exports = async function inspect_backup(backup_file) {
    try {
        await fs_access_async(backup_file, fs.constants.F_OK | fs.constants.R_OK);
    } catch(ex) {
        throw new ProcessError(`Unable to access ${backup_file}. Error: ${ex.message}`);
    }

    let unzipped = await decompress(backup_file);
    let files = _.groupBy(unzipped,  'path');

    let top_export = new DOMParser().parseFromString(files['export.xml'][0].data.toString('utf8'));
    let domains = XPath.select('/datapower-configuration/domains/domain', top_export);

    let backup_info = {domains: {}};

    for (let domain of domains) {
        let domain_name = domain.getAttribute('name');
        let domain_zip = `${domain_name}.zip`;
        if (!files[domain_zip]) {
            logger.warn(`Could not find ${domain_zip} inside ${backup_file}, skipping this domain.`);
            continue;
        }

        let domain_info = await inspect_domain(domain_name, files[domain_zip][0].data);
        backup_info.domains[domain_name] = domain_info;
    }


    logger.info(YAML.stringify(backup_info));


    return backup_info;
};