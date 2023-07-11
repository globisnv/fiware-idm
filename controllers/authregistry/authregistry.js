const debug = require('debug')('idm:authregistry_controller');
const Ajv = require('ajv');
const ajv = new Ajv();
const fs = require('fs');
const path = require('path');
const moment = require('moment');
const oauth2_server = require('oauth2-server'); //eslint-disable-line snakecase/snakecase
const uuid = require('uuid');

const config_service = require('../../lib/configService.js');
const models = require('../../models/models');
const utils = require('../../controllers/extparticipant/utils');
const Request = oauth2_server.Request;
const Response = oauth2_server.Response;

const config = config_service.get_config();
const delegation_evidence_schema = JSON.parse(fs.readFileSync(path.join(__dirname, 'delegationEvidenceSchema.json')));
const validate_delegation_evicence = ajv.compile(delegation_evidence_schema);
const delegation_request_schema = JSON.parse(fs.readFileSync(path.join(__dirname, 'delegationRequestSchema.json')));
const validate_delegation_request = ajv.compile(delegation_request_schema);

// Create Oauth Server model
const oauth2 = new oauth2_server({ //eslint-disable-line new-cap
  model: require('../../models/model_oauth_server.js'),
  debug: true
});


const authenticate_bearer = async function authenticate_bearer(req) {
  const options = {};

  const request = new Request({
    headers: { authorization: req.headers.authorization },
    method: "POST",
    query: {}
  });

  const response = new Response();

  return await oauth2.authenticate(request, response, options);
}

const get_delegation_evidence = async function get_delegation_evidence(subject) {
  const evidence = await models.delegation_evidence.findOne({
    where: {
      policy_issuer: config.pr.client_id,
      access_subject: subject
    }
  });
  return evidence == null ? null : evidence.policy;
};

const arrays_are_equal = function arrays_are_equal(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  a.sort();
  b.sort();

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

const _retrieve_policy = async function _retrieve_policy(req, res) {
    const token_info = await authenticate_bearer(req);

    debug(`Checking whether user is an admin`);
    const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
    if (!token_info.user.admin && token_info.user.email !== authorized_email) {
      res.status(403).json({
        error: "You are not authorized to retrieve policies",
        details: validate_delegation_evicence.errors
      });
      return true;
    }

    if (!req.query.accessSubject) {
        res.status(400).json({
          error: "Missing 'accessSubject' query parameter"
        });
        return true;
    }

    debug('Requesting available delegation evidences');

    const evidence = await get_delegation_evidence(req.query.accessSubject);
    if (evidence == null) {
      res.status(404).json({
        error: "Didn't find any policy with access subject equal to " + req.query.accessSubject
      });
      return true;
    }

    return res.status(200).json({evidence});
}

const simplify_delegation = function simplify_delegation(delegation_body) {
  debug(`Starting delegation merge`);
  delegation = delegation_body.delegationEvidence || delegation_body.delegationRequest;

  // Merge policy sets
  debug(`Processing policy sets`);
  delegation.policySets = delegation.policySets.reduce((acc, curr, idx) => {
    debug(`  Processing policy set ${idx}`);
    let matching_set_idx;
    
    if (curr.maxDelegationDepth != null) {
      matching_set_idx = acc.findIndex(set => set.maxDelegationDepth == curr.maxDelegationDepth 
        && arrays_are_equal(set.target.environment.licenses, curr.target.environment.licenses));
    }
    else {
      matching_set_idx = acc.length - 1;
    }
      
    if (matching_set_idx != -1) {
      debug(`    Merging policy set ${idx} with policy set ${matching_set_idx}`);
      acc[matching_set_idx].policies.push(...curr.policies);
    }
    else {
      acc.push(curr);
    }

    return acc;
  }, []);

  // Merge policies inside policy set
  debug(`Processing policies`);
  delegation.policySets.every((set, set_idx) => {
    set.policies = set.policies.reduce((acc, curr, idx) => {
      debug(`  Processing policy ${idx} within policy set ${set_idx}`);
      const curr_resource = curr.target.resource;
      const matching_policy_idx = acc.findIndex(pol => {
        const pol_resource = pol.target.resource;
        return pol_resource.type == curr_resource.type
          && arrays_are_equal(pol_resource.attributes, curr_resource.attributes)
          && arrays_are_equal(pol.target.actions, curr.target.actions);
      });

      if (matching_policy_idx != -1) {
        debug(`    Merging policy ${idx} with policy ${matching_policy_idx}`);
        acc[matching_policy_idx].target.resource.identifiers.push(...curr.target.resource.identifiers);
        acc[matching_policy_idx].rules.push(...curr.rules.filter(r => r.effect != "Permit")); // Following official iSHARE spec that notes that only the first rule can be a permit
      }
      else {
        acc.push(curr);
      }

      return acc;
    }, []);
  });

  // merge rules inside policy
  debug(`Processing policy rules`);
  delegation.policySets.every((set, set_idx) => {
    set.policies.every((pol, pol_idx) => {
      pol.rules.reduce((acc, curr, idx) => {
        debug(`  Processing rule ${idx} from policy ${pol_idx} within policy set ${set_idx}`);
        if (curr.target) {
          const curr_resource = curr.target.resource;
          const matching_rule_idx = acc.findIndex(rule => {
            const rule_resource = rule.target.resource;
            return rule_resource.type == curr_resource.type
              && arrays_are_equal(rule_resource.attributes, curr_resource.attributes)
              && arrays_are_equal(rule.target.actions, curr.target.actions);
          });
    
          if (matching_rule_idx != -1) {
            debug(`    Merging policy rule ${idx} with policy rule ${matching_rule_idx}`);
            acc[matching_rule_idx].target.resource.identifiers.push(...curr.target.resource.identifiers);
          }
          else {
            acc.push(curr);
          }
        }

        return acc;
      }, []);
    });
  });

  return delegation_body;
}

const _simplify_policy = async function _simplify_policy(req, res) {
  await authenticate_bearer(req);

  debug(`Validating delegation`);
  if (!validate_delegation_request(req.body) && !validate_delegation_evicence(req.body)) {
    debug(validate_delegation_request.errors);
    res.status(400).json({
      error: "Invalid delegation evidence or mask",
      details: validate_delegation_request.errors
    });
    return true;
  }

  const simplified_delegation = simplify_delegation(req.body);
  return res.status(200).json(simplified_delegation);
};

const _delete_policy = async function _delete_policy(req, res) {
  const token_info = await authenticate_bearer(req);

  debug(`Checking whether user is an admin`);
  const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
  if (!token_info.user.admin && token_info.user.email !== authorized_email) {
    res.status(403).json({
      error: "You are not authorized to delete policies",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  if (!req.query.accessSubject) {
      res.status(400).json({
        error: "Missing 'accessSubject' query parameter"
      });
      return true;
  }

  // Check whether one or more 'identifier' query parameters are given
  // If not present, delete the full access policy
  // If present, only delete the parts of the access policy that contain the given identifiers
  if (!req.query.identifier) {
    debug(`Deleting full access policy for ${req.query.accessSubject}`);
    await models.delegation_evidence.destroy({
      where: {
        policy_issuer: config.pr.client_id,
        access_subject: req.query.accessSubject
      }
    });
  } else {
    debug(`Retrieving existing access policy information for ${req.query.accessSubject}`);
    let evidence_current = await get_delegation_evidence(req.query.accessSubject);

    // Skip delete if no access policy is stored for the given subject
    if (evidence_current == null) {
      debug(`No access policy found with given subject, skipping delete`);
      return res.status(200).json({});
    }

    let ids_to_delete = req.query.identifier;
    if (!Array.isArray(ids_to_delete)) {
      ids_to_delete = [ids_to_delete];
    }

    // Loop over all policy sets
    debug(`Deleting access policy information for ${req.query.accessSubject} on identifiers ${ids_to_delete}`);
    for (let set_idx = 0; set_idx < evidence_current.policySets.length; set_idx++) {
      debug(`Processing policy set ${set_idx}`);

      // Loop over all policies in the current policy set
      for (let policy_idx = 0; policy_idx < evidence_current.policySets[set_idx].policies.length; policy_idx++) {
        debug(`  Processing policy ${policy_idx} from the current policy set`);

        // Remove to be deleted identifiers from the policy target resource
        debug(`  Filtering resource identifiers within the current policy`);
        const policy = evidence_current.policySets[set_idx].policies[policy_idx];
        policy.target.resource.identifiers = policy.target.resource.identifiers.filter(id => !ids_to_delete.includes(id));

        // Loop over all rules in the current policy 
        for (let rule_idx = 0; rule_idx < policy.rules.length; rule_idx++) {
          debug(`    Processing rule ${rule_idx} from the current policy`);
          const rule = policy.rules[rule_idx];

          // Skip base rule that only has the 'effect' attribute
          if (rule.target != null) {

            // Remove to be deleted identifiers from the rule target resource
            debug(`    Filtering resource identifiers within the current rule`);
            rule.target.resource.identifiers = rule.target.resource.identifiers.filter(id => !ids_to_delete.includes(id));

            // Remove rule if it has no identifiers left
            if (rule.target.resource.identifiers.length == 0) {
              debug(`    Deleting current rule because it is empty`);
              policy.rules.splice(rule_idx, 1);
              rule_idx--;
            }
          }
        }

        // Remove policy if it has no identifiers and rules left
        if (policy.target.resource.identifiers.length == 0 && policy.rules.length == 1) {
          debug(`  Deleting current policy because it is empty`);
          evidence_current.policySets[set_idx].policies.splice(policy_idx, 1);
          policy_idx--;
        }
      }

      // Remove policy set if it has no policies left
      if (evidence_current.policySets[set_idx].policies.length == 0) {
        debug(`Deleting current policy set because it is empty`);
        evidence_current.policySets.splice(set_idx, 1);
        set_idx--;
      }
    }

    // If there are no policy sets left, delete the whole policy
    // If there are, replace the existing access policy 
    if (evidence_current.policySets.length == 0) {
      debug(`Deleting full access policy for ${req.query.accessSubject}`);
      await models.delegation_evidence.destroy({
        where: {
          policy_issuer: config.pr.client_id,
          access_subject: req.query.accessSubject
        }
      });
    }
    else {
      evidence_current = simplify_delegation(evidence_current);
      debug(`Replacing access policy for ${req.query.accessSubject}`);
      models.delegation_evidence.upsert({
        policy_issuer: evidence_current.policyIssuer,
        access_subject: evidence_current.target.accessSubject,
        policy: evidence_current
      });
    }
  }

  return res.status(200).json({});
}

const _upsert_policy = async function _upsert_policy(req, res) {
  const token_info = await authenticate_bearer(req);

  debug(`Checking whether user is an admin`);
  const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
  if (!token_info.user.admin && token_info.user.email !== authorized_email) {
    res.status(403).json({
      error: "You are not authorized to update policies",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  debug(`Validating delegation evidence structure`);
  if (!validate_delegation_evicence(req.body)) {
    debug(validate_delegation_evicence.errors);
    res.status(400).json({
      error: "Invalid policy document",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  const evidence = req.body.delegationEvidence;

  // Check policyIssuer
  if (evidence.policyIssuer !== config.pr.client_id) {
    res.status(422).json({
      error: `Invalid value for policyIssuer: ${evidence.policyIssuer}`
    });
    return true;
  }

  models.delegation_evidence.upsert({
    policy_issuer: evidence.policyIssuer,
    access_subject: evidence.target.accessSubject,
    policy: evidence
  });

  return res.status(200).json({});
};

const _upsert_merge_policy = async function _upsert_merge_policy(req, res) {
  const token_info = await authenticate_bearer(req);

  debug(`Checking whether user is an admin`);
  const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
  if (!token_info.user.admin && token_info.user.email !== authorized_email) {
    res.status(403).json({
      error: "You are not authorized to update policies",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  debug(`Validating delegation evidence structure`);
  if (!validate_delegation_evicence(req.body)) {
    debug(validate_delegation_evicence.errors);
    res.status(400).json({
      error: "Invalid policy document",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  const evidence = req.body.delegationEvidence;

  // Check policyIssuer
  if (evidence.policyIssuer !== config.pr.client_id) {
    res.status(422).json({
      error: `Invalid value for policyIssuer: ${evidence.policyIssuer}`
    });
    return true;
  }

  // METHOD:
  // start with stored policy def:
  // loop over stored policy sets
  //   Find all given policy sets in the given policy def with same licenses and delegation depth 
  //   Delete those policy sets from the given policy object
  //   Loop over the policies in the current stored policy set
  //     Find all given policies in the given policy def with same 
  // Add the other policy set objects that are left to the stored policy

  let evidence_current = await get_delegation_evidence(evidence.target.accessSubject);
  if (evidence_current != null)
  {
    // TODO multiple policy sets
    // TODO rule exceptions

    // Make a list containing all new types (type + id combination)
    let p_types = [];
    for (let p_idx = 0; p_idx < evidence.policySets[0].policies.length; p_idx++) {
      const p_target = evidence.policySets[0].policies[p_idx].target;
      const p_resource = p_target.resource;
      const p_actions = p_target.actions;

      if (!p_types.hasOwnProperty(p_resource.type)) {
        p_types[p_resource.type] = [];
      }

      // Collect type + id combo's per actions and attributes, to be used later
      const p_obj_prev_idx = p_types[p_resource.type].findIndex(obj => arrays_are_equal(obj.actions, p_actions) && arrays_are_equal(obj.attrs, p_resource.attributes));
      if (p_obj_prev_idx != -1) {
        p_types[p_resource.type][p_obj_prev_idx].idx.push(p_idx);
        p_types[p_resource.type][p_obj_prev_idx].ids.push(...p_resource.identifiers);
      } else {
        let p_obj = {idx: [p_idx], ids: p_resource.identifiers, selected: new Array(p_resource.identifiers.length).fill(false), actions: p_actions, attrs: p_resource.attributes};
        p_types[p_resource.type].push(p_obj);
      }
    }

    // Remove these types from the currently stored policy definition
    for (let p_current_idx = 0; p_current_idx < evidence_current.policySets[0].policies.length; p_current_idx++) {
      const p_current_policy = evidence_current.policySets[0].policies[p_current_idx];
      const p_current_resource = p_current_policy.target.resource;
      const p_current_actions = p_current_policy.target.actions;
      
      // Policy has the same type as one of the new policies
      if (p_types.hasOwnProperty(p_current_resource.type)) {
        for (let type_idx = 0; type_idx < p_types[p_current_resource.type].length; type_idx++) {

          // Get currently looped new policy object
          const p_obj = p_types[p_current_resource.type][type_idx];

          // Check whether the currently looped new policy object has the same actions as the currently looped stored policy object.
          // If this is the case, it means that the new identifiers in the policy object can be safely added to the identifiers linked to the stored policy object.
          // If this is not the case, it means that new identifiers must not be present in the identifiers linked to the stored policy object.
          if (arrays_are_equal(p_obj.actions, p_current_actions) && arrays_are_equal(p_obj.attrs, p_current_resource.attributes) && p_current_policy.rules.length == 1) {
            for (let p_ids_idx = 0; p_ids_idx < p_obj.ids.length; p_ids_idx++) {
              const p_id = p_obj.ids[p_ids_idx];
              p_obj.selected[p_ids_idx] = true;
              if (!p_current_resource.identifiers.includes(p_id)) {
                p_current_resource.identifiers.push(p_id);
              }
            }
          } else {
            for (let p_current_ids_idx = 0; p_current_ids_idx < p_current_resource.identifiers.length; p_current_ids_idx++) {
              if (p_obj.ids.includes(p_current_resource.identifiers[p_current_ids_idx])) {
                p_current_resource.identifiers.splice(p_current_ids_idx, 1);
                p_current_ids_idx--;
              }
            }
          }

          // Remove policy if empty
          if (p_current_resource.identifiers.length == 0) {
            evidence_current.policySets[0].policies.splice(p_current_idx, 1);
            p_current_idx--;
            break;
          }
        }
      }
    }

    // Add the new policies to the policy definition
    // TODO exceptions to the rule
    for (let type in p_types) {
      if (p_types.hasOwnProperty(type)) {
        for (let t_idx = 0; t_idx < p_types[type].length; t_idx++) {
          let p = null;
          for (let p_id_idx = 0; p_id_idx < p_types[type][t_idx].ids.length; p_id_idx++) {
            if (!p_types[type][t_idx].selected[p_id_idx]) {
              if (!p) {
                const policy_idx = p_types[type][t_idx].idx[p_id_idx];
                p = evidence.policySets[0].policies[policy_idx];
              } else {
                const p_id = p_types[type][t_idx].ids[p_id_idx];
                if (!p.target.resource.identifiers.includes(p_id)) {
                  p.target.resource.identifiers.push(p_id);
                }
              }
            }
          }

          if (p) {
            evidence_current.policySets[0].policies.push(p);
          }
        }
      }
   }
  } else {
    evidence_current = evidence;
  }

  models.delegation_evidence.upsert({
    policy_issuer: evidence_current.policyIssuer,
    access_subject: evidence_current.target.accessSubject,
    policy: evidence_current
  });

  return res.status(200).json({});
};

const is_matching_policy = function is_matching_policy(policy_mask, policy) {
  // Check resource type
  if (policy.target.resource.type !== policy_mask.target.resource.type) {
    return false;
  }

  // Check provider
  if (policy.target.environment != null) {
    if (policy_mask.target.environment == null) {
      return false;
    }

    const service_providers_mask = policy_mask.target.environment.serviceProviders;
    const service_providers = policy.target.environment.serviceProviders;
    const all_mask_sp = service_providers_mask.every(sp => service_providers.has(sp));
    if (!all_mask_sp) {
      return false;
    }
  }

  const resource = policy.target.resource;

  // Check identifiers
  const id_match = policy_mask.target.resource.identifiers.every(
    mid => {return resource.identifiers.length === 1 && resource.identifiers.includes("*") || resource.identifiers.includes(mid);}
  );
  if (!id_match) {
    return false;
  }

  // Check attributes
  const attributes_match = policy_mask.target.resource.attributes.every(
    aid => {return resource.attributes.length === 1 && resource.attributes.includes("*") || resource.attributes.includes(aid);}
  );
  if (!attributes_match) {
    return false;
  }

  // Check actions
  return policy_mask.target.actions != null &&
         policy_mask.target.actions.length > 0 &&
         policy_mask.target.actions.every(
           mact => {return policy.target.actions.length === 1 && policy.target.actions.includes("*") || policy.target.actions.includes(mact);}
         );
};

const is_denying_permission = function is_denying_permission(policy_mask, policy) {
  return policy.rules.reverse().some(rule => rule.effect === "Deny" &&
      rule.target.resource.type === policy_mask.target.resource.type &&
      (rule.target.resource.identifiers.includes("*") || policy_mask.target.resource.identifiers.some(i => rule.target.resource.identifiers.includes(i))) &&
      (rule.target.resource.attributes.includes("*") || policy_mask.target.resource.attributes.some(a => rule.target.resource.attributes.includes(a))) &&
      (rule.target.actions.length === 0 || rule.target.actions.includes("*") || policy_mask.target.actions.some(a => rule.target.actions.includes(a)))
  );
};

const _query_evidences = async function _query_evidences(req, res) {
  const token_info = await authenticate_bearer(req);

  debug(`Requesting delegation evidences affecing user ${token_info.user.username} (id: ${token_info.user.id})`);

  debug('Validating delegation mask structure');

  if (!validate_delegation_request(req.body)) {
    debug(validate_delegation_request.errors);
    res.status(400).json({
      error: "Invalid mask document",
      details: validate_delegation_request.errors
    });
    return true;
  }
  const mask = req.body.delegationRequest;

  debug('Requesting available delegation evidences');

  const evidence = await get_delegation_evidence(mask.target.accessSubject);
  if (evidence == null) {
    res.status(404).end();
    return true;
  }

  debug('Filtering delegation evidence using the provided mask');

  const new_policy_sets = mask.policySets.flatMap((policy_set_mask, i) => {

    debug(`Processing policy set ${i} from the providen mask`);

    return evidence.policySets.map((policy_set, j) => {
      debug(`  Processing policy set ${j} from the available delegation evidence`);

      const response_policy_set = {
        maxDelegationDepth: policy_set.maxDelegationDepth, //eslint-disable-line snakecase/snakecase
        target: policy_set.target
      };

      response_policy_set.policies = policy_set_mask.policies.map((policy_mask, z) => {
        debug(`    Processing policy ${z} from the current policy set`);
        const matching_policies = policy_set.policies.filter((policy) => is_matching_policy(policy_mask, policy));
        return {
          target: policy_mask.target,
          rules: [{
            effect: (matching_policies.length === 0 || matching_policies.some(p => is_denying_permission(policy_mask, p))) ? "Deny": "Permit"
          }]
        };
      });

      return response_policy_set;
    });
  });
  evidence.policySets = new_policy_sets;

  const now = moment();
  const iat = now.unix();
  const exp = now.add(30, 'seconds').unix();
  const delegation_token = await utils.create_jwt({
    iss: config.pr.client_id,
    sub: mask.target.accessSubject,
    jti: uuid.v4(),
    iat,
    exp,
    aud: token_info.user.id,
    delegationEvidence: evidence  // eslint-disable-line snakecase/snakecase
  });

  debug("Delegation evidence processed");
  res.status(200).json({delegation_token});

  return false;
};

exports.oauth2 = oauth2;
exports.get_delegation_evidence = get_delegation_evidence;
exports.arrays_are_equal = arrays_are_equal;

exports.upsert_policy = function upsert_policy(req, res, next) {
  debug(' --> upsert policy');
  _upsert_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.upsert_merge_policy = function upsert_merge_policy(req, res, next) {
  debug(' --> upsert merge policy');
  _upsert_merge_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.delete_policy = function delete_policy(req, res, next) {
  debug(' --> delete policy');
  _delete_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.retrieve_policy = function retrieve_policy(req, res, next) {
  debug(' --> retrieve policy');
  _retrieve_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.query_evidences = function query_evidences(req, res, next) {
  debug(' --> delegate');
  _query_evidences(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.simplify_policy = function simplify_policy(req, res, next) {
  debug(' --> simplify');
  _simplify_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};