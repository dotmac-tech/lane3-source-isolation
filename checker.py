"""Immutable-workflow policy: candidate trees are data, never executable code."""
import hashlib
import json
import re

MAX_ENTRIES = 20000
MAX_WORKFLOW_BYTES = 65536
SHA = re.compile(r'[0-9a-f]{40}')

class Refused(ValueError):
    """No success may be published from an incomplete or changed source tree."""

def policy_revision(policy):
    return hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def validate_policy(policy):
    if set(policy) != {'repository','repository_id','owner_id','default_branch','baseline','workflows'}:
        raise Refused('policy shape')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',policy['repository']):raise Refused('repository')
    if policy['repository_id']<=0 or policy['owner_id']<=0 or policy['default_branch']!='main':raise Refused('identity')
    if not SHA.fullmatch(policy['baseline']):raise Refused('baseline')
    workflows=policy['workflows']
    if not workflows or any(not p.startswith('.github/workflows/') or not p.endswith(('.yml','.yaml')) or not SHA.fullmatch(s) for p,s in workflows.items()):raise Refused('workflow policy')

def evaluate_repository(repository,policy):
    validate_policy(policy)
    if (repository.get('id')!=policy['repository_id'] or repository.get('full_name')!=policy['repository'] or repository.get('owner',{}).get('id')!=policy['owner_id'] or repository.get('default_branch')!=policy['default_branch'] or repository.get('archived') or repository.get('disabled')):
        raise Refused('repository identity changed')

def evaluate_tree(tree,policy):
    validate_policy(policy)
    entries=tree.get('tree')
    if tree.get('truncated') is not False or not isinstance(entries,list) or len(entries)>MAX_ENTRIES:raise Refused('incomplete tree')
    found={};seen=set()
    for entry in entries:
        path=entry.get('path')
        if not isinstance(path,str) or path in seen:raise Refused('invalid path')
        seen.add(path)
        if path in ('.github','.github/workflows'):
            if entry.get('type')!='tree' or entry.get('mode')!='040000':raise Refused('workflow directory indirection')
        if path.startswith('.github/workflows/'):
            if path not in policy['workflows']:raise Refused('unapproved workflow path')
            if entry.get('type')!='blob' or entry.get('mode')!='100644':raise Refused('workflow not regular data')
            if not isinstance(entry.get('size'),int) or not 0<entry['size']<=MAX_WORKFLOW_BYTES:raise Refused('workflow bounds')
            if entry.get('sha')!=policy['workflows'][path]:raise Refused('workflow content changed')
            found[path]=entry['sha']
    if found!=policy['workflows']:raise Refused('missing workflows')
    return hashlib.sha256(json.dumps(found,sort_keys=True).encode()).hexdigest()
