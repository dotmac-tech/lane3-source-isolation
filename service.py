"""Outbound-only GitHub App polling worker. No candidate checkout or shell."""
import argparse
import base64
import json
import os
import resource
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from checker import Refused, SHA, evaluate_repository, evaluate_tree, policy_revision, validate_policy

CONTEXT='lane3-source-isolation'
MAX_RESPONSE=8*1024*1024
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise Refused('API redirect')

class GitHub:
    def __init__(self,token):self.token=token;self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def call(self,path,method='GET',payload=None):
        if not path.startswith('/') or '..' in path:raise Refused('API path')
        data=None if payload is None else json.dumps(payload).encode()
        request=urllib.request.Request('https://api.github.com'+path,data=data,method=method,headers={'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json','User-Agent':'dotmac-lane3-source-isolation'})
        with self.opener.open(request,timeout=20) as response:
            body=response.read(MAX_RESPONSE+1)
            if len(body)>MAX_RESPONSE:raise Refused('response bounds')
            return json.loads(body) if body else {}

def app_jwt(app_id,key_path):
    def encode(value):return base64.urlsafe_b64encode(json.dumps(value,separators=(',',':')).encode()).rstrip(b'=')
    now=int(time.time());data=encode({'alg':'RS256','typ':'JWT'})+b'.'+encode({'iat':now-60,'exp':now+300,'iss':str(app_id)})
    result=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(key_path)],input=data,capture_output=True,check=True,timeout=10)
    return (data+b'.'+base64.urlsafe_b64encode(result.stdout).rstrip(b'=')).decode()

def installation_api(app_id,installation_id,key_path,policy):
    api=GitHub(app_jwt(app_id,key_path))
    app=api.call('/app')
    if app.get('id')!=app_id:raise Refused('App identity')
    installation=api.call(f'/app/installations/{installation_id}')
    if installation.get('app_id')!=app_id or installation.get('account',{}).get('id')!=policy['owner_id'] or installation.get('repository_selection')!='selected' or installation.get('suspended_at'):
        raise Refused('installation scope')
    permissions=installation.get('permissions',{})
    required={'contents':'read','metadata':'read','pull_requests':'read','checks':'write'}
    if permissions!=required:raise Refused('App permissions')
    auth=api.call(f'/app/installations/{installation_id}/access_tokens','POST',{'repository_ids':[policy['repository_id']],'permissions':required})
    return GitHub(auth['token'])

def snapshot(api,repo,number):
    pr=api.call(f'/repos/{repo}/pulls/{number}')
    if pr.get('state')!='open' or pr.get('base',{}).get('ref')!='main' or pr.get('base',{}).get('repo',{}).get('full_name')!=repo:raise Refused('PR scope')
    if pr.get('mergeable') is not True:raise Refused('merge result unavailable')
    values=(pr.get('head',{}).get('sha'),pr.get('base',{}).get('sha'),pr.get('merge_commit_sha'))
    if any(not isinstance(s,str) or not SHA.fullmatch(s) for s in values):raise Refused('source SHA')
    base=api.call(f'/repos/{repo}/git/ref/heads/main')['object']['sha']
    if base!=values[1]:raise Refused('base moved')
    return values

def verify_candidate(api,repo,values,policy):
    head,base,merge=values
    evaluate_repository(api.call(f'/repos/{repo}'),policy)
    commit=api.call(f'/repos/{repo}/git/commits/{merge}')
    if commit.get('sha')!=merge or {p.get('sha') for p in commit.get('parents',[])}!={base,head}:raise Refused('merge parents')
    digests=[]
    for sha in (base,merge):
        tree=api.call(f'/repos/{repo}/git/trees/{sha}?recursive=1')
        digests.append(evaluate_tree(tree,policy))
    return digests

def process_pr(api,number,policy,implementation_revision):
    repo=policy['repository'];values=snapshot(api,repo,number)
    head,base,merge=values
    binding={'pr':number,'head':head,'base':base,'merge':merge,'policy':policy_revision(policy),'implementation':implementation_revision}
    external=json.dumps(binding,sort_keys=True,separators=(',',':'))
    # Publish on the synthetic merge SHA; old results do not certify a new merge tree.
    check=api.call(f'/repos/{repo}/check-runs','POST',{'name':CONTEXT,'head_sha':merge,'status':'in_progress','external_id':external})
    conclusion='failure';reason='evaluation failed'
    try:
        verify_candidate(api,repo,values,policy)
        if snapshot(api,repo,number)!=values:raise Refused('source moved')
        conclusion='success';reason='Exact approved workflow blobs verified; source was treated only as data.'
    except Exception:
        reason='Incomplete, changed or unapproved source; no admission claimed.'
    api.call(f'/repos/{repo}/check-runs/{check["id"]}','PATCH',{'status':'completed','conclusion':conclusion,'output':{'title':'Source isolation '+conclusion,'summary':reason+'\n\nBinding: '+external}})
    # Retract our own completed result if source moved across publication.
    try: unchanged=snapshot(api,repo,number)==values
    except Exception:unchanged=False
    if not unchanged:
        api.call(f'/repos/{repo}/check-runs/{check["id"]}','PATCH',{'status':'completed','conclusion':'failure','output':{'title':'Source changed','summary':'Re-evaluation required; previous success invalidated.'}})
        conclusion='failure'
    return conclusion

def cycle(api,policy,revision):
    evaluate_repository(api.call('/repos/'+policy['repository']),policy)
    pulls=api.call('/repos/'+policy['repository']+'/pulls?state=open&per_page=100')
    if not isinstance(pulls,list) or len(pulls)>=100:raise Refused('PR census bounds')
    results=[]
    for pr in pulls:
        if pr.get('base',{}).get('ref')!='main':continue
        try:results.append(process_pr(api,pr['number'],policy,revision))
        except Exception:results.append('indeterminate')
    return results

def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser();parser.add_argument('--once',action='store_true');args=parser.parse_args()
    policy=json.loads(Path(__file__).with_name('policy.json').read_text());validate_policy(policy)
    expected=os.environ['POLICY_SHA256']
    if policy_revision(policy)!=expected:raise Refused('unapproved policy revision')
    revision=os.environ['IMPLEMENTATION_REVISION']
    if not SHA.fullmatch(revision):raise Refused('implementation revision')
    app_id=int(os.environ['GITHUB_APP_ID']);installation_id=int(os.environ['GITHUB_INSTALLATION_ID'])
    key=Path(os.environ['CREDENTIALS_DIRECTORY'])/'github-app.pem'
    while True:
        api=None
        try:
            api=installation_api(app_id,installation_id,key,policy)
            results=cycle(api,policy,revision)
            print(json.dumps({'success':results.count('success'),'failure':results.count('failure'),'indeterminate':results.count('indeterminate')}),flush=True)
        except Exception:
            print('cycle indeterminate; no success claimed',flush=True)
            if args.once:return 2
        finally:
            if api:
                try:api.call('/installation/token','DELETE')
                except Exception:print('installation token revoke indeterminate; server expiry still applies',flush=True)
                api.token=None
        if args.once:return 0 if all(r=='success' for r in results) else 2
        time.sleep(60)

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:raise SystemExit('Service refused startup; check nonsecret configuration.')
