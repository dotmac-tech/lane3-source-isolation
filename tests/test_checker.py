import copy
import unittest
from checker import Refused, evaluate_tree, evaluate_repository, policy_revision

POLICY = {'repository':'dotmac-tech/lane3-exposure-execution','repository_id':1406738001,'owner_id':335992433,'default_branch':'main','baseline':'67eb180022340eaea4a249cd49b06de5417b30c4','workflows':{'.github/workflows/lane3-exposure-rehearsal.yml':'a'*40,'.github/workflows/source-policy.yml':'b'*40}}

def tree():
    return {'truncated':False,'tree':[{'path':p,'type':'blob','mode':'100644','sha':sha,'size':100} for p,sha in POLICY['workflows'].items()]}

class PolicyTests(unittest.TestCase):
    def test_safe_tree(self):
        evaluate_tree(tree(), POLICY)
    def test_nonworkflow_data_is_never_executed(self):
        t=tree();t['tree'].append({'path':'scripts/source_policy.py','type':'blob','mode':'100644','sha':'c'*40,'size':200})
        evaluate_tree(t,POLICY)
    def test_trigger_only_and_combined_policy_edit_refused(self):
        for extra in (False,True):
            t=tree();t['tree'][0]['sha']='c'*40
            if extra:t['tree'].append({'path':'scripts/source_policy.py','type':'blob','mode':'100644','sha':'d'*40,'size':200})
            with self.subTest(combined=extra),self.assertRaises(Refused):evaluate_tree(t,POLICY)
    def test_every_workflow_change_refused(self):
        variants=[]
        t=tree();t['tree'].pop();variants.append(t)
        t=tree();t['tree'].append({'path':'.github/workflows/new.yml','type':'blob','mode':'100644','sha':'c'*40,'size':10});variants.append(t)
        t=tree();t['tree'][0]['mode']='120000';variants.append(t)
        t=tree();t['tree'][0]['type']='commit';variants.append(t)
        t=tree();t['truncated']=True;variants.append(t)
        t=tree();t['tree'][0]['size']=1000000;variants.append(t)
        t=tree();t['tree'].append({'path':'.github/workflows','type':'blob','mode':'120000','sha':'c'*40,'size':10});variants.append(t)
        for t in variants:
            with self.subTest(t=t),self.assertRaises(Refused):evaluate_tree(t,POLICY)
    def test_identity_refused(self):
        r={'id':1406738001,'full_name':POLICY['repository'],'owner':{'id':335992433},'default_branch':'main','archived':False,'disabled':False}
        evaluate_repository(r,POLICY)
        for field,value in [('id',1),('full_name','attacker/repo'),('default_branch','other'),('archived',True),('disabled',True)]:
            changed=copy.deepcopy(r);changed[field]=value
            with self.subTest(field=field),self.assertRaises(Refused):evaluate_repository(changed,POLICY)
        r['owner']['id']=1
        with self.assertRaises(Refused):evaluate_repository(r,POLICY)
    def test_policy_revision_binds_every_value(self):
        p=copy.deepcopy(POLICY);p['workflows'][next(iter(p['workflows']))]='e'*40
        self.assertNotEqual(policy_revision(p),policy_revision(POLICY))

if __name__=='__main__':unittest.main()
