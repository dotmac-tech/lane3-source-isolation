import copy
import unittest
from unittest.mock import patch
from checker import Refused
from service import process_pr, snapshot
from test_checker import POLICY, tree

BASE='1'*40;HEAD='2'*40;MERGE='3'*40
class API:
    def __init__(self,change_at=None,unsafe=False):self.snapshots=0;self.change_at=change_at;self.unsafe=unsafe;self.published=[]
    def call(self,path,method='GET',payload=None):
        if method=='POST':return {'id':9}
        if method=='PATCH':self.published.append(payload['conclusion']);return {}
        if '/pulls/' in path:
            self.snapshots+=1
            return {'state':'open','mergeable':True,'base':{'ref':'main','sha':BASE,'repo':{'full_name':POLICY['repository']}},'head':{'sha':HEAD},'merge_commit_sha':('4'*40 if self.change_at and self.snapshots>=self.change_at else MERGE)}
        if '/git/ref/' in path:return {'object':{'sha':BASE}}
        if '/git/commits/' in path:return {'sha':MERGE,'parents':[{'sha':BASE},{'sha':HEAD}]}
        if '/git/trees/' in path:
            t=tree()
            if self.unsafe:t['tree'][0]['sha']='f'*40
            return t
        return {'id':POLICY['repository_id'],'full_name':POLICY['repository'],'owner':{'id':POLICY['owner_id']},'default_branch':'main'}

class ServiceTests(unittest.TestCase):
    def test_safe_candidate_publishes_success_on_merge(self):
        api=API();self.assertEqual(process_pr(api,1,POLICY,'a'*40),'success');self.assertEqual(api.published,['success'])
    def test_candidate_workflow_edit_is_failure(self):
        api=API(unsafe=True);self.assertEqual(process_pr(api,1,POLICY,'a'*40),'failure');self.assertEqual(api.published,['failure'])
    def test_source_moves_before_publication_never_success(self):
        api=API(change_at=2);self.assertEqual(process_pr(api,1,POLICY,'a'*40),'failure');self.assertNotIn('success',api.published)
    def test_source_moves_after_publication_success_retracted(self):
        api=API(change_at=3);self.assertEqual(process_pr(api,1,POLICY,'a'*40),'failure');self.assertEqual(api.published,['success','failure'])
    def test_api_errors_do_not_publish_success(self):
        api=API()
        original=api.call
        def fail(path,method='GET',payload=None):
            if '/git/trees/' in path:raise OSError('unavailable')
            return original(path,method,payload)
        api.call=fail
        self.assertEqual(process_pr(api,1,POLICY,'a'*40),'failure');self.assertNotIn('success',api.published)
    def test_wrong_merge_parents_refused(self):
        api=API();original=api.call
        def wrong(path,method='GET',payload=None):
            if '/git/commits/' in path:return {'sha':MERGE,'parents':[{'sha':'9'*40},{'sha':HEAD}]}
            return original(path,method,payload)
        api.call=wrong
        self.assertEqual(process_pr(api,1,POLICY,'a'*40),'failure')

if __name__=='__main__':unittest.main()
