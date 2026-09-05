import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from soc_validation_experiment import corrective_evaluation as c
from soc_validation_experiment import pipeline as p


class CorrectiveEvaluationTests(unittest.TestCase):
    def test_feature_identity_ignores_labels_and_metadata(self):
        f=pd.DataFrame({'a':[1.,1.,2.],'Label':['BENIGN','attack','attack'],'__day':['Monday','Tuesday','Friday'],'__source_row':[0,1,2]})
        groups=c.fingerprints(c.features(f))
        self.assertEqual(groups[0],groups[1])
        self.assertNotEqual(groups[0],groups[2])
        self.assertEqual(c.buckets(groups)[0],c.buckets(groups)[1])

    def test_split_is_deterministic_and_group_disjoint(self):
        groups=np.array([str(i//3) for i in range(600)])
        first=c.split_indices(groups,np.array(['Monday']*600),'duplicate_group_split')
        second=c.split_indices(groups,np.array(['Monday']*600),'duplicate_group_split')
        for key in first: np.testing.assert_array_equal(first[key],second[key])
        self.assertEqual(sum(map(len,first.values())),len(groups))
        for a,b in [('train','test'),('train','development'),('development','test')]:
            self.assertFalse(set(groups[first[a]]) & set(groups[first[b]]))

    def test_day_holdout_purges_duplicate_training_features(self):
        groups=np.array(['same','same',*[f'g{i}' for i in range(100)]])
        days=np.array(['Friday',*(['Monday']*101)])
        idx=c.split_indices(groups,days,'leave_day_out_Friday')
        self.assertEqual(idx['test'].tolist(),[0])
        self.assertNotIn(1,np.concatenate([idx['train'],idx['development']]))

    def test_imputer_never_learns_test_extreme(self):
        x=pd.DataFrame({'a':[1.,3.,np.nan,100000.],'b':[1.,2.,3.,4.]})
        idx={'train':np.array([0,1]),'development':np.array([2]),'test':np.array([3])}
        _,transformed,medians,checks=c.prepare_split(x,c.fingerprints(x),idx)
        self.assertEqual(medians['a'],2.)
        self.assertEqual(transformed['development'].iloc[0]['a'],2.)
        self.assertFalse(any(checks['overlap_checks'].values()))

    def test_all_missing_training_column_has_declared_fallback(self):
        x=pd.DataFrame({'a':[np.nan,np.nan,1.,2.],'b':[1.,2.,3.,4.]})
        idx={'train':np.array([0,1]),'development':np.array([2]),'test':np.array([3])}
        _,_,medians,checks=c.prepare_split(x,c.fingerprints(x),idx)
        self.assertEqual(medians['a'],0.)
        self.assertEqual(checks['all_missing_training_features'],['a'])

    def test_threshold_selection_uses_development_only(self):
        f=pd.DataFrame({'baseline_probability':[.15,.2,.3,.8,.9,1.], 'y_true':[0,0,1,1,1,0]})
        selected,_=c.select_thresholds(f,np.array([True,False,False,False,False,False]))
        self.assertEqual(selected['selection_partition'],'development_only')
        self.assertEqual(selected['score_only_cutoff'],.21)
        self.assertEqual(selected['detector_cutoff'],.3)

    def test_ineligible_comparator_does_not_extend_grid(self):
        f=pd.DataFrame({'baseline_probability':[1.,1.], 'y_true':[0,1]})
        selected,_=c.select_thresholds(f,np.array([True,False]))
        self.assertIsNone(selected['score_only_cutoff'])
        self.assertFalse(selected['eligible_comparator'])

    def test_metrics_match_hand_calculation(self):
        f=pd.DataFrame({'y_true':[1,1,1,0,0]})
        m=c.metrics(f,np.array([1,1,0,1,1],bool),np.array([1,0,0,0,1],bool))
        self.assertEqual((m['baseline_tp'],m['baseline_fp'],m['fp_removed'],m['tp_removed']),(2,2,1,1))
        self.assertAlmostEqual(m['recall_delta'],-1/3)
        self.assertEqual(m['fp_reduction'],.5)

    def test_absent_denominators_are_not_false_successes(self):
        f=pd.DataFrame({'y_true':[0,0]})
        m=c.metrics(f,np.zeros(2,bool),np.zeros(2,bool))
        self.assertIsNone(m['recall_delta'])
        self.assertIsNone(m['fp_reduction'])
        self.assertEqual(m['fp_reduction_wilson_ci95'],[None,None])

    def test_development_predicates_equal_z3_checked_test_path(self):
        f=p.build_synthetic_cicids(75,42)
        f['baseline_probability']=np.linspace(.15,1,len(f))
        f['baseline_predicted_label']=f.Label
        for r in f.to_dict('records'):
            e=p.mock_enrich(r)
            full=p.validate_hypothesis(r,e)
            no_smt=p.validate_hypothesis(r,e,check_smt=False)
            for key in full:
                if key!='smt_result': self.assertEqual(full[key],no_smt[key])
            if full['rule_coverage']:
                self.assertEqual(full['smt_result'],'sat' if full['disposition']=='supported' else 'unsat')

    def test_mock_run_does_not_read_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            config={'run':{'name':'credential_test','enricher':'mock','max_alerts':1},'data':{'synthetic_rows':100},'baseline':{'task':'multiclass','n_estimators':10,'test_size':.3},'validation':{}}
            with patch.object(p,'read_config',return_value=config), patch.object(p,'load_env_file',side_effect=AssertionError('Credential file was touched')):
                result=p.run_pipeline(root,root/'unused.toml',synthetic=True,enricher='mock',max_alerts=1)
                self.assertTrue((result.run_dir/'metrics.json').exists())


if __name__=='__main__':
    unittest.main()
