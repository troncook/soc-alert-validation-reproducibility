"""Protocol-locked corrective evaluation; no network, credentials or historical overwrite."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.ensemble import RandomForestClassifier

from . import pipeline as legacy

SEED = 42
GRID = np.round(np.arange(15, 101) / 100, 2)
REFERENCE = 0.15
META = ["__source_file", "__source_row", "__day"]
SKIP = {"Label", "Flow ID", "Source IP", "Src IP", "Destination IP", "Dst IP", "Timestamp", "SimillarHTTP", *META}


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def clean(value):
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, np.ndarray)):
        return [clean(x) for x in value]
    if isinstance(value, np.generic):
        return clean(value.item())
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_json(path, value):
    Path(path).write_text(json.dumps(clean(value), indent=2, sort_keys=True, allow_nan=False)+'\n', encoding='utf-8')


def features(frame):
    # Header-defined feature set; never select columns from test variance/missingness.
    return frame[[c for c in frame if c not in SKIP]].apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).astype('float64')


def fingerprints(x):
    values = np.array(x.to_numpy(dtype='<f8'), dtype='<f8', order='C', copy=True)
    values[values == 0] = 0.0  # canonicalize signed zero
    values[np.isnan(values)] = np.nan  # canonical quiet NaN representation
    return np.array([hashlib.sha256(row.tobytes()).hexdigest() for row in values])


def buckets(groups, seed=SEED):
    mapping = {g: int(hashlib.sha256(f'{seed}:{g}'.encode()).hexdigest()[:16],16)%100 for g in np.unique(groups)}
    return np.array([mapping[g] for g in groups])


def load_sample(root, config, synthetic=False):
    if synthetic:
        df = legacy.build_synthetic_cicids(2000, SEED)
        df['__source_file'] = 'synthetic.csv'
        df['__source_row'] = np.arange(len(df))
        df['__day'] = np.array(['Monday','Tuesday','Wednesday','Thursday','Friday'])[np.arange(len(df))%5]
        # Duplicate and missing-value fixtures exercise the actual pipeline.
        df.loc[5,'Flow Bytes/s'] = np.nan
        duplicate = df.iloc[:20].copy()
        duplicate['__source_row'] += len(df)
        return pd.concat([df,duplicate],ignore_index=True), []
    parts, receipts = [], []
    for relative in config['data']['csv_paths']:
        path = root/relative
        raw = pd.read_csv(path,low_memory=False)
        raw.columns = raw.columns.str.strip()
        raw['__source_file'] = path.name
        raw['__source_row'] = np.arange(len(raw))
        raw['__day'] = path.name.split('-')[0]
        sample = legacy.stratified_cap_frame(legacy.standardize_columns(raw), int(config['run']['max_rows']), SEED)
        receipts.append({'file':path.name,'sha256':sha(path),'raw_rows':len(raw),'sample_rows':len(sample)})
        parts.append(sample)
        print(f'Loaded {path.name}: {len(sample):,} sampled rows',flush=True)
    return pd.concat(parts,ignore_index=True), receipts


def split_indices(groups, days, condition):
    b = buckets(groups)
    if condition == 'duplicate_group_split':
        return {'train':np.flatnonzero(b>=50),'development':np.flatnonzero((b>=30)&(b<50)),'test':np.flatnonzero(b<30)}
    day = condition.removeprefix('leave_day_out_')
    test = days == day
    eligible = ~np.isin(groups, np.unique(groups[test]))
    return {'train':np.flatnonzero(eligible & (b>=30)), 'development':np.flatnonzero(eligible & (b<30)), 'test':np.flatnonzero(test)}


def prepare_split(raw_x, groups, indices):
    idx={k:v.copy() for k,v in indices.items()}
    original={k:len(v) for k,v in idx.items()}
    for attempt in range(5):
        if any(len(v)==0 for v in idx.values()):
            raise ValueError('Empty train/development/test partition')
        medians=raw_x.iloc[idx['train']].median().fillna(0)
        transformed={k:raw_x.iloc[v].fillna(medians) for k,v in idx.items()}
        fp={k:fingerprints(v) for k,v in transformed.items()}
        drop_dev=np.isin(fp['development'],fp['test'])
        drop_train=np.isin(fp['train'],np.concatenate([fp['test'],fp['development']]))
        if not drop_dev.any() and not drop_train.any():
            break
        idx['development']=idx['development'][~drop_dev]
        idx['train']=idx['train'][~drop_train]
    else:
        raise AssertionError('Post-imputation overlap did not converge in five passes')
    checks={}
    for a,b in [('train','development'),('train','test'),('development','test')]:
        checks[f'{a}_{b}_row_overlap']=len(np.intersect1d(idx[a],idx[b]))
        checks[f'{a}_{b}_raw_group_overlap']=len(np.intersect1d(groups[idx[a]],groups[idx[b]]))
        checks[f'{a}_{b}_transformed_group_overlap']=len(np.intersect1d(fp[a],fp[b]))
    assert not any(checks.values()),checks
    assert all(np.isfinite(x.to_numpy()).all() for x in transformed.values())
    return idx,transformed,medians,{'overlap_checks':checks,'before_purge_rows':original,'rows':{k:len(v) for k,v in idx.items()},'post_imputation_purges':{k:original[k]-len(v) for k,v in idx.items()},'imputation_passes':attempt+1,'all_missing_training_features':raw_x.iloc[idx['train']].columns[raw_x.iloc[idx['train']].isna().all()].tolist()}


def predict(model, x, raw, indices, groups):
    probabilities=model.predict_proba(x)
    classes=np.array([str(c) for c in model.classes_])
    benign=np.char.upper(classes)=='BENIGN'
    assert benign.any() and (~benign).any(),'Training requires benign and attack classes'
    attack_positions=np.flatnonzero(~benign)
    score=probabilities[:,attack_positions].sum(axis=1)
    attack_label=classes[attack_positions[probabilities[:,attack_positions].argmax(axis=1)]]
    frame=raw.iloc[indices].copy().reset_index(drop=True)
    frame['row_index']=indices
    frame['feature_group']=groups[indices]
    frame['baseline_probability']=score
    frame['baseline_predicted_label']=np.where(score>=REFERENCE,attack_label,'BENIGN')
    frame['y_true']=legacy.binary_labels(frame).to_numpy()
    return frame


def validate(frame, directory, stage, check_smt):
    flags=np.zeros(len(frame),dtype=bool)
    rows=[]
    path=directory/f'{stage}_validation.jsonl'
    with path.open('w',encoding='utf-8') as f:
        for j,(i,record) in enumerate(((i,r) for i,r in enumerate(frame.to_dict('records')) if r['baseline_probability']>=REFERENCE),1):
            started=time.perf_counter_ns()
            enrichment=legacy.mock_enrich(record)
            after_enrichment=time.perf_counter_ns()
            result=legacy.validate_hypothesis(record,enrichment,check_smt=check_smt)
            ended=time.perf_counter_ns()
            if check_smt and result['rule_coverage']:
                assert result['smt_result']==('sat' if result['disposition']=='supported' else 'unsat'),result
            flags[i]=result['disposition']=='unsupported'
            row={'row_index':record['row_index'],'feature_group':record['feature_group'],'label':str(record['Label']),'y_true':int(record['y_true']),'baseline_probability':record['baseline_probability'],'baseline_predicted_label':record['baseline_predicted_label'],'candidate_technique_id':enrichment['candidate_technique_id'],**result,'enrichment_latency_seconds':(after_enrichment-started)/1e9,'validation_latency_seconds':(ended-after_enrichment)/1e9,'latency_seconds':(ended-started)/1e9,'smt_requested':check_smt}
            f.write(json.dumps(clean(row),allow_nan=False)+'\n')
            rows.append(row)
            if j%2000==0:
                print(f'  {directory.name} {stage}: {j:,} alerts checked',flush=True)
    return flags,rows


def select_thresholds(development, unsupported):
    score=development['baseline_probability'].to_numpy()
    y=development['y_true'].to_numpy()
    baseline=score>=REFERENCE
    quota=int(np.sum(unsupported & (y==0)))
    baseline_tp=int(np.sum(baseline & (y==1)))
    frontier=[]
    for t in GRID:
        removed=baseline & (score<t)
        frontier.append({'cutoff':float(t),'false_positives_removed':int(np.sum(removed & (y==0))),'true_positives_removed':int(np.sum(removed & (y==1))),'true_positives_retained':int(np.sum((score>=t)&(y==1)))})
    eligible=[r for r in frontier if r['false_positives_removed']>=quota]
    chosen=min(eligible,key=lambda r:(r['true_positives_removed'],-r['false_positives_removed'],r['cutoff'])) if eligible else None
    same_recall=[r for r in frontier if r['true_positives_retained']==baseline_tp]
    selection={'selection_partition':'development_only','reference_cutoff':REFERENCE,'symbolic_fp_removal_quota':quota,'score_only_cutoff':chosen['cutoff'] if chosen else None,'detector_cutoff':max(r['cutoff'] for r in same_recall),'eligible_comparator':chosen is not None,'grid':GRID.tolist(),'outcomes_previously_examined':'Historical dataset outcomes known; new test outcomes not used in this selection.'}
    return selection,frontier


def ratio(a,b):
    return float(a/b) if b else None


def wilson(k,n):
    if not n:
        return [None,None]
    ci=binomtest(k,n).proportion_ci(method='wilson')
    return [float(ci.low),float(ci.high)]


def group_bootstrap(frame, baseline, removed, draws=1000):
    y=frame['y_true'].to_numpy()
    contributions=pd.DataFrame({'group':frame['feature_group'],'fp':baseline & (y==0),'fp_removed':removed & (y==0),'malicious':y==1,'tp_removed':removed & (y==1)}).groupby('group',sort=True).sum().to_numpy(dtype=float)
    rng=np.random.default_rng(SEED)
    fp_values,recall_values=[],[]
    for _ in range(draws):
        sums=contributions[rng.integers(0,len(contributions),len(contributions))].sum(axis=0)
        if sums[0]: fp_values.append(sums[1]/sums[0])
        if sums[2]: recall_values.append(-sums[3]/sums[2])
    return {'draws':draws,'groups':len(contributions),'fp_reduction_ci95':np.quantile(fp_values,[.025,.975]).tolist() if fp_values else [None,None],'recall_delta_ci95':np.quantile(recall_values,[.025,.975]).tolist() if recall_values else [None,None],'valid_fp_draws':len(fp_values),'valid_recall_draws':len(recall_values),'scope':'Descriptive resampling of exact-feature groups; does not prove independence of near-related traffic.'}


def metrics(frame, baseline, retained):
    y=frame['y_true'].to_numpy()
    assert not np.any(retained & ~baseline)
    removed=baseline & ~retained
    tp=int(np.sum(baseline & (y==1))); fp=int(np.sum(baseline & (y==0)))
    tr=int(np.sum(removed & (y==1))); fr=int(np.sum(removed & (y==0)))
    positive=int(np.sum(y==1)); negative=len(y)-positive
    return {'test_rows':len(y),'malicious':positive,'benign':negative,'baseline_tp':tp,'baseline_fp':fp,'baseline_fn':positive-tp,'baseline_tn':negative-fp,'retained_tp':tp-tr,'retained_fp':fp-fr,'validated_fn':positive-tp+tr,'validated_tn':negative-fp+fr,'fp_removed':fr,'tp_removed':tr,'fp_reduction':ratio(fr,fp),'baseline_recall':ratio(tp,positive),'validated_recall':ratio(tp-tr,positive),'recall_delta':ratio(-tr,positive),'fp_reduction_wilson_ci95':wilson(fr,fp),'break_even_fn_to_fp_cost':ratio(fr,tr),'cost_break_even_note':'No TP removal; any FP removal is favorable under this simplified count model.' if not tr else 'Assumed relative error costs, not measured SOC costs.'}


def latency_summary(rows):
    if not rows: return {'alerts':0,'mean_seconds':None,'median_seconds':None,'p95_seconds':None,'maximum_seconds':None}
    a=np.array([r['latency_seconds'] for r in rows])
    return {'alerts':len(rows),'mean_seconds':float(a.mean()),'median_seconds':float(np.median(a)),'p95_seconds':float(np.quantile(a,.95)),'maximum_seconds':float(a.max()),'mean_enrichment_seconds':float(np.mean([r['enrichment_latency_seconds'] for r in rows])),'mean_validation_seconds':float(np.mean([r['validation_latency_seconds'] for r in rows]))}


def latency_repeats(frame, directory):
    eligible=frame.loc[frame.baseline_probability>=REFERENCE]
    sample=eligible.sample(n=min(1000,len(eligible)),random_state=SEED).to_dict('records')
    if not sample: return {'warmup_alerts':0,'passes':[]}
    for r in sample[:25]: legacy.validate_hypothesis(r,legacy.mock_enrich(r))
    passes=[]
    for repetition in range(5):
        timed=[]
        for r in sample:
            a=time.perf_counter_ns(); e=legacy.mock_enrich(r); b=time.perf_counter_ns(); legacy.validate_hypothesis(r,e); c=time.perf_counter_ns()
            timed.append({'latency_seconds':(c-a)/1e9,'enrichment_latency_seconds':(b-a)/1e9,'validation_latency_seconds':(c-b)/1e9})
        passes.append({'pass':repetition+1,**latency_summary(timed)})
        print(f'  Latency repetition {repetition+1}/5 complete',flush=True)
    pd.DataFrame(passes).to_csv(directory/'latency_repetitions.csv',index=False)
    return {'warmup_alerts':min(25,len(sample)),'sample_alerts':len(sample),'sampling_seed':SEED,'passes':passes}


def evaluate_condition(raw,x,groups,condition,config,out,draws):
    directory=out/condition; directory.mkdir()
    start=time.perf_counter()
    idx,matrix,medians,checks=prepare_split(x,groups,split_indices(groups,raw['__day'].to_numpy(),condition))
    if condition.startswith('leave_day_out_'):
        assert not set(raw.iloc[idx['train']].__day)&set(raw.iloc[idx['test']].__day)
        assert not set(raw.iloc[idx['development']].__day)&set(raw.iloc[idx['test']].__day)
    pd.DataFrame({'feature':medians.index,'training_median':medians.to_numpy()}).to_csv(directory/'training_medians.csv',index=False)
    parts=[]
    for split,ids in idx.items():
        part=raw.iloc[ids][['Label',*META]].copy(); part['row_index']=ids; part['feature_group']=groups[ids]; part['split']=split; parts.append(part)
    assignments=pd.concat(parts,ignore_index=True)
    assignments.to_csv(directory/'split_assignments.csv',index=False)
    assignments.groupby(['split','Label'],dropna=False).size().rename('rows').reset_index().to_csv(directory/'class_composition.csv',index=False)
    labels=raw.iloc[idx['train']].Label.astype(str).str.strip()
    model=RandomForestClassifier(n_estimators=100,class_weight='balanced',random_state=SEED,n_jobs=4)
    a=time.perf_counter(); model.fit(matrix['train'],labels); fit_seconds=time.perf_counter()-a
    print(f'{condition}: fit complete, train={len(labels):,}; development selection follows',flush=True)
    development=predict(model,matrix['development'],raw,idx['development'],groups)
    dev_unsupported,_=validate(development,directory,'development',False)
    selection,frontier=select_thresholds(development,dev_unsupported)
    selection['locked_at_utc']=utc(); selection['model_parameters']=model.get_params(); selection['protocol_sha256']=sha(out/'protocol.md')
    write_json(directory/'selection_lock.json',selection)
    selection_hash=sha(directory/'selection_lock.json')
    pd.DataFrame(frontier).to_csv(directory/'development_threshold_frontier.csv',index=False)
    a=time.perf_counter(); test=predict(model,matrix['test'],raw,idx['test'],groups); predict_seconds=time.perf_counter()-a
    unsupported,validation=validate(test,directory,'test',True)
    assert sha(directory/'selection_lock.json')==selection_hash
    test['unsupported']=unsupported
    test[['row_index','feature_group','Label',*META,'baseline_probability','baseline_predicted_label','y_true','unsupported']].to_csv(directory/'test_predictions.csv',index=False)
    score=test.baseline_probability.to_numpy(); base=score>=REFERENCE
    alternatives={'reference_detector':(base,base),'symbolic':(base,base & ~unsupported)}
    if selection['score_only_cutoff'] is not None:
        alternatives['development_score_filter']=(base,score>=selection['score_only_cutoff'])
    selected_base=score>=selection['detector_cutoff']
    alternatives['development_detector']=(base,selected_base)
    alternatives['development_detector_plus_symbolic']=(base,selected_base & ~unsupported)
    results={}; families=[]; target_rows=[]; cost_rows=[]
    for name,(reference,retained) in alternatives.items():
        m=metrics(test,reference,retained)
        m['feature_group_bootstrap']=group_bootstrap(test,reference,reference & ~retained,draws)
        # One observation per exact feature group and label; conflicting labels remain explicit.
        unique=~test.duplicated(['feature_group','Label']).to_numpy()
        m['unique_feature_label_metrics']=metrics(test.loc[unique].reset_index(drop=True),reference[unique],retained[unique])
        results[name]=m
        for label in sorted(test.Label.unique()):
            mask=test.Label.eq(label).to_numpy()
            families.append({'condition':condition,'policy':name,'label':label,'test_rows':int(mask.sum()),'baseline_retained':int(np.sum(reference&mask)),'policy_retained':int(np.sum(retained&mask)),'removed':int(np.sum(reference&~retained&mask)),'absent_from_training':str(label) not in set(labels),'malicious_label':str(label).upper()!='BENIGN'})
        for target in [.1,.2,.3,.4,.5]:
            for margin in [0,.001,.005,.01,.02,.05]:
                target_rows.append({'policy':name,'fp_target':target,'recall_margin':margin,'fp_target_met':None if m['fp_reduction'] is None else m['fp_reduction']>=target,'recall_margin_met':None if m['recall_delta'] is None else m['recall_delta']>=-margin})
        for weight in [1,5,10,20,100,1000]:
            cost_rows.append({'policy':name,'fn_to_fp_cost_assumption':weight,'net_count_benefit':m['fp_removed']-weight*m['tp_removed']})
    pd.DataFrame(families).to_csv(directory/'attack_family_outcomes.csv',index=False)
    pd.DataFrame(target_rows).to_csv(directory/'target_sensitivity.csv',index=False)
    pd.DataFrame(cost_rows).to_csv(directory/'cost_sensitivity.csv',index=False)
    report={'condition':condition,'selection':selection,'selection_lock_sha256':selection_hash,'split_checks':checks,'model_fit_seconds':fit_seconds,'test_prediction_seconds':predict_seconds,'policies':results,'test_latency':latency_summary(validation),'smt_test_alerts':len(validation),'smt_disagreements':0,'absent_test_classes':sorted(set(labels)-set(test.Label)),'test_classes_absent_from_training':sorted(set(test.Label)-set(labels)),'validation_dispositions':pd.Series([r['disposition'] for r in validation]).value_counts().to_dict(),'elapsed_seconds':time.perf_counter()-start}
    if condition=='duplicate_group_split': report['repeated_latency']=latency_repeats(test,directory)
    write_json(directory/'results.json',report)
    print(f'{condition} complete: symbolic FP/TP removed {results["symbolic"]["fp_removed"]}/{results["symbolic"]["tp_removed"]}',flush=True)
    return report


def environment_receipt(root):
    packages={p:importlib.metadata.version(p) for p in ['pandas','numpy','scikit-learn','scipy','z3-solver','joblib','threadpoolctl']}
    hardware={}
    if os.name=='nt':
        command="$p=Get-CimInstance Win32_Processor; $m=Get-CimInstance Win32_ComputerSystem; @{cpu=($p.Name -join ', ');physical_cores=($p.NumberOfCores | Measure-Object -Sum).Sum;logical_cores=($p.NumberOfLogicalProcessors | Measure-Object -Sum).Sum;physical_memory_bytes=$m.TotalPhysicalMemory} | ConvertTo-Json -Compress"
        p=subprocess.run(['powershell','-NoProfile','-Command',command],capture_output=True,text=True,check=True)
        hardware=json.loads(p.stdout)
    else:
        hardware={'cpu':platform.processor(),'logical_cores':os.cpu_count()}
    git=subprocess.run(['git','rev-parse','HEAD'],cwd=root,capture_output=True,text=True)
    dirty=subprocess.run(['git','status','--porcelain','--untracked-files=no'],cwd=root,capture_output=True,text=True)
    return {'python':platform.python_version(),'os':platform.platform(),'packages':packages,'hardware':hardware,'git_commit':git.stdout.strip() if git.returncode==0 else None,'tracked_worktree_dirty':bool(dirty.stdout.strip()),'fit_workers':4,'validation_workers':1,'hosted_calls':0}


def run(root,config_path,output,protocol,synthetic=False,conditions=None):
    config=legacy.read_config(config_path)
    assert config['run']['enricher']=='mock'
    assert config['baseline']['task']=='multiclass' and config['baseline']['n_estimators']==100
    output.mkdir(parents=True,exist_ok=False)
    (output/'protocol.md').write_bytes(protocol.read_bytes())
    source_receipts={str(p.relative_to(root)):sha(p) for p in [Path(__file__),Path(legacy.__file__),config_path,protocol]}
    manifest={'started_at_utc':utc(),'classification':'synthetic_QA' if synthetic else 'corrective_re_evaluation','replaces_historical_primary':False,'environment':environment_receipt(root),'source_hashes':source_receipts,'config':config,'protocol_sha256':sha(protocol),'conditions':conditions or ['duplicate_group_split',*[f'leave_day_out_{d}' for d in ['Monday','Tuesday','Wednesday','Thursday','Friday']]],'status':'running'}
    write_json(output/'manifest.json',manifest)
    try:
        raw,inputs=load_sample(root,config,synthetic)
        x=features(raw); groups=fingerprints(x)
        if not synthetic: assert len(raw)==400000 and x.shape[1]==78
        manifest.update({'dataset_inputs':inputs,'sample_rows':len(raw),'feature_columns':list(x),'unique_feature_groups':len(np.unique(groups)),'duplicate_excess':len(raw)-len(np.unique(groups))})
        write_json(output/'manifest.json',manifest)
        reports=[]
        for condition in manifest['conditions']:
            reports.append(evaluate_condition(raw,x,groups,condition,config,output,100 if synthetic else 1000))
        write_json(output/'results.json',reports)
        manifest['status']='complete'
    except Exception as exc:
        manifest['status']='failed'; manifest['failure']=f'{type(exc).__name__}: {exc}'
        raise
    finally:
        manifest['finished_at_utc']=utc()
        manifest['output_hashes']={str(p.relative_to(output)):sha(p) for p in output.rglob('*') if p.is_file() and p.name!='manifest.json'}
        manifest['source_unchanged_during_run']=all(sha(root/p)==h for p,h in source_receipts.items())
        write_json(output/'manifest.json',manifest)
    assert manifest['source_unchanged_during_run']
    return output
