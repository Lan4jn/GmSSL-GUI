import pathlib,sys,os,subprocess,importlib.util
R=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('dmprod',R/'tests/dm/run_production_verification.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
jdk=next((R/'.tools').glob('jdk-21*/Contents/Home'));driver=R/'.tools/logs/dm-dependency/DmJdbcDriver18-8.1.3.140.jar';target=R/'tests/dm/target/baseline-probe';target.mkdir(parents=True,exist_ok=True)
p=subprocess.run([str(jdk/'bin/javac'),'-cp',str(driver),'-d',str(target),str(R/'tests/dm/DmBaselineProbe.java')],capture_output=True,timeout=30)
print('DMB COMPILE_EXIT '+str(p.returncode))
if p.returncode:print(p.stderr.decode());sys.exit(p.returncode)
if '--compile-only' in sys.argv:sys.exit(0)
env=mod.read_test_env();env['PATH']=os.defpath
args=[]
if '--execute' in sys.argv:
 args=[str(R/'ops/dm8/migrations/00_schema_version_and_baseline.sql')]
p=subprocess.run([str(jdk/'bin/java'),'-cp',str(target)+os.pathsep+str(driver),'DmBaselineProbe']+args,env=env,capture_output=True,timeout=60)
lines=[line for line in p.stdout.decode(errors='replace').splitlines() if line.startswith('DMB ')]
lines.append('DMB EXIT '+str(p.returncode));text='\n'.join(lines)+'\n'
log=R/('.tools/logs/dm-upgrade-nohash-reentry.log' if args else '.tools/logs/dm-upgrade-metadata.log');fd=os.open(log,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as f:f.write(text)
print(text,end='');sys.exit(p.returncode)
