import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseEnv } from 'node:util';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

process.umask(0o077);
const phase = process.argv[2];
assert(['plan', 'install', 'upgrade', 'enable', 'verify', 'rollback'].includes(phase));
if (['install', 'upgrade', 'enable', 'rollback'].includes(phase)) assert.equal(process.env.PLEXAUTH_LIVE_APPROVED, 'true');
const repository = path.resolve(import.meta.dirname, '..');
const infrastructure = path.join(os.homedir(), 'owl.red');
const config = JSON.parse(fs.readFileSync(path.join(infrastructure, 'ansible/vars/jellyfin.json'), 'utf8'));
const dll = fs.readFileSync(path.join(repository, 'src/Jellyfin.Plugin.PlexAuth/bin/Release/net10.0/Jellyfin.Plugin.PlexAuth.dll'));
const manifest = fs.readFileSync(path.join(repository, 'meta.json'));
const environment = { ...process.env, BW_SECRET: parseEnv(fs.readFileSync(path.join(infrastructure, 'env.secret'), 'utf8')).BW_SECRET,
    BITWARDENCLI_APPDATA_DIR: path.join(os.homedir(), '.local/state/owl-red/bitwarden-cli-2026.7.0') };
const binary = path.join(os.homedir(), '.local/share/owl-red/tools/bitwarden/2026.7.0/bw');
function vault(args) {
    const result = spawnSync(binary, args, { env: environment, encoding: 'utf8' });
    assert.equal(result.status, 0, 'Private vault operation failed; details suppressed.');
    return result.stdout.trim();
}
environment.BW_SESSION = vault(['unlock', '--passwordenv', 'BW_SECRET', '--raw']);
const items = JSON.parse(vault(['list', 'items', '--search', 'Jellyfin Access'])).filter(item => item.name === 'Jellyfin Access');
assert.equal(items.length, 1);
assert(items[0].login?.username && items[0].login?.password);
const request = { phase, config, login: { username: items[0].login.username, password: items[0].login.password },
    dll: dll.toString('base64'), manifest: manifest.toString('base64'),
    dllHash: createHash('sha256').update(dll).digest('hex'), manifestHash: createHash('sha256').update(manifest).digest('hex') };
const code = String.raw`<?php
ini_set('zend.exception_ignore_args','1');
set_exception_handler(function($error){file_put_contents('php://stderr','Plex Auth operation failed: '.$error->getMessage().PHP_EOL);exit(1);});
$r=json_decode(base64_decode('REQUEST'),true,512,JSON_THROW_ON_ERROR);$c=$r['config'];$guid='679e3ea6-3b13-4ebf-8b60-e8eab13e9ecd';
function check($condition,$message){if(!$condition)throw new RuntimeException($message);}
function run($args){$p=proc_open($args,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);check(proc_close($p)===0,'Native command failed: '.$args[0]);return trim($out);}
function inspect($name){return json_decode(run(['docker','inspect',$name]),true,512,JSON_THROW_ON_ERROR)[0];}
function api($route,$method='GET',$body=null,$token=null){$h=curl_init('http://10.0.10.5:8096'.$route);$a='MediaBrowser Client="owl.red PlexAuth Install", Device="controller", DeviceId="owl-red-plexauth-install", Version="1.0"';if($token!==null)$a.=', Token="'.$token.'"';curl_setopt_array($h,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CUSTOMREQUEST=>$method,CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_TIMEOUT=>30,CURLOPT_HTTPHEADER=>['Content-Type: application/json','Authorization: '.$a]]);if($body!==null)curl_setopt($h,CURLOPT_POSTFIELDS,json_encode($body));$out=curl_exec($h);$status=curl_getinfo($h,CURLINFO_HTTP_CODE);curl_close($h);check($out!==false&&$status>=200&&$status<300,'Jellyfin API '.$method.' '.parse_url($route,PHP_URL_PATH).' HTTP '.$status);return $out!==''?json_decode($out,true,512,JSON_THROW_ON_ERROR):null;}
$j=inspect('jellyfin');$p=inspect('plex');check($j['State']['Running']&&$p['State']['Running'],'Expected both services running');check($j['Config']['Image']===$c['image'],'Jellyfin image drift');
$package=json_decode(base64_decode($r['manifest']),true,512,JSON_THROW_ON_ERROR);check(preg_match('/^\d+\.\d+\.\d+\.\d+$/',$package['version'])===1,'Invalid package version');$target=$c['config'].'/plugins/PlexAuth_'.$package['version'];$previous=$c['config'].'/plugins/PlexAuth_0.1.0.0';check(is_dir($c['config'].'/plugins')&&!is_link($c['config'].'/plugins'),'Unexpected plugin root');
if($r['phase']==='rollback'){check(is_dir($target)&&!is_link($target),'No owned plugin to quarantine');$meta=json_decode(file_get_contents($target.'/meta.json'),true);check($meta['guid']===$guid,'Plugin identity drift');$quarantine=$c['config'].'/.PlexAuth_'.$package['version'].'-disabled-'.bin2hex(random_bytes(4));check(rename($target,$quarantine),'Plugin quarantine failed');run(['docker','restart','--time','60','jellyfin']);echo json_encode(['quarantined'=>$quarantine,'jellyfinRestarted'=>true]);exit;}
$auth=api('/Users/AuthenticateByName','POST',['Username'=>$r['login']['username'],'Pw'=>$r['login']['password']]);$token=$auth['AccessToken'];check($auth['User']['Policy']['IsAdministrator'],'Local owner is not administrator');
$libraries=api('/Library/VirtualFolders','GET',null,$token);$ids=[];foreach($c['libraries'] as $library){$matches=array_values(array_filter($libraries,fn($item)=>$item['Name']===$library['name']&&$item['Locations']===$library['paths']&&$item['CollectionType']===$library['type']));check(count($matches)===1&&!empty($matches[0]['ItemId']),'Declared library mismatch');$ids[]=$matches[0]['ItemId'];}check(count($ids)===5,'Expected five libraries');
$sessions=api('/Sessions','GET',null,$token);$playing=count(array_filter($sessions,fn($s)=>!empty($s['NowPlayingItem'])));
$h=curl_init('http://127.0.0.1:32400/identity');curl_setopt_array($h,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10]);$xml=curl_exec($h);check(curl_getinfo($h,CURLINFO_HTTP_CODE)===200,'Plex identity request failed');curl_close($h);$identity=simplexml_load_string($xml);$machine=(string)$identity['machineIdentifier'];check($machine!=='','Missing Plex machine identifier');
$desired=['Enabled'=>true,'PublicUrl'=>rtrim($c['webui'],'/'),'MachineId'=>$machine,'ClientIdentifier'=>'owl-red-jellyfin-plexauth-679e3ea6','LibraryIds'=>$ids];
$managed=array_values(array_filter(api('/Users','GET',null,$token),fn($u)=>($u['Policy']['AuthenticationProviderId']??'')==='Jellyfin.Plugin.PlexAuth.PlexOnlyAuthenticationProvider'));$profiles=array_map(fn($u)=>['id'=>$u['Id'],'name'=>$u['Name'],'hasImage'=>!empty($u['PrimaryImageTag']),'administrator'=>$u['Policy']['IsAdministrator']],$managed);
if($r['phase']==='plan'){api('/Sessions/Logout','POST',null,$token);echo json_encode(['localAdminVerified'=>true,'activePlayback'=>$playing,'pluginExists'=>file_exists($target),'previousVersionExists'=>is_dir($previous),'pluginTarget'=>$target,'dllSHA256'=>$r['dllHash'],'manifestSHA256'=>$r['manifestHash'],'desiredConfiguration'=>$desired,'managedProfiles'=>$profiles,'jellyfinId'=>$j['Id'],'plexId'=>$p['Id'],'plexStarted'=>$p['State']['StartedAt'],'quickConnectEnabled'=>api('/QuickConnect/Enabled')]);exit;}
if(in_array($r['phase'],['install','upgrade'],true)){
 check($playing===0,'Active playback; do not restart');check(!file_exists($target),'Package already exists; inspect instead of repeating install');
 if($r['phase']==='upgrade'){check($package['version']==='0.1.2.0'&&is_dir($previous)&&!is_link($previous),'Expected installed version missing');$oldMeta=json_decode(file_get_contents($previous.'/meta.json'),true);check($oldMeta['guid']===$guid&&$oldMeta['version']==='0.1.0.0'&&hash_file('sha256',$previous.'/Jellyfin.Plugin.PlexAuth.dll')==='ea6411d0ab4fae7fb01d0403d17b71a2f5190a742840eb74a7d64e79b45eb7c7','Installed old package drift');check(count($managed)>0,'Expected managed profile missing');}
 $stage=$c['config'].'/.plexauth-stage-'.bin2hex(random_bytes(4));check(mkdir($stage,0755),'Staging failed');check(chown($stage,$c['uid'])&&chgrp($stage,$c['gid']),'Staging ownership failed');
 foreach(['Jellyfin.Plugin.PlexAuth.dll'=>['data'=>$r['dll'],'hash'=>$r['dllHash']],'meta.json'=>['data'=>$r['manifest'],'hash'=>$r['manifestHash']]] as $name=>$payload){$file=$stage.'/'.$name;check(file_put_contents($file,base64_decode($payload['data'],true))!==false,'Artifact write failed');check(hash_file('sha256',$file)===$payload['hash'],'Artifact hash mismatch');check(chown($file,$c['uid'])&&chgrp($file,$c['gid'])&&chmod($file,0644),'Artifact permissions failed');}
 check(rename($stage,$target),'Atomic package publication failed');api('/Sessions/Logout','POST',null,$token);run(['docker','restart','--time','60','jellyfin']);$after=inspect('plex');check($after['Id']===$p['Id']&&$after['State']['StartedAt']===$p['State']['StartedAt'],'Plex continuity changed');echo json_encode(['installed'=>true,'jellyfinRestarted'=>true,'plexUnchanged'=>true,'backupSkippedByRequest'=>true]);exit;
}
check(is_dir($target)&&hash_file('sha256',$target.'/Jellyfin.Plugin.PlexAuth.dll')===$r['dllHash'],'Installed DLL differs');$actualMeta=json_decode(file_get_contents($target.'/meta.json'),true,512,JSON_THROW_ON_ERROR);$expectedMeta=json_decode(base64_decode($r['manifest']),true,512,JSON_THROW_ON_ERROR);foreach(['guid','name','version','targetAbi','status','autoUpdate','owner','assemblies'] as $key)check($actualMeta[$key]===$expectedMeta[$key],'Installed manifest identity differs: '.$key);
$plugins=api('/Plugins','GET',null,$token);$matches=array_values(array_filter($plugins,fn($item)=>str_replace('-','',strtolower($item['Id']))===str_replace('-','',$guid)));check(count($matches)===1,'Plugin not loaded');check($matches[0]['Status']==='Active','Plugin not active');
$saved=api('/Plugins/'.$guid.'/Configuration','GET',null,$token);
if($r['phase']==='enable'){check($playing===0,'Active playback; stop configuration change');check(!$saved['Enabled'],'Plugin already enabled; verify instead');api('/Plugins/'.$guid.'/Configuration','POST',array_merge($saved,$desired),$token);$saved=api('/Plugins/'.$guid.'/Configuration','GET',null,$token);}
if($saved['Enabled']){foreach($desired as $key=>$value){$actual=$saved[$key];if($key==='LibraryIds'){$actual=array_map(fn($id)=>str_replace('-','',strtolower($id)),$actual);$value=array_map(fn($id)=>str_replace('-','',strtolower($id)),$value);}check($actual===$value,'Plugin configuration drift: '.$key);}}
api('/Sessions/Logout','POST',null,$token);$after=inspect('plex');check($after['Id']===$p['Id']&&$after['State']['StartedAt']===$p['State']['StartedAt'],'Plex continuity changed');
echo json_encode(['pluginLoaded'=>true,'version'=>$package['version'],'enabled'=>$saved['Enabled'],'localAdminVerified'=>true,'libraryCount'=>count($ids),'managedProfiles'=>$profiles,'quickConnectEnabled'=>api('/QuickConnect/Enabled'),'plexUnchanged'=>true,'syncEnabled'=>false]);
`.replace('REQUEST', Buffer.from(JSON.stringify(request)).toString('base64'));
const result = spawnSync('ssh', ['-T', '-i', path.join(os.homedir(), '.ssh/id_ed25519_owl_ansible'), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', 'root@10.0.10.5', 'php'], { input: code, encoding: 'utf8', maxBuffer: 1024 * 1024 });
assert.equal(result.status, 0, (result.stderr || 'Live operation failed; inspect actual state before any retry.').trim());
console.log(result.stdout.trim());