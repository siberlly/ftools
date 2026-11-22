"""Bounded cross-source timeline and same-evidence artifact correlation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TIMELINE_SCHEMA = 1
DDL = """
CREATE TABLE IF NOT EXISTS timeline_meta(evidence_id TEXT PRIMARY KEY, state TEXT, generations TEXT, skipped INTEGER DEFAULT 0, errors TEXT, updated_at TEXT, progress INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS timeline_events(evidence_id TEXT NOT NULL,event_id TEXT NOT NULL,source_type TEXT NOT NULL,source_record_id TEXT NOT NULL,occurred_at_utc TEXT NOT NULL,timestamp_kind TEXT NOT NULL,title TEXT,summary TEXT,path TEXT,filename TEXT,sha256 TEXT,sha1 TEXT,md5 TEXT,actor TEXT,source_url TEXT,provenance TEXT,PRIMARY KEY(evidence_id,event_id));
CREATE INDEX IF NOT EXISTS timeline_time ON timeline_events(evidence_id,occurred_at_utc DESC,event_id);
CREATE INDEX IF NOT EXISTS timeline_source ON timeline_events(evidence_id,source_type,timestamp_kind);
"""

def _utc(value: Any) -> str | None:
    if not value: return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError): return None

def normalize_windows_path(value: str | None) -> str | None:
    if not value: return None
    value = str(value).replace("\x00", "").strip().replace("/", "\\")
    for prefix in ("\\\\?\\", "\\??\\", "\\Device\\HarddiskVolume"):
        if value.lower().startswith(prefix.lower()):
            if prefix.lower().startswith("\\device"):
                value = "<device>" + value[len(prefix):]
            else: value = value[len(prefix):]
            break
    return "\\".join(part.strip() for part in value.split("\\") if part).casefold()

class InvestigationService:
    def __init__(self, settings, services):
        self.settings, self.services = settings, services
        self.path = settings.var_dir / "cases" / "timeline.db"
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connect() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(DDL)
            columns={row[1] for row in c.execute("PRAGMA table_info(timeline_meta)")}
            if "progress" not in columns: c.execute("ALTER TABLE timeline_meta ADD COLUMN progress INTEGER DEFAULT 0")
        # These indexes keep correlations bounded to SQLite rows rather than
        # iterating the evidence index on each detail-panel request.
        try:
            with sqlite3.connect(settings.index_database(), timeout=5) as c:
                c.execute("CREATE INDEX IF NOT EXISTS idx_entry_stored_sha1 ON filesystem_entries(evidence_id,scan_id,stored_sha1)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_entry_stored_md5 ON filesystem_entries(evidence_id,scan_id,stored_md5)")
        except sqlite3.Error:
            pass
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="timeline")
        self._futures: dict[str, Any] = {}
        self._lock = threading.Lock()

    def _connect(self):
        c=sqlite3.connect(self.path, timeout=10); c.row_factory=sqlite3.Row; return c

    def _generations(self, evidence_id: str) -> dict[str, Any]:
        result={}
        for source, path, table, where, params, col, state_col, time_col in (
            ("filesystem",self.settings.index_database(),"evidence_indexes","evidence_id=?",(evidence_id,),"scan_id","status","completed_at"),
            ("amcache",self.settings.registry_database(),"registry_hives","evidence_id=?",(evidence_id,),"hive_id","state","finished_at"),
            ("evtx",self.settings.evtx_database(),"evtx_logs","evidence_id=?",(evidence_id,),"log_id","status","completed_at"),
            ("browser",self.settings.browser_database(),"browser_artifacts","evidence_id=?",(evidence_id,),"artifact_id","status","completed_at")):
            try:
                c=sqlite3.connect(f"file:{path}?mode=ro",uri=True,timeout=3); c.row_factory=sqlite3.Row
                rows=c.execute(f"SELECT {col},{state_col},{time_col} FROM {table} WHERE {where}",params).fetchall()
                result[source]=sorted([list(row) for row in rows])
                c.close()
            except (sqlite3.Error,OSError): result[source]=[]
        return result

    def start(self,evidence_id:str,rebuild:bool=False)->dict[str,Any]:
        with self._lock:
            existing=self._futures.get(evidence_id)
            if existing and not existing.done(): return self.status(evidence_id)
            current=self._generations(evidence_id)
            if not rebuild:
                status=self.status(evidence_id)
                if status.get("state")=="ready" and not status.get("stale"): return status
            with self._connect() as c: c.execute("INSERT OR REPLACE INTO timeline_meta(evidence_id,state,generations,skipped,errors,updated_at,progress) VALUES(?,?,?,?,?,?,?)",(evidence_id,"queued",json.dumps(current,sort_keys=True),0,"{}",_now(),0))
            self._futures[evidence_id]=self._pool.submit(self._build,evidence_id,current)
        return self.status(evidence_id)

    def _build(self,eid,generations):
        with self._connect() as c:
            c.execute("UPDATE timeline_meta SET state='running' WHERE evidence_id=?",(eid,)); c.execute("DELETE FROM timeline_events WHERE evidence_id=?",(eid,))
        started=time.monotonic(); deadline=started+max(1,float(self.settings.index_timeout))
        skipped=0; errors={k:"not_indexed" for k,v in generations.items() if not v}; batch=[]; added=0; maximum=200000
        def flush():
            nonlocal added
            if not batch:return
            with self._connect() as c:
                c.executemany("INSERT OR IGNORE INTO timeline_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",batch)
                added += len(batch); batch.clear()
                c.execute("UPDATE timeline_meta SET progress=?,updated_at=? WHERE evidence_id=?",(min(99,added*100//maximum),_now(),eid))
        def add(src,rid,when,kind,title,summary,path,sha256,sha1,md5,url,prov,actor=None):
            nonlocal skipped
            if time.monotonic()>deadline: raise TimeoutError("timeline build exceeded configured timeout")
            ts=_utc(when)
            if not ts: skipped+=1; return
            if added+len(batch)>=maximum: skipped+=1; return
            eid_hash=hashlib.sha256(f"{eid}|{src}|{rid}|{kind}|{ts}".encode()).hexdigest()
            batch.append((eid,eid_hash,src,str(rid),ts,kind,title,summary,path,Path(path).name if path else None,sha256,sha1,md5,actor,url,json.dumps(prov,ensure_ascii=False)))
            if len(batch)>=500: flush()
        def read(source, db, query, params, consume):
            try:
                con=sqlite3.connect(f"file:{db}?mode=ro",uri=True,timeout=5); con.row_factory=sqlite3.Row
                for row in con.execute(query,params): consume(row)
                con.close()
            except (sqlite3.Error,OSError,KeyError,ValueError) as ex: errors[source]=str(ex)[:500]
        try:
            fs=self.settings.index_database()
            try:
                con=sqlite3.connect(f"file:{fs}?mode=ro",uri=True,timeout=5); con.row_factory=sqlite3.Row
                scan=con.execute("SELECT scan_id,scanner_version FROM evidence_indexes WHERE evidence_id=? AND status='ready'",(eid,)).fetchone()
                if scan:
                    sid=scan[0]; rows=con.execute("SELECT * FROM filesystem_entries WHERE evidence_id=? AND scan_id=? AND entry_type='file' LIMIT ?",(eid,sid,min(self.settings.index_max_entries,200000)))
                    for r in rows:
                        base={"scan_id":sid,"entry_id":r["id"],"parser":scan["scanner_version"]}; entryid=r["id"]; path=r["full_path"]
                        for field,kind in (("created_time","created"),("modified_time","modified"),("accessed_time","accessed"),("mft_modified_time","metadata_changed")):
                            add("filesystem",entryid,r[field],kind,Path(path).name or path,f"File {kind}: {path}",path,None,r["stored_sha1"],r["stored_md5"],f"/evidence/{eid}/entry/{entryid}",base)
                con.close()
            except (sqlite3.Error,OSError) as ex: errors["filesystem"]=str(ex)[:500]
            def am(r):
                for f,k in (("compile_timestamp","compiled"),("key_mtime","key_modified"),("first_run","first_run"),("last_modified","last_modified")):
                    add("amcache",r["id"],r[f],k,r["executable_name"] or r["program_name"] or "Amcache record",r["executable_path"] or r["source_key_path"],r["executable_path"],None,r["hash_normalized"] if r["hash_algorithm"]=="sha1" else None,r["hash_normalized"] if r["hash_algorithm"]=="md5" else None,f"/registry/amcache/{r['hive_id']}/{r['id']}",{"hive_id":r["hive_id"],"record_id":r["id"],"parser":r["source_parser"]})
            read("amcache",self.settings.registry_database(),"SELECT a.*,h.parser_version AS source_parser FROM registry_amcache a JOIN registry_hives h ON h.hive_id=a.hive_id WHERE h.evidence_id=? LIMIT ?",(eid,min(self.settings.registry_max_amcache_records,100000)),am)
            def ev(r):
                kind="service_installed" if r["event_id"]==7045 else "process_created" if r["event_id"]==4688 or (r["event_id"]==1 and "sysmon" in (r["provider_name"] or "").casefold()) else "event"
                add("evtx",f"{r['log_id']}:{r['record_id']}",r["timestamp_utc"],kind,r["provider_name"] or f"Event {r['event_id']}",r["summary"] or r["message"] or "",None,None,None,None,f"/event-logs/{r['log_id']}/events/{r['record_id']}",{"log_id":r["log_id"],"record_id":r["record_id"],"parser":r["parser_version"]},str(r["user_sid"] or r["process_id"] or "") )
            read("evtx",self.settings.evtx_database(),"SELECT e.*,l.parser_version FROM evtx_events e JOIN evtx_logs l ON l.log_id=e.log_id WHERE l.evidence_id=? LIMIT ?",(eid,min(self.settings.evtx_max_records,200000)),ev)
            def browser(table,kindfield,tsfields):
                def consume(r):
                    for f,k in tsfields:
                        add("browser",f"{r['id']}",r[f],k,r["filename"] if "filename" in r.keys() and r["filename"] else r["title"] if "title" in r.keys() else r["url"] if "url" in r.keys() else "Browser artifact",r["url"] if "url" in r.keys() else r["target_path"] if "target_path" in r.keys() else "",r["target_path"] if "target_path" in r.keys() else r["local_path"] if "local_path" in r.keys() else None,None,None,r["hash_value"] if "hash_value" in r.keys() else None,f"/browser/records/{kindfield}/{r['id']}",{"artifact_id":r["artifact_id"],"record_id":r["id"],"parser":r["parser_version"]})
                read("browser",self.settings.browser_database(),f"SELECT b.*,a.parser_version FROM {table} b JOIN browser_artifacts a ON a.artifact_id=b.artifact_id WHERE a.evidence_id=? LIMIT ?",(eid,min(self.settings.browser_max_records,200000)),consume)
            browser("browser_downloads","download",[("start_time","downloaded"),("end_time","download_completed")]); browser("browser_visits","visit",[("visit_time","visited")]); browser("browser_cache","cache",[("created_time","cache_created"),("accessed_time","cache_accessed"),("modified_time","cache_modified")])
            flush()
            with self._connect() as c:
                c.execute("UPDATE timeline_meta SET state='ready',progress=100,skipped=?,errors=?,updated_at=? WHERE evidence_id=?",(skipped,json.dumps(errors),_now(),eid))
        except Exception as ex:
            with self._connect() as c: c.execute("UPDATE timeline_meta SET state='error',errors=?,updated_at=? WHERE evidence_id=?",(json.dumps({**errors,"timeline":str(ex)[:500]}),_now(),eid))

    def status(self,eid):
        with self._connect() as c: r=c.execute("SELECT * FROM timeline_meta WHERE evidence_id=?",(eid,)).fetchone()
        if not r:return {"evidence_id":eid,"state":"not_indexed","stale":False,"completeness":0,"trust":"untrusted_evidence_data"}
        expected=json.loads(r["generations"] or "{}"); current=self._generations(eid); errors=json.loads(r["errors"] or "{}")
        stale=expected!=current; state="stale" if stale else "partial" if r["state"]=="ready" and errors else r["state"]
        return {"evidence_id":eid,"state":state,"progress":r["progress"],"stale":stale,"skipped_timestamps":r["skipped"],"errors":errors,"generations":expected,"current_generations":current,"completeness":0 if stale else 0.5 if errors else 1,"trust":"untrusted_evidence_data"}

    def query(self,eid,*,time_from=None,time_to=None,source=None,kind=None,keyword=None,path=None,hash_value=None,page=1,page_size=100,sort="desc"):
        state=self.status(eid); page=max(1,int(page)); page_size=max(1,min(500,int(page_size)))
        if state["stale"]: return {"items":[],"total":0,"page":page,"page_size":page_size,**state}
        clauses=["evidence_id=?"]; params=[eid]
        for col,val,op in (("occurred_at_utc",_utc(time_from),">="),("occurred_at_utc",_utc(time_to),"<="),("source_type",source,"="),("timestamp_kind",kind,"=")):
            if val: clauses.append(f"{col}{op}?");params.append(val)
        if keyword:
            escaped="%"+str(keyword).replace("%","\\%").replace("_","\\_")+"%"
            clauses.append("(title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' OR filename LIKE ? ESCAPE '\\')")
            params.extend([escaped,escaped,escaped])
        if path:
            clauses.append("path LIKE ? ESCAPE '\\'")
            params.append("%"+str(path).replace("%","\\%").replace("_","\\_")+"%")
        if hash_value:clauses.append("(sha256=? OR sha1=? OR md5=?)");params.extend([hash_value]*3)
        where=" AND ".join(clauses)
        with self._connect() as c:
            total=c.execute(f"SELECT COUNT(*) FROM timeline_events WHERE {where}",params).fetchone()[0]
            rows=c.execute(f"SELECT * FROM timeline_events WHERE {where} ORDER BY occurred_at_utc {'ASC' if sort=='asc' else 'DESC'},event_id LIMIT ? OFFSET ?",(*params,page_size,(page-1)*page_size)).fetchall()
        return {"items":[dict(r)|{"provenance":json.loads(r["provenance"])} for r in rows],"total":total,"page":page,"page_size":page_size,**state}

    def event(self,eid,event_id):
        with self._connect() as c:r=c.execute("SELECT * FROM timeline_events WHERE evidence_id=? AND event_id=?",(eid,event_id)).fetchone()
        if r is None: raise KeyError("timeline event not found")
        return dict(r)|{"provenance":json.loads(r["provenance"]),"trust":"untrusted_evidence_data"}

    def related(self,eid,entry_id,limit=100):
        limit=max(1,min(200,int(limit))); entry=self.services.indexer.tree_entry(self.services.evidence.get(eid),int(entry_id))
        if entry.entry_type!="file": return {"entry_id":entry_id,"items":[],"sources":{},"trust":"untrusted_evidence_data"}
        generations=self._generations(eid)
        src={key:("ready" if any(len(row)>1 and row[1]=="ready" for row in rows) else "partial" if any(len(row)>1 and row[1]=="partial" for row in rows) else "indexing" if rows else "not_indexed") for key,rows in generations.items()}; hits=[]
        path=entry.full_path; norm=normalize_windows_path(path); name=Path(path).name.casefold(); hashes={"sha1":getattr(entry,"stored_sha1",None),"md5":getattr(entry,"stored_md5",None),"sha256":None}
        def hit(rel, val, confidence, source, rid, url, title, timestamp=None, prov=None):hits.append({"relationship_type":rel,"match_value":val,"confidence_basis":confidence,"source_type":source,"source_record_id":str(rid),"target_id":rid,"target_url":url,"title":title,"timestamp_utc":_utc(timestamp),"provenance":prov or {},"trust":"untrusted_evidence_data"})
        con=sqlite3.connect(f"file:{self.settings.index_database()}?mode=ro",uri=True);con.row_factory=sqlite3.Row
        try:
            scanrow=con.execute("SELECT scan_id FROM evidence_indexes WHERE evidence_id=? AND status='ready'",(eid,)).fetchone()
            if scanrow:
              terms=["basename=? COLLATE NOCASE"]
              args=[eid,scanrow[0],name]
              candidates=[path, path.replace("\\","/"), path.replace("/","\\")]
              terms.append("full_path IN (?,?,?) COLLATE NOCASE"); args.extend(candidates)
              if hashes["sha1"]: terms.append("stored_sha1=?"); args.append(hashes["sha1"])
              if hashes["md5"]: terms.append("stored_md5=?"); args.append(hashes["md5"])
              query="SELECT * FROM filesystem_entries WHERE evidence_id=? AND scan_id=? AND entry_type='file' AND ("+" OR ".join(terms)+") LIMIT 1000"
              for r in con.execute(query,args):
                if r["id"]==entry.id:continue
                why=None; val=None
                for h in hashes:
                    hv=r["stored_sha1"] if h=="sha1" else r["stored_md5"] if h=="md5" else None
                    if hashes[h] and hv and hashes[h].casefold()==hv.casefold():why="exact_hash";val=hv;break
                if not why and norm and normalize_windows_path(r["full_path"])==norm:why="exact_normalized_path";val=path
                if not why and r["basename"].casefold()==name:why="filename_only";val=name
                if why:hit(why,val,"cryptographic hash" if why=="exact_hash" else "normalized full path" if why=="exact_normalized_path" else "filename only; weak association", "filesystem",r["id"],f"/evidence/{eid}/entry/{r['id']}",r["basename"],r["modified_time"],{"scan_id":r["scan_id"]})
        finally:con.close()
        # Query the other already-built SQLite indexes, never the evidence image.
        for source,db,table,join,keycol,timecol,urltype in (("browser",self.settings.browser_database(),"browser_downloads","browser_artifacts","target_path","start_time","download"),("amcache",self.settings.registry_database(),"registry_amcache","registry_hives","executable_path","first_run",None)):
            try:
                c=sqlite3.connect(f"file:{db}?mode=ro",uri=True);c.row_factory=sqlite3.Row
                if source=="browser": rows=c.execute("SELECT d.* FROM browser_downloads d JOIN browser_artifacts a ON a.artifact_id=d.artifact_id WHERE a.evidence_id=? AND a.status IN ('ready','partial') AND d.target_path IS NOT NULL LIMIT 1000",(eid,))
                else: rows=c.execute("SELECT x.* FROM registry_amcache x JOIN registry_hives h ON h.hive_id=x.hive_id WHERE h.evidence_id=? AND h.state IN ('ready','partial') LIMIT 1000",(eid,))
                for r in rows:
                    candidate=r[keycol] if keycol in r.keys() else None; rel=None; val=None
                    for h in hashes:
                        hv=r["hash_value"] if source=="browser" and "hash_value" in r.keys() else r["hash_normalized"] if source=="amcache" and "hash_normalized" in r.keys() else None
                        if hashes[h] and hv and hashes[h].casefold()==hv.casefold():rel="exact_hash";val=hv;break
                    if not rel and norm and candidate and normalize_windows_path(candidate)==norm:rel="download_target" if source=="browser" else "exact_normalized_path";val=candidate
                    if not rel and candidate and Path(candidate.replace("\\","/")).name.casefold()==name:rel="filename_only";val=Path(candidate.replace("\\","/")).name
                    if rel:
                        rid=r["id"]
                        if source=="browser": url=f"/browser/records/download/{rid}"; title=r["url"] or candidate
                        else:url=f"/registry/amcache/{r['hive_id']}/{rid}";title=r["executable_name"] or candidate
                        hit(rel,val,"stored matching hash" if rel=="exact_hash" else "normalized path" if rel!="filename_only" else "filename only; weak association",source,rid,url,title,r[timecol] if timecol in r.keys() else None,{"artifact_id":r["artifact_id"]} if source=="browser" else {"hive_id":r["hive_id"]})
                c.close()
            except (sqlite3.Error,OSError): src[source]="not_indexed"
        try:
            c=sqlite3.connect(f"file:{self.settings.evtx_database()}?mode=ro",uri=True,timeout=2); c.row_factory=sqlite3.Row
            c.set_progress_handler(lambda: 1, 20000)
            rows=c.execute("SELECT e.* FROM evtx_events e JOIN evtx_logs l ON l.log_id=e.log_id WHERE l.evidence_id=? AND l.status IN ('ready','partial') AND (e.event_data_json LIKE ? OR e.message LIKE ? OR e.summary LIKE ?) LIMIT 200",(eid,"%"+name+"%","%"+name+"%","%"+name+"%"))
            # Keep source readiness tied to index state, even when the query
            # returned no rows.
            for r in rows:
                data=(r["event_data_json"] or "")+(r["message"] or "")+(r["summary"] or "")
                if norm and norm in normalize_windows_path(data):
                    rel="service_image_path"; val=path; basis="normalized path found in indexed event fields"
                else:
                    rel="filename_only"; val=name; basis="filename found in indexed event fields; weak association"
                hit(rel,val,basis,"evtx",f"{r['log_id']}:{r['record_id']}",f"/event-logs/{r['log_id']}/events/{r['record_id']}",r["summary"] or r["provider_name"] or "EVTX event",r["timestamp_utc"],{"log_id":r["log_id"],"record_id":r["record_id"]})
            c.close()
        except (sqlite3.Error,OSError): src["evtx"]="not_indexed"
        rank={"exact_hash":0,"exact_normalized_path":1,"download_target":2,"service_image_path":2,"filename_only":3}
        hits.sort(key=lambda h:(rank.get(h["relationship_type"],4),h["source_type"],h["source_record_id"]))
        return {"entry_id":entry.id,"path":entry.full_path,"items":hits[:limit],"sources":src,"trust":"untrusted_evidence_data","complete":True}

def _now():return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
