import {validRingLink,matchRingNonce,constantTimeEqual,claimRingAccount} from "./ring-link";
const e=new TextEncoder();
const h=(s:string,status=200)=>new Response('<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><title>CLARITY</title><body style="font:18px system-ui;max-width:480px;margin:8vh auto;padding:20px"><h1>CLARITY Ring</h1>'+s+'</body></html>',{status,headers:{"content-type":"text/html","cache-control":"no-store","content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"}});
const form=(n:string,t:string,msg="")=>h('<p>Sign in to CLARITY to connect Ring.</p><p>'+msg+'</p><form method="post" action="/ring/auth"><input type="hidden" name="nonce" value="'+n+'"><input type="hidden" name="time" value="'+t+'"><input name="email" type="email" placeholder="Email" required><input name="password" type="password" minlength="12" placeholder="Password (12+ characters)" required><button name="mode" value="login">Sign in</button><button name="mode" value="register">Create account</button></form>');
const hex=(b:Uint8Array)=>Array.from(b,x=>x.toString(16).padStart(2,"0")).join("");
const bytes=(s:string)=>Uint8Array.from(s.match(/.{2}/g)||[],x=>parseInt(x,16));
const digest=async(s:string)=>hex(new Uint8Array(await crypto.subtle.digest("SHA-256",e.encode(s))));
const passhash=async(p:string,s:Uint8Array)=>{const k=await crypto.subtle.importKey("raw",e.encode(p),"PBKDF2",false,["deriveBits"]);return hex(new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:s,iterations:250000},k,256)))};
async function setup(db:any){
 await db.unsafe("CREATE TABLE IF NOT EXISTS clarity_accounts(id uuid primary key,email text unique not null,salt text not null,passhash text not null)");
 await db.unsafe("CREATE TABLE IF NOT EXISTS clarity_sessions(id uuid primary key,account_id uuid not null,token_hash text unique not null,expires_at timestamptz not null)");
}
async function signedIn(req:Request,db:any){
 const cookie=req.headers.get("cookie")||"";
 const token=cookie.split(";").map(x=>x.trim()).find(x=>x.startsWith("clarity_session="))?.slice(16);
 if(!token||! /^[a-f0-9]{64}$/.test(token))return null;
 const rows=await db.unsafe("SELECT a.id,a.email FROM clarity_sessions s JOIN clarity_accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>now()",[await digest(token)]);
 return rows[0]||null;
}
export async function link(req:Request,url:URL,db:any){
 const n=url.searchParams.get("nonce"),t=url.searchParams.get("time");
 if(!validRingLink(n,t))return h("<p>Link expired. Restart from Ring.</p>",400);
 if(!db)return h("<p>Database unavailable.</p>",503);
 try{await setup(db);const a=await signedIn(req,db);if(!a)return form(n!,t!);return await finish(db,a,n!,t!)}catch{return h("<p>Linking unavailable. Please retry.</p>",503)}
}
async function finish(db:any,a:any,n:string,t:string){
 const rows=await db.unsafe("SELECT id,ring_account_id,access_cipher,refresh_cipher,expires_at FROM clarity_ring_tokens WHERE clarity_account_id IS NULL AND ring_account_id IS NOT NULL ORDER BY created_at DESC LIMIT 100");
 let match:any=null;
 for(const r of rows){if(constantTimeEqual(await matchRingNonce(t,r.ring_account_id,Bun.env.RING_HMAC_KEY||""),n))match=r}
 if(!match)return h("<p>No matching Ring authorization. Restart from Ring.</p>",409);
 const key=await crypto.subtle.importKey("raw",bytes(Bun.env.RING_TOKEN_ENCRYPTION_KEY||""),"AES-GCM",false,["decrypt","encrypt"]);
 const open=async(value:string)=>{const [iv,cipher]=value.split(":");return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:bytes(iv)},key,bytes(cipher)))};
 const seal=async(value:string)=>{const iv=crypto.getRandomValues(new Uint8Array(12));return hex(iv)+":"+hex(new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,e.encode(value))))};
 let access=await open(match.access_cipher);
 if(new Date(match.expires_at).getTime()<Date.now()+60000){
  const refresh=await open(match.refresh_cipher);
  const resp=await fetch("https://oauth.ring.com/oauth/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"refresh_token",refresh_token:refresh,client_id:Bun.env.RING_CLIENT_ID||"",client_secret:Bun.env.RING_CLIENT_SECRET||""}),signal:AbortSignal.timeout(12000)});
  if(!resp.ok)return h("<p>Ring authorization expired. Restart from Ring.</p>",409);
  const data=await resp.json();if(typeof data.access_token!=="string")return h("<p>Ring refresh failed.</p>",502);
  access=data.access_token;
  const nextAccess=await seal(access),nextRefresh=await seal(typeof data.refresh_token==="string"?data.refresh_token:refresh);
  await db.unsafe("UPDATE clarity_ring_tokens SET access_cipher=$1,refresh_cipher=$2,expires_at=$3 WHERE id=$4",[nextAccess,nextRefresh,new Date(Date.now()+Math.max(60,Number(data.expires_in)||14400)*1000),match.id]);
 }
 const [local,domain]=String(a.email).split("@"),masked=local[0]+"***"+local.slice(-1)+"@"+domain;
 const result=await claimRingAccount(access,masked,n);
 if(!result.ok)return h("<p>Ring confirmation failed. Restart from Ring.</p>",502);
 await db.unsafe("UPDATE clarity_ring_tokens SET clarity_account_id=$1,claimed_at=now() WHERE id=$2 AND clarity_account_id IS NULL",[String(a.id),match.id]);
 return h("<p>Ring connected to CLARITY.</p>");
}
export async function auth(req:Request,db:any){
 if(!db)return h("<p>Database unavailable.</p>",503);
 const origin=req.headers.get("origin");if(origin&&origin!==new URL(req.url).origin&&origin!=="https://clarity-api-live-production.up.railway.app")return h("<p>Invalid origin.</p>",403);
 let b:URLSearchParams;try{const raw=await req.text();if(raw.length>4096)return h("<p>Request too large.</p>",413);b=new URLSearchParams(raw)}catch{return h("<p>Invalid request.</p>",400)}
 const n=b.get("nonce"),t=b.get("time");if(!validRingLink(n,t))return h("<p>Link expired.</p>",400);
 const email=(b.get("email")||"").trim().toLowerCase(),password=b.get("password")||"",mode=b.get("mode");
 if(!email.includes("@")||email.length>255||password.length<12||password.length>256)return form(n!,t!,"Invalid email or password.");
 try{
 await setup(db);let account:any;
 if(mode==="register"){
 const salt=crypto.getRandomValues(new Uint8Array(16)),hash=await passhash(password,salt);
 const rows=await db.unsafe("INSERT INTO clarity_accounts(id,email,salt,passhash) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING RETURNING id,email",[crypto.randomUUID(),email,hex(salt),hash]);
 account=rows[0];if(!account)return form(n!,t!,"Account exists. Sign in.");
 }else if(mode==="login"){
 const rows=await db.unsafe("SELECT id,email,salt,passhash FROM clarity_accounts WHERE email=$1",[email]);
 const a=rows[0],hash=await passhash(password,a?bytes(a.salt):new Uint8Array(16));
 if(!a||!constantTimeEqual(hash,a.passhash))return form(n!,t!,"Invalid credentials.");account=a;
 }else return form(n!,t!,"Choose an action.");
 const token=hex(crypto.getRandomValues(new Uint8Array(32)));
 await db.unsafe("INSERT INTO clarity_sessions(id,account_id,token_hash,expires_at) VALUES($1,$2,$3,$4)",[crypto.randomUUID(),String(account.id),await digest(token),new Date(Date.now()+604800000)]);
 return new Response(null,{status:303,headers:{"location":"/ring/link?nonce="+encodeURIComponent(n!)+"&time="+encodeURIComponent(t!),"set-cookie":"clarity_session="+token+"; Secure; HttpOnly; SameSite=Lax; Path=/ring; Max-Age=604800","cache-control":"no-store"}});
 }catch{return form(n!,t!,"Authentication temporarily unavailable.")}
}

export async function accountStatus(req:Request,db:any){if(!db)return Response.json({linked:false,database:false},{status:503});try{await setup(db);const a=await signedIn(req,db);if(!a)return Response.json({linked:false,authenticated:false},{status:401});const rows=await db.unsafe("SELECT id FROM clarity_ring_tokens WHERE clarity_account_id=$1 AND claimed_at IS NOT NULL LIMIT 1",[String(a.id)]);return Response.json({linked:rows.length>0,authenticated:true},{headers:{"cache-control":"no-store"}})}catch{return Response.json({linked:false,error:"Status unavailable"},{status:503})}}
