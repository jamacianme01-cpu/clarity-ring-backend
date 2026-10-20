import {link,auth,accountStatus} from "./account-link";
import {validRingLink} from "./ring-link";
import postgres from "postgres";
const db = Bun.env.DATABASE_URL ? postgres(Bun.env.DATABASE_URL,{max:2}) : null;
const response=(body:unknown,status=200)=>Response.json(body,{status,headers:{"cache-control":"no-store"}});
const secret=Bun.env.CLARITY_INTERNAL_API_KEY;
Bun.serve({port:Number(Bun.env.PORT||3000),hostname:"0.0.0.0",async fetch(req:Request){
const url=new URL(req.url);
if(req.method==="GET"&&url.pathname==="/health"){try{if(!db)throw Error("No database");await db`SELECT 1`;return response({status:"ok",database:true,ringConnected:false});}catch{return response({status:"degraded",database:false,ringConnected:false},503);}}
if(req.method==="GET"&&url.pathname==="/api/integrations/status"){if(!secret||req.headers.get("x-clarity-api-key")!==secret)return response({error:"Unauthorized"},401);let database=false;try{if(db){await db`SELECT 1`;database=true}}catch{}return response({database,ring:{accountLinked:false,webhookSigningKeyConfigured:!!Bun.env.RING_HMAC_KEY,authorizationConfigured:!!(Bun.env.RING_CLIENT_ID&&Bun.env.RING_CLIENT_SECRET)},sweeper:{hardwareConnected:false}});}
if(req.method==="GET"&&url.pathname==="/api/sweeper/observations"){if(!secret||req.headers.get("x-clarity-api-key")!==secret)return response({error:"Unauthorized"},401);if(!db)return response({error:"Database unavailable"},503);try{await db`CREATE TABLE IF NOT EXISTS clarity_observations(id uuid primary key,event_type text not null,body jsonb not null,created_at timestamptz default now())`;const rows=await db`SELECT id,event_type,body,created_at FROM clarity_observations ORDER BY created_at DESC LIMIT 50`;return response({observations:rows});}catch{return response({error:"Unable to retrieve observations"},503);}}
if(req.method==="GET"&&url.pathname==="/api/ring/events"){if(!secret||req.headers.get("x-clarity-api-key")!==secret)return response({error:"Unauthorized"},401);if(!db)return response({error:"Database unavailable"},503);try{await db`CREATE TABLE IF NOT EXISTS clarity_ring_events(id uuid primary key,payload jsonb not null,received_at timestamptz default now())`;const rows=await db`SELECT id,payload,received_at FROM clarity_ring_events ORDER BY received_at DESC LIMIT 50`;return response({events:rows});}catch{return response({error:"Unable to retrieve events"},503);}}
if(req.method==="GET"&&url.pathname==="/api/sweeper/status"){if(!secret||req.headers.get("x-clarity-api-key")!==secret)return response({error:"Unauthorized"},401);return response({hardwareConnected:false,ringConnected:false});}
if(req.method==="POST"&&url.pathname==="/api/sweeper/observations"){if(!secret||req.headers.get("x-clarity-api-key")!==secret)return response({error:"Unauthorized"},401);try{const e=await req.json();if(!e||typeof e.type!=="string")return response({error:"Missing type"},400);if(!db)return response({error:"Database unavailable"},503);await db`CREATE TABLE IF NOT EXISTS clarity_observations(id uuid primary key,event_type text not null,body jsonb not null,created_at timestamptz default now())`;const id=crypto.randomUUID();await db`INSERT INTO clarity_observations(id,event_type,body) VALUES(${id},${e.type},${JSON.stringify(e)}::jsonb)`;return response({accepted:true,persisted:true,id},201);}catch{return response({error:"Unable to save observation"},503);}}

if(req.method==="GET"&&url.pathname==="/ring/account")return accountStatus(req,db);
if(req.method==="GET"&&url.pathname==="/ring/link")return link(req,url,db);
if(req.method==="POST"&&url.pathname==="/ring/auth")return auth(req,db);
if(req.method==="GET"&&url.pathname==="/ring/ready")return response({credentials:!!(Bun.env.RING_CLIENT_ID&&Bun.env.RING_CLIENT_SECRET&&Bun.env.RING_HMAC_KEY),accountLinking:true,tokenStorage:!!(db&&Bun.env.RING_TOKEN_ENCRYPTION_KEY)});
if(req.method==="GET"&&url.pathname==="/ring/config")return Response.redirect("https://gentle-home-awareness.lovable.app",302);
if(req.method==="POST"&&url.pathname==="/ring/oauth/token"){
if(!db||!Bun.env.RING_CLIENT_ID||!Bun.env.RING_CLIENT_SECRET||!Bun.env.RING_TOKEN_ENCRYPTION_KEY)return response({error:"Ring token vault unavailable"},503);
const len=Number(req.headers.get("content-length")||0);if(len>8192)return response({error:"Request too large"},413);
let code="";try{const raw=await req.text();if(raw.length>8192)return response({error:"Request too large"},413);if((req.headers.get("content-type")||"").includes("json")){code=String(JSON.parse(raw).code||"")}else{code=new URLSearchParams(raw).get("code")||""}}catch{return response({error:"Invalid request"},400)}
if(!code||code.length>4096)return response({error:"Missing authorization code"},400);
try{
await db`CREATE TABLE IF NOT EXISTS clarity_ring_tokens(id uuid primary key, access_cipher text not null, refresh_cipher text not null, expires_at timestamptz not null, ring_account_id text, clarity_account_id text, claimed_at timestamptz, created_at timestamptz default now())`;
const body=new URLSearchParams({grant_type:"authorization_code",client_id:Bun.env.RING_CLIENT_ID,client_secret:Bun.env.RING_CLIENT_SECRET,code});
const exchange=await fetch("https://oauth.ring.com/oauth/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body,signal:AbortSignal.timeout(12000)});
if(!exchange.ok)return response({error:"Ring rejected authorization code",ringStatus:exchange.status},502);
const tokens=await exchange.json();if(!tokens.access_token||!tokens.refresh_token) return response({error:"Incomplete Ring token response"},502);
const keyBytes=Uint8Array.from(Bun.env.RING_TOKEN_ENCRYPTION_KEY.match(/.{2}/g)||[],x=>parseInt(x,16));if(keyBytes.length!==32)throw Error("Invalid encryption key");
const aes=await crypto.subtle.importKey("raw",keyBytes,"AES-GCM",false,["encrypt"]);
async function seal(value:string){const iv=crypto.getRandomValues(new Uint8Array(12));const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},aes,new TextEncoder().encode(value)));return Array.from(iv,x=>x.toString(16).padStart(2,"0")).join("")+":"+Array.from(ciphertext,x=>x.toString(16).padStart(2,"0")).join("")}
const profile=await fetch("https://api.amazonvision.com/v1/users/me",{headers:{"authorization":"Bearer "+tokens.access_token},signal:AbortSignal.timeout(12000)});
if(!profile.ok)return response({error:"Ring user profile lookup failed",ringStatus:profile.status},502);
const profileJson=await profile.json();
const ringAccountId=typeof profileJson?.data?.id==="string"?profileJson.data.id:null;
if(!ringAccountId)return response({error:"Ring account ID unavailable"},502);
const id=crypto.randomUUID();const access=await seal(tokens.access_token),refresh=await seal(tokens.refresh_token);const expiry=new Date(Date.now()+Math.max(60,Number(tokens.expires_in)||14400)*1000);
await db`INSERT INTO clarity_ring_tokens(id,access_cipher,refresh_cipher,expires_at,ring_account_id) VALUES(${id},${access},${refresh},${expiry},${ringAccountId})`;
return response({received:true,stored:true,accountLinked:false},202);
}catch{return response({error:"Ring authorization could not be stored securely"},503)}
}
if(req.method==="POST"&&url.pathname==="/ring/webhook"){
const key=Bun.env.RING_HMAC_KEY;if(!key)return response({error:"Ring signing key not configured"},503);
if(Number(req.headers.get("content-length")||0)>65536)return response({error:"Payload too large"},413);
const raw=await req.text();if(new TextEncoder().encode(raw).length>65536)return response({error:"Payload too large"},413);
const signature=req.headers.get("x-signature")||"";if(!/^sha256=[0-9a-f]{64}$/i.test(signature))return response({error:"Invalid signature"},401);
const encoder=new TextEncoder();const imported=await crypto.subtle.importKey("raw",encoder.encode(key),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
const bytes=new Uint8Array(await crypto.subtle.sign("HMAC",imported,encoder.encode(raw)));
const expected="sha256="+Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("");
let mismatch=0;for(let i=0;i<expected.length;i++)mismatch|=expected.charCodeAt(i)^signature.toLowerCase().charCodeAt(i);
if(mismatch)return response({error:"Invalid signature"},401);
try{const payload=JSON.parse(raw);if(!db)return response({error:"Database unavailable"},503);await db`CREATE TABLE IF NOT EXISTS clarity_ring_events(id uuid primary key,payload jsonb not null,received_at timestamptz default now())`;
const id=crypto.randomUUID();await db`INSERT INTO clarity_ring_events(id,payload) VALUES(${id},${JSON.stringify(payload)}::jsonb)`;return response({received:true,id},200);}catch{return response({error:"Unable to store event"},503);}
}
if(url.pathname.startsWith("/ring/"))return response({error:"Ring account linking not yet authorized"},503);
return response({error:"Not found"},404);
}});