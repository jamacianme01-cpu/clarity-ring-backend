const enc=new TextEncoder();
export function validRingLink(nonce:string|null,time:string|null,now=Date.now()){
 if(!nonce||!time||!/^[A-Za-z0-9_-]{43}$/.test(nonce)||!/^[0-9]{13}$/.test(time))return false;
 const age=now-Number(time);return age>=0&&age<=600000;
}
export async function matchRingNonce(time:string,ringAccountId:string,key:string){
 const k=await crypto.subtle.importKey("raw",enc.encode(key),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const mac=new Uint8Array(await crypto.subtle.sign("HMAC",k,enc.encode(time+":"+ringAccountId)));
 return btoa(String.fromCharCode(...mac)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
export function constantTimeEqual(a:string,b:string){
 let mismatch=a.length^b.length;
 for(let i=0;i<Math.max(a.length,b.length);i++)mismatch|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);
 return mismatch===0;
}
export async function claimRingAccount(accessToken:string,accountIdentifier:string,nonce:string){
 const endpoint="https://api.amazonvision.com/v1/accounts/me/app-integrations";
 const headers={"authorization":"Bearer "+accessToken,"content-type":"application/json"};
 const claim=await fetch(endpoint,{method:"POST",headers,body:JSON.stringify({account_identifier:accountIdentifier,nonce}),signal:AbortSignal.timeout(12000)});
 if(!claim.ok)return {ok:false,stage:"claim",status:claim.status};
 const complete=await fetch(endpoint,{method:"PATCH",headers,body:JSON.stringify({status:"completed"}),signal:AbortSignal.timeout(12000)});
 return {ok:complete.ok,stage:"complete",status:complete.status};
}
