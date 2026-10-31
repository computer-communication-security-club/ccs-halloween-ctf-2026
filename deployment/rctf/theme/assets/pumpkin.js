/* Dependency-free WebGL pumpkin. Loaded once; mounts with rCTF's SPA routes. */
(() => {
  const vertex = `attribute vec2 position; void main(){gl_Position=vec4(position,0.,1.);}`;
  const fragment = `precision highp float;
    uniform vec2 resolution;
    uniform vec2 turn;
    uniform float time;
    vec2 rotate2(vec2 p,float a){float c=cos(a),s=sin(a);return mat2(c,-s,s,c)*p;}
    vec3 local(vec3 p){p.y-=.08;p.yz=rotate2(p.yz,turn.y);p.xz=rotate2(p.xz,turn.x);return p;}
    float segment(vec2 p,vec2 a,vec2 b){vec2 v=b-a;return length(p-a-v*clamp(dot(p-a,v)/dot(v,v),0.,1.));}
    float cross2(vec2 a,vec2 b){return a.x*b.y-a.y*b.x;}
    float tri(vec2 p,vec2 a,vec2 b,vec2 c){float d=min(segment(p,a,b),min(segment(p,b,c),segment(p,c,a)));float x=cross2(b-a,p-a),y=cross2(c-b,p-b),z=cross2(a-c,p-c);return (min(x,min(y,z))>0.||max(x,max(y,z))<0.)?-d:d;}
    float box(vec2 p,vec2 b){vec2 d=abs(p)-b;return length(max(d,0.))+min(max(d.x,d.y),0.);}
    float pumpkin(vec3 p){
      float a=atan(p.z,p.x);
      float ribs=1.+.065*cos(a*10.);
      vec3 q=vec3(p.x/ribs,p.y/0.79,p.z/ribs);
      return (length(q)-.99)*.72;
    }
    float cut(vec3 p){
      float left=tri(p.xy,vec2(-.65,.10),vec2(-.21,.08),vec2(-.38,.44));
      float right=tri(p.xy,vec2(.21,.08),vec2(.65,.10),vec2(.38,.44));
      float nose=tri(p.xy,vec2(-.095,-.10),vec2(.095,-.10),vec2(0.,.055));
      float mouth=max(length(vec2(p.x,(p.y+.17)*1.12))-.56,-(p.y+.48));
      mouth=max(mouth,-(length(vec2(p.x,(p.y-.04)*1.0))-.49));
      mouth=max(mouth,-box(p.xy-vec2(-.24,-.25),vec2(.075,.10)));
      mouth=max(mouth,-box(p.xy-vec2(.18,-.42),vec2(.075,.095)));
      return max(min(min(left,right),min(nose,mouth)),.12-p.z);
    }
    vec2 scene(vec3 world){
      vec3 p=local(world);
      float skin=max(abs(pumpkin(p))-.045,-cut(p));
      vec2 result=vec2(skin,1.);
      vec3 a=vec3(0.,.74,0.),b=vec3(.13,1.16,-.035),v=b-a;
      float h=clamp(dot(p-a,v)/dot(v,v),0.,1.);
      float stem=length(p-a-v*h)-mix(.12,.064,h);
      if(stem<result.x)result=vec2(stem,2.);
      float core=length(p/vec3(.68,.54,.68))-1.;
      if(core<result.x)result=vec2(core,3.);
      return result;
    }
    vec3 normal(vec3 p){vec2 e=vec2(.001,0.);return normalize(vec3(scene(p+e.xyy).x-scene(p-e.xyy).x,scene(p+e.yxy).x-scene(p-e.yxy).x,scene(p+e.yyx).x-scene(p-e.yyx).x));}
    float shadow(vec3 p,vec3 light){float res=1.,t=.025;for(int i=0;i<28;i++){float h=scene(p+light*t).x;res=min(res,12.*h/t);t+=clamp(h,.025,.13);if(t>3.)break;}return clamp(res,.16,1.);}
    void main(){
      vec2 uv=(gl_FragCoord.xy*2.-resolution)/resolution.y;
      vec3 ro=vec3(0.,.35,4.5),target=vec3(0.,.1,0.);
      vec3 forward=normalize(target-ro),right=normalize(cross(forward,vec3(0.,1.,0.))),up=cross(right,forward);
      vec3 rd=normalize(forward*2.55+uv.x*right+uv.y*up);
      float t=0.;vec2 hit=vec2(0.);bool found=false;
      for(int i=0;i<128;i++){hit=scene(ro+rd*t);if(hit.x<.0015){found=true;break;}t+=max(hit.x*.72,.001);if(t>7.)break;}
      if(!found){
        float plane=(-.87-ro.y)/rd.y;vec3 floorPoint=ro+rd*plane;
        float shade=plane>0.?exp(-dot(floorPoint.xz,floorPoint.xz)*2.4)*.28:0.;
        gl_FragColor=vec4(.035,.018,.028,shade);return;
      }
      vec3 p=ro+rd*t,n=normal(p),q=local(p);
      vec3 key=normalize(vec3(-3.,4.,5.)),rim=normalize(vec3(3.,2.,-3.));
      float diffuse=max(dot(n,key),0.)*shadow(p+n*.008,key);
      float back=max(dot(n,rim),0.);
      float ao=clamp(scene(p+n*.08).x/.08,.35,1.);
      float grain=sin(q.x*150.)*sin(q.y*130.)*sin(q.z*170.);
      vec3 color;
      if(hit.y>2.5){color=vec3(1.,.52,.09)*(1.+.055*sin(time*2.7));}
      else {
        vec3 base=hit.y>1.5?vec3(.19,.24,.075):mix(vec3(.58,.105,.013),vec3(.94,.27,.026),smoothstep(-.6,.7,q.y));
        base*=1.+grain*.024;
        float gloss=pow(max(dot(reflect(-key,n),-rd),0.),28.);
        float fresnel=pow(1.-max(dot(n,-rd),0.),3.);
        color=base*(.18*ao+diffuse*.95)+vec3(1.,.47,.16)*back*.52+vec3(1.,.77,.48)*gloss*.31+vec3(.32,.23,.48)*fresnel*.22;
        // Warm light catches the actual carved edges from inside the shell.
        if(hit.y<1.5){float edge=1.-smoothstep(.0,.095,abs(cut(q)));color+=vec3(1.,.25,.015)*edge*.40;}
      }
      gl_FragColor=vec4(pow(color,vec3(.78)),1.);
    }`;

  function mount(host) {
    if (host.dataset.mounted) return;
    host.dataset.mounted = 'true';
    const canvas = document.createElement('canvas');
    canvas.className = 'hw-pumpkin-canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Three-dimensional glowing jack-o’-lantern. Move the pointer or use arrow keys to turn it.');
    canvas.tabIndex = 0;
    const gl = canvas.getContext('webgl', {alpha:true, antialias:true, premultipliedAlpha:false});
    if (!gl) return; // The original illustration stays visible as a fallback.
    let program, buffer, frame = 0, disposed = false;
    const shaders = [];
    try {
      function compile(type, source) {
        const shader = gl.createShader(type);
        shaders.push(shader); gl.shaderSource(shader, source); gl.compileShader(shader);
        if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw Error(gl.getShaderInfoLog(shader));
        return shader;
      }
      program = gl.createProgram();
      gl.attachShader(program, compile(gl.VERTEX_SHADER, vertex));
      gl.attachShader(program, compile(gl.FRAGMENT_SHADER, fragment));
      gl.linkProgram(program);
      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw Error(gl.getProgramInfoLog(program));
      gl.useProgram(program);
      buffer = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),gl.STATIC_DRAW);
      const position=gl.getAttribLocation(program,'position');
      gl.enableVertexAttribArray(position); gl.vertexAttribPointer(position,2,gl.FLOAT,false,0,0);
    } catch (error) {
      shaders.forEach(shader=>gl.deleteShader(shader));
      if(program)gl.deleteProgram(program);
      if(buffer)gl.deleteBuffer(buffer);
      console.warn('Pumpkin illustration fallback:', error.message);
      return;
    }
    const resolution = gl.getUniformLocation(program,'resolution');
    const turn = gl.getUniformLocation(program,'turn');
    const time = gl.getUniformLocation(program,'time');
    let x=.12,y=-.06, goalX=.12,goalY=-.06, visible=true, lastDraw=-Infinity;
    const reduced = matchMedia('(prefers-reduced-motion: reduce)');
    function draw(now=0) {
      if(disposed)return;
      frame=0;
      // Limit the candle animation to 30 fps, even on high-refresh displays.
      if (!reduced.matches && now-lastDraw<1000/30) { schedule(); return; }
      lastDraw=now;
      const rect=canvas.getBoundingClientRect();
      const scale=Math.min(devicePixelRatio||1,1.5);
      const width=Math.max(1,Math.round(rect.width*scale)),height=Math.max(1,Math.round(rect.height*scale));
      if(canvas.width!==width||canvas.height!==height){canvas.width=width;canvas.height=height;gl.viewport(0,0,width,height);}
      x+=(goalX-x)*.12;y+=(goalY-y)*.12;
      gl.uniform2f(resolution,width,height);
      gl.uniform2f(turn,x,y);gl.uniform1f(time,reduced.matches?0:now/1000);
      gl.drawArrays(gl.TRIANGLES,0,6);
      if(visible&&!document.hidden&&!reduced.matches)frame=requestAnimationFrame(draw);
    }
    function schedule(){if(!disposed&&!frame&&visible&&!document.hidden)frame=requestAnimationFrame(draw);}
    host.addEventListener('pointermove',e=>{
      if(e.pointerType==='touch')return;
      const r=host.getBoundingClientRect();
      goalX=((e.clientX-r.left)/r.width-.5)*1.05;
      goalY=((e.clientY-r.top)/r.height-.5)*.35;
      if(reduced.matches){x=goalX;y=goalY;}schedule();
    });
    host.addEventListener('pointerleave',()=>{goalX=.12;goalY=-.06;if(reduced.matches){x=goalX;y=goalY;}schedule();});
    canvas.addEventListener('keydown',e=>{
      if(!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home'].includes(e.key))return;
      e.preventDefault();
      if(e.key==='Home'){goalX=.12;goalY=-.06;}
      if(e.key==='ArrowLeft')goalX-=.15;if(e.key==='ArrowRight')goalX+=.15;
      if(e.key==='ArrowUp')goalY-=.1;if(e.key==='ArrowDown')goalY+=.1;
      goalX=Math.max(-.8,Math.min(.8,goalX));goalY=Math.max(-.3,Math.min(.3,goalY));
      if(reduced.matches){x=goalX;y=goalY;}schedule();
    });
    const resize=new ResizeObserver(schedule);resize.observe(host);
    const intersection=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;if(!visible)cancelAnimationFrame(frame);frame=0;schedule();});intersection.observe(host);
    const visibility=()=>{cancelAnimationFrame(frame);frame=0;schedule();};
    document.addEventListener('visibilitychange',visibility);
    reduced.addEventListener('change',visibility);
    const cleanup=()=>{
      if(disposed)return;disposed=true;cancelAnimationFrame(frame);
      resize.disconnect();intersection.disconnect();
      document.removeEventListener('visibilitychange',visibility);reduced.removeEventListener('change',visibility);
      shaders.forEach(shader=>gl.deleteShader(shader));gl.deleteBuffer(buffer);gl.deleteProgram(program);
      canvas.remove();host.classList.remove('hw-pumpkin-ready');
    };
    canvas.addEventListener('webglcontextlost',e=>{e.preventDefault();cleanup();});
    host.append(canvas);host.classList.add('hw-pumpkin-ready');
    active.set(host,cleanup);schedule();
  }
  const active=new Map();
  function reconcile(){
    for(const [host,cleanup] of active)if(!host.isConnected){cleanup();active.delete(host);}
    document.querySelectorAll('.hw-pumpkin').forEach(mount);
  }
  new MutationObserver(reconcile).observe(document.body,{childList:true,subtree:true});
  reconcile();
})();
