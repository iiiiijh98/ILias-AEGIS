// 태블릿 사진: 업로드 전에 긴 변 1600px JPEG로 줄여 전송량(서버 한도 4MB)을 맞춥니다.
(function () {
  function shrink(input) {
    var f = input.files && input.files[0]; if (!f || !/^image\//.test(f.type) || typeof DataTransfer === 'undefined') return;
    var img = new Image(); var url = URL.createObjectURL(f);
    img.onload = function () {
      var max = 1600, w = img.naturalWidth, h = img.naturalHeight, s = Math.min(1, max / Math.max(w, h));
      var c = document.createElement('canvas'); c.width = Math.round(w * s); c.height = Math.round(h * s);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height); URL.revokeObjectURL(url);
      c.toBlob(function (b) { if (!b) return; var dt = new DataTransfer(); dt.items.add(new File([b], (f.name || 'photo').replace(/\.\w+$/, '') + '.jpg', { type: 'image/jpeg' })); input.files = dt.files; var p = input.parentNode.querySelector('.pv'); if (p) p.textContent = '사진 준비됨 (' + Math.round(b.size / 1024) + ' KB)'; }, 'image/jpeg', 0.85);
    };
    img.onerror = function () { URL.revokeObjectURL(url); };
    img.src = url;
  }
  document.addEventListener('change', function (e) { if (e.target.matches('input[type=file][data-shrink]')) shrink(e.target); });
  document.addEventListener('submit', function (e) { var m = e.target.getAttribute('data-confirm'); if (m && !window.confirm(m)) e.preventDefault(); });
  document.addEventListener('change', function (e) { if (e.target.id === 'allbox') { document.querySelectorAll('input[name=ids]').forEach(function (c) { c.checked = e.target.checked; }); } });
  var clk = document.getElementById('clock'); if (clk) setInterval(function () { clk.textContent = new Date().toLocaleTimeString('ko-KR', { timeZone: 'Asia/Seoul', hour12: false }) + ' KST'; }, 1000);
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('/sw.js').catch(function () {});
})();
