function copyURL(url) {
  navigator.clipboard.writeText(url).then(() => {
    // small visual feedback
    alert("URL copied to clipboard!");
  }).catch(err => {
    alert("Copy failed: " + err);
  });
}
