document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('reputation-toggle');
  if (!toggle) return;

  // Read current setting from chrome.storage.local (default: enabled on fresh installations)
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['reputationEnabled'], (res) => {
      toggle.checked = res.reputationEnabled !== false;
    });

    toggle.addEventListener('change', () => {
      chrome.storage.local.set({ reputationEnabled: toggle.checked });
    });
  } else {
    toggle.checked = true;
  }
});
