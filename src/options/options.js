document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('reputationToggle');
  const PROXY_URL_MATCH = 'https://reputation.behindthelink.net/*';

  // Load current state
  chrome.storage.local.get(['reputationEnabled'], (result) => {
    toggle.checked = !!result.reputationEnabled;
  });

  // Save on change
  toggle.addEventListener('change', (e) => {
    if (e.target.checked) {
      // Prompt for permissions
      chrome.permissions.request({
        origins: [PROXY_URL_MATCH]
      }, (granted) => {
        if (granted) {
          chrome.storage.local.set({ reputationEnabled: true });
        } else {
          // Denied, revert toggle
          toggle.checked = false;
          chrome.storage.local.set({ reputationEnabled: false });
        }
      });
    } else {
      // Revoke optional permissions when disabled? Usually good practice, but not strictly required by user.
      // We'll just disable the feature flag.
      chrome.storage.local.set({ reputationEnabled: false });
    }
  });
});
