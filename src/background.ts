// Right-click selected text → "Scan with Decoy" → opens the side panel with that text.

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "decoy-scan", title: "Scan with Decoy", contexts: ["selection", "link"] });
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "decoy-scan" || !tab?.windowId) return;
  // Must open synchronously within the user gesture.
  chrome.sidePanel.open({ windowId: tab.windowId });
  await chrome.storage.session.set({ pending: { text: info.selectionText ?? "", link: info.linkUrl ?? "" } });
});
